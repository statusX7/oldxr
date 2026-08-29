package encoding

import (
	"bytes"
	"crypto/rand"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessaead "github.com/xtls/xray-core/proxy/vmess/aead"
)

// OwnerBodyCodec keeps the trusted VMess body cryptographic state while an
// established TCP relay moves from blocking net.Conn copies to an owner event
// loop. It intentionally supports only the AES-128-GCM stream common case;
// callers must retain the generic path for every other protocol shape.
type OwnerBodyCodec struct {
	session *ServerSession
	request *protocol.RequestHeader
	reader  *buf.BufferedReader

	requestAuth    crypto.Authenticator
	requestSize    crypto.ChunkSizeDecoder
	requestPadding crypto.PaddingLengthGenerator

	requestSizePrefix []byte
	requestWire       []byte
	requestWireSize   int
	requestWirePad    int

	responseAuth    crypto.Authenticator
	responseSize    crypto.ChunkSizeEncoder
	responsePadding crypto.PaddingLengthGenerator
	responseHeader  []byte
	responseStarted bool
	responseEnd     bool
	responsePrefix  [18]byte
	paddingEntropy  []byte
	paddingOffset   int
}

const ownerPaddingEntropySize = 4 * 1024

// appendResponsePadding amortizes getrandom calls without changing the VMess
// padding stream: every emitted byte still comes directly from crypto/rand.
// OwnerBodyCodec is connection-local and its owner callbacks are serialized.
func (c *OwnerBodyCodec) appendResponsePadding(dst []byte, size int) ([]byte, error) {
	start := len(dst)
	dst = append(dst, make([]byte, size)...)
	padding := dst[start:]
	for len(padding) > 0 {
		if c.paddingOffset == len(c.paddingEntropy) {
			if c.paddingEntropy == nil {
				c.paddingEntropy = make([]byte, ownerPaddingEntropySize)
			}
			if _, err := rand.Read(c.paddingEntropy); err != nil {
				return nil, err
			}
			c.paddingOffset = 0
		}
		n := copy(padding, c.paddingEntropy[c.paddingOffset:])
		c.paddingOffset += n
		padding = padding[n:]
	}
	return dst, nil
}

// NewOwnerBodyCodec creates a request-side codec without changing any wire or
// replay semantics. The response state is initialized lazily after routing has
// produced the exact response header.
func (s *ServerSession) NewOwnerBodyCodec(request *protocol.RequestHeader, reader *buf.BufferedReader) (*OwnerBodyCodec, error) {
	if request == nil || reader == nil || !s.isAEADRequest || request.Command != protocol.RequestCommandTCP || request.Security != protocol.SecurityType_AES128_GCM || !request.Option.Has(protocol.RequestOptionChunkStream) {
		return nil, newError("unsupported VMess owner body")
	}

	sizeParser := crypto.ChunkSizeDecoder(crypto.PlainChunkSizeParser{})
	if request.Option.Has(protocol.RequestOptionChunkMasking) {
		sizeParser = NewShakeSizeParser(s.requestBodyIV[:])
	}
	var padding crypto.PaddingLengthGenerator
	if request.Option.Has(protocol.RequestOptionGlobalPadding) {
		var ok bool
		padding, ok = sizeParser.(crypto.PaddingLengthGenerator)
		if !ok {
			return nil, newError("invalid option: RequestOptionGlobalPadding")
		}
	}

	aead := crypto.NewAesGcm(s.requestBodyKey[:])
	auth := &crypto.AEADAuthenticator{
		AEAD:                    aead,
		NonceGenerator:          GenerateChunkNonce(s.requestBodyIV[:], uint32(aead.NonceSize())),
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
	if request.Option.Has(protocol.RequestOptionAuthenticatedLength) {
		key := vmessaead.KDF16(s.requestBodyKey[:], "auth_len")
		lengthAEAD := crypto.NewAesGcm(key)
		lengthAuth := &crypto.AEADAuthenticator{
			AEAD:                    lengthAEAD,
			NonceGenerator:          GenerateChunkNonce(s.requestBodyIV[:], uint32(lengthAEAD.NonceSize())),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		}
		sizeParser = NewAEADSizeParser(lengthAuth)
	}

	account, ok := request.User.Account.(*vmess.MemoryAccount)
	if !ok {
		return nil, newError("invalid VMess owner account")
	}
	return &OwnerBodyCodec{
		session:        s,
		request:        request,
		reader:         reader,
		requestAuth:    auth,
		requestSize:    sizeParser,
		requestPadding: padding,
		responseEnd:    !account.NoTerminationSignal,
	}, nil
}

func (c *OwnerBodyCodec) readRequestRecord() ([]byte, error) {
	if c.requestWireSize == 0 {
		sizeBytes, err := c.fillRequestWire(&c.requestSizePrefix, int(c.requestSize.SizeBytes()))
		if err != nil {
			return nil, err
		}
		wireSize, padding, done, err := c.DecodeRequestSize(sizeBytes)
		c.requestSizePrefix = c.requestSizePrefix[:0]
		if err != nil {
			return nil, err
		}
		if done {
			return nil, io.EOF
		}
		c.requestWireSize = wireSize
		c.requestWirePad = padding
	}

	wire, err := c.fillRequestWire(&c.requestWire, c.requestWireSize)
	if err != nil {
		return nil, err
	}
	plaintext, err := c.OpenRequest(wire, c.requestWirePad)
	c.requestWire = nil
	c.requestWireSize = 0
	c.requestWirePad = 0
	return plaintext, err
}

// fillRequestWire retains bytes already consumed from the encrypted stream if
// the short direct-dispatch sniff deadline expires between TCP fragments. The
// next generic or owner-candidate read resumes the same VMess record boundary.
func (c *OwnerBodyCodec) fillRequestWire(dst *[]byte, size int) ([]byte, error) {
	if size <= 0 || len(*dst) > size {
		return nil, io.ErrShortBuffer
	}
	if cap(*dst) < size {
		grown := make([]byte, len(*dst), size)
		copy(grown, *dst)
		*dst = grown
	}
	start := len(*dst)
	*dst = (*dst)[:size]
	n, err := io.ReadFull(c.reader, (*dst)[start:])
	*dst = (*dst)[:start+n]
	if err != nil {
		return nil, err
	}
	return *dst, nil
}

// ReadMultiBuffer implements buf.Reader for routing sniffing and for the
// generic fallback after a failed owner transfer.
func (c *OwnerBodyCodec) ReadMultiBuffer() (buf.MultiBuffer, error) {
	plaintext, err := c.readRequestRecord()
	if err != nil {
		return nil, err
	}
	return buf.MultiBuffer{buf.FromBytes(plaintext)}, nil
}

// RequestSizeBytes returns the exact encrypted record prefix length.
func (c *OwnerBodyCodec) RequestSizeBytes() int {
	return int(c.requestSize.SizeBytes())
}

// RequestTransferReady reports whether request parsing is exactly between
// encrypted records. A partially consumed record remains on the generic codec
// so its cryptographic size/nonce state cannot be split across two owners.
func (c *OwnerBodyCodec) RequestTransferReady() bool {
	return len(c.requestSizePrefix) == 0 && c.requestWireSize == 0 && len(c.requestWire) == 0
}

// DecodeRequestSize advances the masking/padding state exactly once. wireSize
// includes ciphertext authentication overhead and clear-text padding.
func (c *OwnerBodyCodec) DecodeRequestSize(sizeBytes []byte) (wireSize int, padding int, done bool, err error) {
	if len(sizeBytes) != int(c.requestSize.SizeBytes()) {
		return 0, 0, false, io.ErrUnexpectedEOF
	}
	if c.requestPadding != nil {
		padding = int(c.requestPadding.NextPaddingLen())
	}
	size, err := c.requestSize.Decode(sizeBytes)
	if err != nil {
		return 0, 0, false, err
	}
	if int(size) == c.requestAuth.Overhead()+padding {
		return int(size), padding, true, nil
	}
	if int(size) <= c.requestAuth.Overhead()+padding || int(size) > buf.Size {
		return 0, 0, false, io.ErrUnexpectedEOF
	}
	return int(size), padding, false, nil
}

// OpenRequest authenticates one complete encrypted VMess record.
func (c *OwnerBodyCodec) OpenRequest(wire []byte, padding int) ([]byte, error) {
	if padding < 0 || len(wire) <= padding+c.requestAuth.Overhead() {
		return nil, io.ErrUnexpectedEOF
	}
	return c.requestAuth.Open(wire[:0], wire[:len(wire)-padding])
}

// TakeEncryptedBuffered transfers bytes already read from the kernel by the
// header/sniffing reader but not yet consumed by the body codec.
func (c *OwnerBodyCodec) TakeEncryptedBuffered() []byte {
	if c.reader == nil || c.reader.Buffer.IsEmpty() {
		return nil
	}
	buffered := make([]byte, 0, c.reader.Buffer.Len())
	for _, part := range c.reader.Buffer {
		buffered = append(buffered, part.Bytes()...)
	}
	c.reader.Buffer = buf.ReleaseMulti(c.reader.Buffer)
	return buffered
}

// PrepareResponse preserves the existing VMess response-header implementation
// and initializes only the incremental body writer state.
func (c *OwnerBodyCodec) PrepareResponse(response *protocol.ResponseHeader) error {
	if c.responseAuth != nil {
		return nil
	}
	var header bytes.Buffer
	c.session.EncodeResponseHeader(response, &header)
	c.responseHeader = append(c.responseHeader[:0], header.Bytes()...)

	sizeParser := crypto.ChunkSizeEncoder(crypto.PlainChunkSizeParser{})
	if c.request.Option.Has(protocol.RequestOptionChunkMasking) {
		sizeParser = NewShakeSizeParser(c.session.responseBodyIV[:])
	}
	var padding crypto.PaddingLengthGenerator
	if c.request.Option.Has(protocol.RequestOptionGlobalPadding) {
		var ok bool
		padding, ok = sizeParser.(crypto.PaddingLengthGenerator)
		if !ok {
			return newError("invalid option: RequestOptionGlobalPadding")
		}
	}

	aead := crypto.NewAesGcm(c.session.responseBodyKey[:])
	auth := &crypto.AEADAuthenticator{
		AEAD:                    aead,
		NonceGenerator:          GenerateChunkNonce(c.session.responseBodyIV[:], uint32(aead.NonceSize())),
		AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
	}
	if c.request.Option.Has(protocol.RequestOptionAuthenticatedLength) {
		key := vmessaead.KDF16(c.session.requestBodyKey[:], "auth_len")
		lengthAEAD := crypto.NewAesGcm(key)
		lengthAuth := &crypto.AEADAuthenticator{
			AEAD:                    lengthAEAD,
			NonceGenerator:          GenerateChunkNonce(c.session.requestBodyIV[:], uint32(lengthAEAD.NonceSize())),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		}
		sizeParser = NewAEADSizeParser(lengthAuth)
	}
	c.responseAuth = auth
	c.responseSize = sizeParser
	c.responsePadding = padding
	return nil
}

func (c *OwnerBodyCodec) responsePayloadLimit() int {
	maxPadding := 0
	if c.responsePadding != nil {
		maxPadding = int(c.responsePadding.MaxPaddingLen())
	}
	return buf.Size - c.responseAuth.Overhead() - int(c.responseSize.SizeBytes()) - maxPadding
}

func (c *OwnerBodyCodec) startResponse(dst []byte) []byte {
	if !c.responseStarted {
		dst = append(dst, c.responseHeader...)
		c.responseStarted = true
	}
	return dst
}

// ResponsePayloadLimit returns the maximum plaintext carried by one VMess
// response record for this connection's negotiated options.
func (c *OwnerBodyCodec) ResponsePayloadLimit() int {
	if c.responseAuth == nil || c.responseSize == nil {
		return 0
	}
	return c.responsePayloadLimit()
}

// SealResponseRecord emits exactly one encrypted response record. Keeping the
// record boundary visible lets an event-loop owner retain bounded partial
// output and credit traffic only after a complete authenticated record has
// reached the socket.
func (c *OwnerBodyCodec) SealResponseRecord(dst, plaintext []byte) ([]byte, error) {
	if c.responseAuth == nil || c.responseSize == nil {
		return nil, newError("VMess owner response is not prepared")
	}
	maxPayload := c.responsePayloadLimit()
	if len(plaintext) == 0 || maxPayload <= 0 || len(plaintext) > maxPayload {
		return nil, io.ErrShortBuffer
	}
	dst = c.startResponse(dst)
	padding := 0
	if c.responsePadding != nil {
		padding = int(c.responsePadding.NextPaddingLen())
	}
	wireSize := len(plaintext) + c.responseAuth.Overhead() + padding
	prefix := c.responsePrefix[:c.responseSize.SizeBytes()]
	c.responseSize.Encode(uint16(wireSize), prefix)
	dst = append(dst, prefix...)
	var err error
	dst, err = c.responseAuth.Seal(dst, plaintext)
	if err != nil {
		return nil, err
	}
	if padding > 0 {
		dst, err = c.appendResponsePadding(dst, padding)
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

// SealResponse appends the response header once and then emits one or more
// protocol-identical encrypted records without a blocking writer goroutine.
func (c *OwnerBodyCodec) SealResponse(dst, plaintext []byte) ([]byte, error) {
	if c.responseAuth == nil || c.responseSize == nil {
		return nil, newError("VMess owner response is not prepared")
	}
	dst = c.startResponse(dst)
	maxPayload := c.responsePayloadLimit()
	if maxPayload <= 0 {
		return nil, io.ErrShortBuffer
	}
	for len(plaintext) > 0 {
		size := len(plaintext)
		if size > maxPayload {
			size = maxPayload
		}
		var err error
		dst, err = c.SealResponseRecord(dst, plaintext[:size])
		if err != nil {
			return nil, err
		}
		plaintext = plaintext[size:]
	}
	return dst, nil
}

// SealResponseEnd emits the standard empty authenticated termination record.
func (c *OwnerBodyCodec) SealResponseEnd(dst []byte) ([]byte, error) {
	if c.responseAuth == nil || c.responseSize == nil {
		return nil, newError("VMess owner response is not prepared")
	}
	dst = c.startResponse(dst)
	if !c.responseEnd {
		return dst, nil
	}
	padding := 0
	if c.responsePadding != nil {
		padding = int(c.responsePadding.NextPaddingLen())
	}
	wireSize := c.responseAuth.Overhead() + padding
	var prefixBuffer [18]byte
	prefix := prefixBuffer[:c.responseSize.SizeBytes()]
	c.responseSize.Encode(uint16(wireSize), prefix)
	dst = append(dst, prefix...)
	var err error
	dst, err = c.responseAuth.Seal(dst, nil)
	if err != nil {
		return nil, err
	}
	if padding > 0 {
		dst, err = c.appendResponsePadding(dst, padding)
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}
