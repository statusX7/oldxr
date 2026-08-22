package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	ss "github.com/xtls/xray-core/proxy/shadowsocks"
	"golang.org/x/crypto/hkdf"
)

const (
	ssSaltSize       = 16
	ssTagSize        = 16
	ssLengthWireSize = 2 + ssTagSize
	ssMaxPayload     = 8192 - ssLengthWireSize - ssTagSize
)

var errIncompleteAddress = errors.New("incomplete Shadowsocks target address")

func newAES128GCMSession(account *ss.MemoryAccount, salt []byte) (cipher.AEAD, error) {
	if len(salt) != ssSaltSize {
		return nil, fmt.Errorf("invalid AES-128-GCM salt length %d", len(salt))
	}
	cipherConfig, ok := account.Cipher.(*ss.AEADCipher)
	if !ok || cipherConfig.KeySize() != 16 || cipherConfig.IVSize() != ssSaltSize {
		return nil, errors.New("account is not AES-128-GCM")
	}
	subkey := make([]byte, 16)
	if _, err := io.ReadFull(hkdf.New(sha1.New, account.Key, salt, []byte("ss-subkey")), subkey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// incrementNonce follows Shadowsocks AEAD's little-endian nonce sequence.
func incrementNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

func parseSSTarget(payload []byte) (target string, consumed int, err error) {
	if len(payload) < 1 {
		return "", 0, errIncompleteAddress
	}
	addressType := payload[0] & 0x0f
	var host string
	switch addressType {
	case 1:
		if len(payload) < 1+net.IPv4len+2 {
			return "", 0, errIncompleteAddress
		}
		host = net.IP(payload[1 : 1+net.IPv4len]).String()
		consumed = 1 + net.IPv4len
	case 4:
		if len(payload) < 1+net.IPv6len+2 {
			return "", 0, errIncompleteAddress
		}
		host = net.IP(payload[1 : 1+net.IPv6len]).String()
		consumed = 1 + net.IPv6len
	case 3:
		if len(payload) < 2 {
			return "", 0, errIncompleteAddress
		}
		domainLength := int(payload[1])
		if domainLength == 0 || len(payload) < 2+domainLength+2 {
			return "", 0, errIncompleteAddress
		}
		host = string(payload[2 : 2+domainLength])
		consumed = 2 + domainLength
	default:
		return "", 0, fmt.Errorf("unsupported Shadowsocks address type %d", addressType)
	}
	port := binary.BigEndian.Uint16(payload[consumed : consumed+2])
	consumed += 2
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), consumed, nil
}

func sealSSRecords(aead cipher.AEAD, nonce []byte, dst, plaintext []byte) []byte {
	for len(plaintext) > 0 {
		chunkSize := len(plaintext)
		if chunkSize > ssMaxPayload {
			chunkSize = ssMaxPayload
		}
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(chunkSize))
		dst = aead.Seal(dst, nonce, length[:], nil)
		incrementNonce(nonce)
		dst = aead.Seal(dst, nonce, plaintext[:chunkSize], nil)
		incrementNonce(nonce)
		plaintext = plaintext[chunkSize:]
	}
	return dst
}
