package encoding_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vmess"
	. "github.com/xtls/xray-core/proxy/vmess/encoding"
)

var errOwnerBodyTestTimeout = errors.New("owner body test timeout")

type ownerBodyBoundaryReader struct {
	data                   []byte
	headerBytes            int
	bodyBytesBeforeTimeout int
	offset                 int
	timeoutSent            bool
}

func (r *ownerBodyBoundaryReader) Read(p []byte) (int, error) {
	if r.offset == len(r.data) {
		return 0, io.EOF
	}
	limit := len(r.data)
	if r.offset < r.headerBytes {
		limit = r.headerBytes
	} else if !r.timeoutSent {
		limit = r.headerBytes + r.bodyBytesBeforeTimeout
		if r.offset == limit {
			r.timeoutSent = true
			return 0, errOwnerBodyTestTimeout
		}
	}
	if limit > len(r.data) {
		limit = len(r.data)
	}
	n := len(p)
	if n > limit-r.offset {
		n = limit - r.offset
	}
	copy(p, r.data[r.offset:r.offset+n])
	r.offset += n
	return n, nil
}

type ownerBodyCountingReader struct {
	reader io.Reader
	bytes  int
}

func (r *ownerBodyCountingReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	n, err := r.reader.Read(p)
	r.bytes += n
	return n, err
}

type ownerBodyChunkReader struct {
	data    []byte
	pattern []int
	offset  int
	next    int
}

func (r *ownerBodyChunkReader) Read(p []byte) (int, error) {
	if r.offset == len(r.data) {
		return 0, io.EOF
	}
	limit := len(p)
	if len(r.pattern) > 0 {
		limit = r.pattern[r.next%len(r.pattern)]
		r.next++
		if limit < 1 {
			limit = 1
		}
		if limit > len(p) {
			limit = len(p)
		}
	}
	if remaining := len(r.data) - r.offset; limit > remaining {
		limit = remaining
	}
	copy(p, r.data[r.offset:r.offset+limit])
	r.offset += limit
	return limit, nil
}

func readOwnerBodyStream(t *testing.T, reader buf.Reader) ([]byte, error) {
	t.Helper()
	var plaintext []byte
	for reads := 0; reads < 1024; reads++ {
		mb, err := reader.ReadMultiBuffer()
		for _, part := range mb {
			plaintext = append(plaintext, part.Bytes()...)
		}
		buf.ReleaseMulti(mb)
		if err != nil {
			return plaintext, err
		}
	}
	t.Fatal("VMess body reader did not terminate after 1024 reads")
	return nil, nil
}

func TestOwnerBodyCodecAES128GCM(t *testing.T) {
	for _, authenticatedLength := range []bool{false, true} {
		t.Run(map[bool]string{false: "masked", true: "authenticated-length"}[authenticatedLength], func(t *testing.T) {
			id := uuid.New()
			account, err := (&vmess.Account{Id: id.String()}).AsAccount()
			if err != nil {
				t.Fatal(err)
			}
			user := &protocol.MemoryUser{Level: 0, Email: "owner@example.com", Account: account}
			request := &protocol.RequestHeader{
				Version:  1,
				User:     user,
				Command:  protocol.RequestCommandTCP,
				Address:  net.DomainAddress("example.com"),
				Port:     443,
				Security: protocol.SecurityType_AES128_GCM,
				Option:   protocol.RequestOptionChunkStream | protocol.RequestOptionChunkMasking | protocol.RequestOptionGlobalPadding,
			}
			if authenticatedLength {
				request.Option.Set(protocol.RequestOptionAuthenticatedLength)
			}

			requestPayload := bytes.Repeat([]byte("request-owner-codec-"), 200)
			requestWire := buf.New()
			defer requestWire.Release()
			client := NewClientSession(context.Background(), true, protocol.DefaultIDHash, 0)
			if err := client.EncodeRequestHeader(request, requestWire); err != nil {
				t.Fatal(err)
			}
			requestWriter, err := client.EncodeRequestBody(request, requestWire)
			if err != nil {
				t.Fatal(err)
			}
			if err := requestWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(requestPayload)}); err != nil {
				t.Fatal(err)
			}

			validator := vmess.NewTimedUserValidator(protocol.DefaultIDHash)
			defer common.Close(validator)
			if err := validator.Add(user); err != nil {
				t.Fatal(err)
			}
			history := NewSessionHistory()
			defer common.Close(history)
			server := NewServerSession(validator, history)
			server.SetAEADForced(true)
			wireReader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(requestWire.Bytes()))}
			decodedRequest, err := server.DecodeRequestHeader(wireReader, false)
			if err != nil {
				t.Fatal(err)
			}
			codec, err := server.NewOwnerBodyCodec(decodedRequest, wireReader)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := codec.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(decoded)
			if got := decoded.String(); got != string(requestPayload) {
				t.Fatalf("request payload mismatch: got %d bytes, want %d", len(got), len(requestPayload))
			}

			if err := codec.PrepareResponse(&protocol.ResponseHeader{}); err != nil {
				t.Fatal(err)
			}
			responsePayload := bytes.Repeat([]byte("response-owner-codec-"), 200)
			responseWire, err := codec.SealResponse(nil, responsePayload)
			if err != nil {
				t.Fatal(err)
			}
			responseReader := bytes.NewReader(responseWire)
			if _, err := client.DecodeResponseHeader(responseReader); err != nil {
				t.Fatal(err)
			}
			bodyReader, err := client.DecodeResponseBody(request, responseReader)
			if err != nil {
				t.Fatal(err)
			}
			response, err := bodyReader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(response)
			if got := response.String(); got != string(responsePayload) {
				t.Fatalf("response payload mismatch: got %d bytes, want %d", len(got), len(responsePayload))
			}
		})
	}
}

func TestOwnerBodyCodecRetainsFragmentedRequestAcrossTimeout(t *testing.T) {
	for _, authenticatedLength := range []bool{false, true} {
		t.Run(map[bool]string{false: "masked", true: "authenticated-length"}[authenticatedLength], func(t *testing.T) {
			id := uuid.New()
			account, err := (&vmess.Account{Id: id.String()}).AsAccount()
			if err != nil {
				t.Fatal(err)
			}
			user := &protocol.MemoryUser{Level: 0, Email: "owner-timeout@example.com", Account: account}
			request := &protocol.RequestHeader{
				Version:  1,
				User:     user,
				Command:  protocol.RequestCommandTCP,
				Address:  net.DomainAddress("example.com"),
				Port:     443,
				Security: protocol.SecurityType_AES128_GCM,
				Option:   protocol.RequestOptionChunkStream | protocol.RequestOptionChunkMasking | protocol.RequestOptionGlobalPadding,
			}
			if authenticatedLength {
				request.Option.Set(protocol.RequestOptionAuthenticatedLength)
			}

			payload := bytes.Repeat([]byte("fragmented-owner-request-"), 128)
			wire := buf.New()
			defer wire.Release()
			client := NewClientSession(context.Background(), true, protocol.DefaultIDHash, 0)
			if err := client.EncodeRequestHeader(request, wire); err != nil {
				t.Fatal(err)
			}
			writer, err := client.EncodeRequestBody(request, wire)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
				t.Fatal(err)
			}
			wireBytes := append([]byte(nil), wire.Bytes()...)

			newCodec := func(t *testing.T, source io.Reader) *OwnerBodyCodec {
				t.Helper()
				validator := vmess.NewTimedUserValidator(protocol.DefaultIDHash)
				t.Cleanup(func() { common.Close(validator) })
				if err := validator.Add(user); err != nil {
					t.Fatal(err)
				}
				history := NewSessionHistory()
				t.Cleanup(func() { common.Close(history) })
				server := NewServerSession(validator, history)
				server.SetAEADForced(true)
				reader := &buf.BufferedReader{Reader: buf.NewReader(source)}
				decoded, err := server.DecodeRequestHeader(reader, false)
				if err != nil {
					t.Fatal(err)
				}
				codec, err := server.NewOwnerBodyCodec(decoded, reader)
				if err != nil {
					t.Fatal(err)
				}
				return codec
			}

			counter := &ownerBodyCountingReader{reader: bytes.NewReader(wireBytes)}
			probe := newCodec(t, counter)
			headerBytes := counter.bytes
			if headerBytes <= 0 || headerBytes >= len(wireBytes) {
				t.Fatalf("decoded header boundary = %d for %d-byte request", headerBytes, len(wireBytes))
			}

			for name, bodyBytesBeforeTimeout := range map[string]int{
				"size-prefix": 1,
				"record-body": probe.RequestSizeBytes() + 7,
			} {
				t.Run(name, func(t *testing.T) {
					source := &ownerBodyBoundaryReader{
						data:                   wireBytes,
						headerBytes:            headerBytes,
						bodyBytesBeforeTimeout: bodyBytesBeforeTimeout,
					}
					codec := newCodec(t, source)
					first, err := codec.ReadMultiBuffer()
					buf.ReleaseMulti(first)
					if !errors.Is(err, errOwnerBodyTestTimeout) {
						t.Fatalf("first fragmented read error = %v, want test timeout", err)
					}
					if codec.RequestTransferReady() {
						t.Fatal("partially consumed request was incorrectly marked transferable")
					}
					decoded, err := codec.ReadMultiBuffer()
					if err != nil {
						t.Fatalf("resume after timeout: %v", err)
					}
					defer buf.ReleaseMulti(decoded)
					if got := decoded.String(); got != string(payload) {
						t.Fatalf("resumed payload mismatch: got %d bytes, want %d", len(got), len(payload))
					}
					if !codec.RequestTransferReady() {
						t.Fatal("completed request record remained non-transferable")
					}
				})
			}
		})
	}
}

func TestOwnerBodyCodecMatchesStandardReaderAcrossEstablishedStream(t *testing.T) {
	for _, authenticatedLength := range []bool{false, true} {
		for _, noTermination := range []bool{false, true} {
			name := map[bool]string{false: "masked", true: "authenticated-length"}[authenticatedLength]
			if noTermination {
				name += "-no-termination"
			}
			t.Run(name, func(t *testing.T) {
				id := uuid.New()
				testsEnabled := ""
				if noTermination {
					testsEnabled = "NoTerminationSignal"
				}
				account, err := (&vmess.Account{Id: id.String(), TestsEnabled: testsEnabled}).AsAccount()
				if err != nil {
					t.Fatal(err)
				}
				user := &protocol.MemoryUser{Level: 0, Email: "owner-stream@example.com", Account: account}
				request := &protocol.RequestHeader{
					Version:  1,
					User:     user,
					Command:  protocol.RequestCommandTCP,
					Address:  net.DomainAddress("example.com"),
					Port:     443,
					Security: protocol.SecurityType_AES128_GCM,
					Option:   protocol.RequestOptionChunkStream | protocol.RequestOptionChunkMasking | protocol.RequestOptionGlobalPadding,
				}
				if authenticatedLength {
					request.Option.Set(protocol.RequestOptionAuthenticatedLength)
				}

				var wire bytes.Buffer
				client := NewClientSession(context.Background(), true, protocol.DefaultIDHash, 0)
				if err := client.EncodeRequestHeader(request, &wire); err != nil {
					t.Fatal(err)
				}
				writer, err := client.EncodeRequestBody(request, &wire)
				if err != nil {
					t.Fatal(err)
				}
				var want []byte
				for record := 0; record < 48; record++ {
					size := 1 + (record*977)%7000
					payload := bytes.Repeat([]byte{byte(record + 1)}, size)
					want = append(want, payload...)
					if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
						t.Fatalf("write record %d: %v", record, err)
					}
				}
				if !noTermination {
					if err := writer.WriteMultiBuffer(nil); err != nil {
						t.Fatal(err)
					}
				}
				wireBytes := append([]byte(nil), wire.Bytes()...)

				for chunkName, pattern := range map[string][]int{
					"socket-sized": nil,
					"single-byte":  {1},
					"irregular":    {2, 3, 5, 7, 11, 17, 31, 127, 4096},
				} {
					t.Run(chunkName, func(t *testing.T) {
						newBodyReader := func(t *testing.T, owner bool) buf.Reader {
							t.Helper()
							validator := vmess.NewTimedUserValidator(protocol.DefaultIDHash)
							t.Cleanup(func() { common.Close(validator) })
							if err := validator.Add(user); err != nil {
								t.Fatal(err)
							}
							history := NewSessionHistory()
							t.Cleanup(func() { common.Close(history) })
							server := NewServerSession(validator, history)
							server.SetAEADForced(true)
							source := &ownerBodyChunkReader{data: wireBytes, pattern: pattern}
							buffered := &buf.BufferedReader{Reader: buf.NewReader(source)}
							decoded, err := server.DecodeRequestHeader(buffered, false)
							if err != nil {
								t.Fatal(err)
							}
							if owner {
								codec, err := server.NewOwnerBodyCodec(decoded, buffered)
								if err != nil {
									t.Fatal(err)
								}
								return codec
							}
							body, err := server.DecodeRequestBody(decoded, buffered)
							if err != nil {
								t.Fatal(err)
							}
							return body
						}

						stockPlaintext, stockErr := readOwnerBodyStream(t, newBodyReader(t, false))
						ownerPlaintext, ownerErr := readOwnerBodyStream(t, newBodyReader(t, true))
						if !errors.Is(stockErr, io.EOF) || !errors.Is(ownerErr, io.EOF) {
							t.Fatalf("terminal errors = stock %v owner %v, want EOF", stockErr, ownerErr)
						}
						if !bytes.Equal(stockPlaintext, want) {
							t.Fatalf("stock plaintext mismatch: got %d want %d", len(stockPlaintext), len(want))
						}
						if !bytes.Equal(ownerPlaintext, want) {
							t.Fatalf("owner plaintext mismatch: got %d want %d", len(ownerPlaintext), len(want))
						}
					})
				}
			})
		}
	}
}

func TestOwnerBodyCodecResponseMatchesStandardWriterAcrossEstablishedStream(t *testing.T) {
	for _, authenticatedLength := range []bool{false, true} {
		for _, noTermination := range []bool{false, true} {
			name := map[bool]string{false: "masked", true: "authenticated-length"}[authenticatedLength]
			if noTermination {
				name += "-no-termination"
			}
			t.Run(name, func(t *testing.T) {
				var want []byte
				var payloads [][]byte
				for record := 0; record < 48; record++ {
					size := 1 + (record*1237)%7000
					payload := bytes.Repeat([]byte{byte(255 - record)}, size)
					payloads = append(payloads, payload)
					want = append(want, payload...)
				}

				decodeResponse := func(t *testing.T, owner bool, pattern []int) ([]byte, error) {
					t.Helper()
					id := uuid.New()
					testsEnabled := ""
					if noTermination {
						testsEnabled = "NoTerminationSignal"
					}
					account, err := (&vmess.Account{Id: id.String(), TestsEnabled: testsEnabled}).AsAccount()
					if err != nil {
						t.Fatal(err)
					}
					user := &protocol.MemoryUser{Level: 0, Email: "owner-response@example.com", Account: account}
					request := &protocol.RequestHeader{
						Version:  1,
						User:     user,
						Command:  protocol.RequestCommandTCP,
						Address:  net.DomainAddress("example.com"),
						Port:     443,
						Security: protocol.SecurityType_AES128_GCM,
						Option:   protocol.RequestOptionChunkStream | protocol.RequestOptionChunkMasking | protocol.RequestOptionGlobalPadding,
					}
					if authenticatedLength {
						request.Option.Set(protocol.RequestOptionAuthenticatedLength)
					}

					var requestWire bytes.Buffer
					client := NewClientSession(context.Background(), true, protocol.DefaultIDHash, 0)
					if err := client.EncodeRequestHeader(request, &requestWire); err != nil {
						t.Fatal(err)
					}
					requestWriter, err := client.EncodeRequestBody(request, &requestWire)
					if err != nil {
						t.Fatal(err)
					}
					if err := requestWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("request"))}); err != nil {
						t.Fatal(err)
					}

					validator := vmess.NewTimedUserValidator(protocol.DefaultIDHash)
					t.Cleanup(func() { common.Close(validator) })
					if err := validator.Add(user); err != nil {
						t.Fatal(err)
					}
					history := NewSessionHistory()
					t.Cleanup(func() { common.Close(history) })
					server := NewServerSession(validator, history)
					server.SetAEADForced(true)
					requestReader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(requestWire.Bytes()))}
					decoded, err := server.DecodeRequestHeader(requestReader, false)
					if err != nil {
						t.Fatal(err)
					}

					var responseWire bytes.Buffer
					response := &protocol.ResponseHeader{}
					if owner {
						codec, err := server.NewOwnerBodyCodec(decoded, requestReader)
						if err != nil {
							t.Fatal(err)
						}
						if err := codec.PrepareResponse(response); err != nil {
							t.Fatal(err)
						}
						for record, payload := range payloads {
							wire, err := codec.SealResponse(nil, payload)
							if err != nil {
								t.Fatalf("seal owner response %d: %v", record, err)
							}
							responseWire.Write(wire)
						}
						wire, err := codec.SealResponseEnd(nil)
						if err != nil {
							t.Fatal(err)
						}
						responseWire.Write(wire)
					} else {
						server.EncodeResponseHeader(response, &responseWire)
						writer, err := server.EncodeResponseBody(decoded, &responseWire)
						if err != nil {
							t.Fatal(err)
						}
						for record, payload := range payloads {
							if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(append([]byte(nil), payload...))}); err != nil {
								t.Fatalf("write standard response %d: %v", record, err)
							}
						}
						if !noTermination {
							if err := writer.WriteMultiBuffer(nil); err != nil {
								t.Fatal(err)
							}
						}
					}

					source := &ownerBodyChunkReader{data: responseWire.Bytes(), pattern: pattern}
					if _, err := client.DecodeResponseHeader(source); err != nil {
						t.Fatal(err)
					}
					body, err := client.DecodeResponseBody(request, source)
					if err != nil {
						t.Fatal(err)
					}
					return readOwnerBodyStream(t, body)
				}

				for chunkName, pattern := range map[string][]int{
					"socket-sized": nil,
					"single-byte":  {1},
					"irregular":    {2, 3, 5, 7, 11, 17, 31, 127, 4096},
				} {
					t.Run(chunkName, func(t *testing.T) {
						stockPlaintext, stockErr := decodeResponse(t, false, pattern)
						ownerPlaintext, ownerErr := decodeResponse(t, true, pattern)
						if !errors.Is(stockErr, io.EOF) || !errors.Is(ownerErr, io.EOF) {
							t.Fatalf("terminal errors = stock %v owner %v, want EOF", stockErr, ownerErr)
						}
						if !bytes.Equal(stockPlaintext, want) {
							t.Fatalf("stock plaintext mismatch: got %d want %d", len(stockPlaintext), len(want))
						}
						if !bytes.Equal(ownerPlaintext, want) {
							t.Fatalf("owner plaintext mismatch: got %d want %d", len(ownerPlaintext), len(want))
						}
					})
				}
			})
		}
	}
}
