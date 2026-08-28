package encoding_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vmess"
	. "github.com/xtls/xray-core/proxy/vmess/encoding"
)

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
