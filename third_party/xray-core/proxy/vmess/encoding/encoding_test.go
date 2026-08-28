package encoding_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vmess"
	. "github.com/xtls/xray-core/proxy/vmess/encoding"
)

func toAccount(a *vmess.Account) protocol.Account {
	account, err := a.AsAccount()
	common.Must(err)
	return account
}

func TestRequestSerialization(t *testing.T) {
	user := &protocol.MemoryUser{
		Level: 0,
		Email: "test@example.com",
	}
	id := uuid.New()
	account := &vmess.Account{
		Id: id.String(),
	}
	user.Account = toAccount(account)

	expectedRequest := &protocol.RequestHeader{
		Version:  1,
		User:     user,
		Command:  protocol.RequestCommandTCP,
		Address:  net.DomainAddress("www.example.com"),
		Port:     net.Port(443),
		Security: protocol.SecurityType_AES128_GCM,
	}

	buffer := buf.New()
	client := NewClientSession(context.TODO(), true, protocol.DefaultIDHash, 0)
	common.Must(client.EncodeRequestHeader(expectedRequest, buffer))

	buffer2 := buf.New()
	buffer2.Write(buffer.Bytes())

	sessionHistory := NewSessionHistory()
	defer common.Close(sessionHistory)

	userValidator := vmess.NewTimedUserValidator(protocol.DefaultIDHash)
	userValidator.Add(user)
	defer common.Close(userValidator)

	server := NewServerSession(userValidator, sessionHistory)
	actualRequest, err := server.DecodeRequestHeader(buffer, false)
	common.Must(err)

	if r := cmp.Diff(actualRequest, expectedRequest, cmp.AllowUnexported(protocol.ID{})); r != "" {
		t.Error(r)
	}

	_, err = server.DecodeRequestHeader(buffer2, false)
	// anti replay attack
	if err == nil {
		t.Error("nil error")
	}
}

func TestLegacyRequestHonorsAEADForcedMode(t *testing.T) {
	user := &protocol.MemoryUser{
		Level: 0,
		Email: "legacy@example.com",
	}
	id := uuid.New()
	user.Account = toAccount(&vmess.Account{Id: id.String()})
	request := &protocol.RequestHeader{
		Version:  1,
		User:     user,
		Command:  protocol.RequestCommandTCP,
		Address:  net.DomainAddress("www.example.com"),
		Port:     net.Port(443),
		Security: protocol.SecurityType_AES128_GCM,
	}

	encodeLegacy := func() *buf.Buffer {
		buffer := buf.New()
		client := NewClientSession(context.TODO(), false, protocol.DefaultIDHash, 0)
		common.Must(client.EncodeRequestHeader(request, buffer))
		return buffer
	}
	encodeAEAD := func() *buf.Buffer {
		buffer := buf.New()
		client := NewClientSession(context.TODO(), true, protocol.DefaultIDHash, 0)
		common.Must(client.EncodeRequestHeader(request, buffer))
		return buffer
	}

	t.Run("legacy enabled", func(t *testing.T) {
		validator := vmess.NewTimedUserValidator(protocol.DefaultIDHash)
		defer common.Close(validator)
		common.Must(validator.Add(user))
		history := NewSessionHistory()
		defer common.Close(history)
		buffer := encodeLegacy()
		defer buffer.Release()

		server := NewServerSession(validator, history)
		actual, err := server.DecodeRequestHeader(buffer, false)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(actual, request, cmp.AllowUnexported(protocol.ID{})); diff != "" {
			t.Error(diff)
		}
	})

	t.Run("AEAD forced", func(t *testing.T) {
		validator := vmess.NewAEADUserValidator(protocol.DefaultIDHash)
		defer common.Close(validator)
		common.Must(validator.Add(user))
		history := NewSessionHistory()
		defer common.Close(history)
		buffer := encodeLegacy()
		defer buffer.Release()

		server := NewServerSession(validator, history)
		server.SetAEADForced(true)
		aeadBuffer := encodeAEAD()
		defer aeadBuffer.Release()
		actual, err := server.DecodeRequestHeader(aeadBuffer, false)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(actual, request, cmp.AllowUnexported(protocol.ID{})); diff != "" {
			t.Error(diff)
		}
		if _, err := server.DecodeRequestHeader(buffer, false); err == nil || !strings.Contains(err.Error(), "VMessAEAD is enforced") {
			t.Fatalf("legacy request was not rejected by AEAD forced mode: %v", err)
		}
	})
}

func TestInvalidRequest(t *testing.T) {
	user := &protocol.MemoryUser{
		Level: 0,
		Email: "test@example.com",
	}
	id := uuid.New()
	account := &vmess.Account{
		Id: id.String(),
	}
	user.Account = toAccount(account)

	expectedRequest := &protocol.RequestHeader{
		Version:  1,
		User:     user,
		Command:  protocol.RequestCommand(100),
		Address:  net.DomainAddress("www.example.com"),
		Port:     net.Port(443),
		Security: protocol.SecurityType_AES128_GCM,
	}

	buffer := buf.New()
	client := NewClientSession(context.TODO(), true, protocol.DefaultIDHash, 0)
	common.Must(client.EncodeRequestHeader(expectedRequest, buffer))

	buffer2 := buf.New()
	buffer2.Write(buffer.Bytes())

	sessionHistory := NewSessionHistory()
	defer common.Close(sessionHistory)

	userValidator := vmess.NewTimedUserValidator(protocol.DefaultIDHash)
	userValidator.Add(user)
	defer common.Close(userValidator)

	server := NewServerSession(userValidator, sessionHistory)
	_, err := server.DecodeRequestHeader(buffer, false)
	if err == nil {
		t.Error("nil error")
	}
}

func TestMuxRequest(t *testing.T) {
	user := &protocol.MemoryUser{
		Level: 0,
		Email: "test@example.com",
	}
	id := uuid.New()
	account := &vmess.Account{
		Id: id.String(),
	}
	user.Account = toAccount(account)

	expectedRequest := &protocol.RequestHeader{
		Version:  1,
		User:     user,
		Command:  protocol.RequestCommandMux,
		Security: protocol.SecurityType_AES128_GCM,
		Address:  net.DomainAddress("v1.mux.cool"),
	}

	buffer := buf.New()
	client := NewClientSession(context.TODO(), true, protocol.DefaultIDHash, 0)
	common.Must(client.EncodeRequestHeader(expectedRequest, buffer))

	buffer2 := buf.New()
	buffer2.Write(buffer.Bytes())

	sessionHistory := NewSessionHistory()
	defer common.Close(sessionHistory)

	userValidator := vmess.NewTimedUserValidator(protocol.DefaultIDHash)
	userValidator.Add(user)
	defer common.Close(userValidator)

	server := NewServerSession(userValidator, sessionHistory)
	actualRequest, err := server.DecodeRequestHeader(buffer, false)
	common.Must(err)

	if r := cmp.Diff(actualRequest, expectedRequest, cmp.AllowUnexported(protocol.ID{})); r != "" {
		t.Error(r)
	}
}
