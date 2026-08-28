//go:build !linux

package owner

import (
	"errors"
	"net"
)

type Role uint8

const (
	Inbound Role = iota + 1
	Outbound
)

type Action uint8
type Conn interface{}

const (
	None Action = iota
	Close
)

type Session interface {
	OnOpen(Role, Conn)
	OnTraffic(Role, Conn) Action
	OnWritable(Role, Conn) Action
	OnReadClosed(Role, Conn) Action
	OnClose(Role, Conn, error)
}

func AdoptPair(_, _ *net.TCPConn, _ Session) error {
	return errors.New("owner: socket reactor is only available on Linux")
}
