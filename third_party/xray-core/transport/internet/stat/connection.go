package stat

import (
	"net"

	"github.com/xtls/xray-core/features/stats"
)

type Connection interface {
	net.Conn
}

type CounterConnection struct {
	Connection
	ReadCounter  stats.Counter
	WriteCounter stats.Counter
}

// UnwrapTCPConnection returns the concrete socket together with every counter
// applied by nested CounterConnection wrappers. It deliberately rejects TLS,
// WebSocket and other wrapped transports which cannot transfer fd ownership.
func UnwrapTCPConnection(conn Connection) (*net.TCPConn, []stats.Counter, []stats.Counter, bool) {
	var readCounters []stats.Counter
	var writeCounters []stats.Counter
	for {
		counter, ok := conn.(*CounterConnection)
		if !ok {
			break
		}
		if counter.ReadCounter != nil {
			readCounters = append(readCounters, counter.ReadCounter)
		}
		if counter.WriteCounter != nil {
			writeCounters = append(writeCounters, counter.WriteCounter)
		}
		conn = counter.Connection
	}
	tcpConn, ok := conn.(*net.TCPConn)
	return tcpConn, readCounters, writeCounters, ok
}

func (c *CounterConnection) Read(b []byte) (int, error) {
	nBytes, err := c.Connection.Read(b)
	if c.ReadCounter != nil {
		c.ReadCounter.Add(int64(nBytes))
	}

	return nBytes, err
}

func (c *CounterConnection) Write(b []byte) (int, error) {
	nBytes, err := c.Connection.Write(b)
	if c.WriteCounter != nil {
		c.WriteCounter.Add(int64(nBytes))
	}
	return nBytes, err
}
