package engine

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type Features struct {
	Traffic bool
	Limiter bool
	Device  bool
	Rule    bool
}

type UserRuntime struct {
	UID      int
	Password string

	upload   atomic.Int64
	download atomic.Int64
	active   atomic.Int64

	limiterMu sync.Mutex
	limiter   *rate.Limiter

	deviceMu    sync.Mutex
	deviceLimit int
	deviceIPs   map[string]int
}

func newUserRuntime(uid int, password string, speedBytes int64, deviceLimit int) *UserRuntime {
	u := &UserRuntime{UID: uid, Password: password, deviceLimit: deviceLimit, deviceIPs: make(map[string]int)}
	u.setSpeed(speedBytes)
	return u
}

func (u *UserRuntime) setSpeed(bytesPerSecond int64) {
	u.limiterMu.Lock()
	defer u.limiterMu.Unlock()
	if bytesPerSecond <= 0 {
		u.limiter = nil
		return
	}
	burst := int(bytesPerSecond)
	if burst < 64*1024 {
		burst = 64 * 1024
	}
	u.limiter = rate.NewLimiter(rate.Limit(bytesPerSecond), burst)
}

func (u *UserRuntime) admit(ip string, enabled bool) bool {
	if !enabled || u.deviceLimit <= 0 {
		u.active.Add(1)
		return true
	}
	u.deviceMu.Lock()
	defer u.deviceMu.Unlock()
	if count := u.deviceIPs[ip]; count > 0 {
		u.deviceIPs[ip] = count + 1
		u.active.Add(1)
		return true
	}
	if len(u.deviceIPs) >= u.deviceLimit {
		return false
	}
	u.deviceIPs[ip] = 1
	u.active.Add(1)
	return true
}

func (u *UserRuntime) release(ip string, enabled bool) {
	u.active.Add(-1)
	if !enabled || u.deviceLimit <= 0 {
		return
	}
	u.deviceMu.Lock()
	if count := u.deviceIPs[ip]; count <= 1 {
		delete(u.deviceIPs, ip)
	} else {
		u.deviceIPs[ip] = count - 1
	}
	u.deviceMu.Unlock()
}

func (u *UserRuntime) snapshotTraffic() (upload, download int64) {
	return u.upload.Swap(0), u.download.Swap(0)
}

func (u *UserRuntime) restoreTraffic(upload, download int64) {
	u.upload.Add(upload)
	u.download.Add(download)
}

type featureWriter struct {
	inner    buf.Writer
	user     *UserRuntime
	ctx      context.Context
	download bool
	features Features
}

func (w *featureWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	n := int(mb.Len())
	if w.features.Limiter && w.user.limiter != nil && n > 0 {
		if err := w.user.limiter.WaitN(w.ctx, n); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	err := w.inner.WriteMultiBuffer(mb)
	if err == nil && w.features.Traffic {
		if w.download {
			w.user.download.Add(int64(n))
		} else {
			w.user.upload.Add(int64(n))
		}
	}
	return err
}

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
