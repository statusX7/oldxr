package mydispatcher

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"expvar"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	routingSession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/time/rate"

	"github.com/XrayR-project/XrayR/common/limiter"
	"github.com/XrayR-project/XrayR/common/rule"
)

var errSniffingTimeout = newError("timeout on sniffing")

var (
	directDispatchAttempts = expvar.NewInt("oldxr_direct_dispatch_attempts")
	directDispatchFallback = expvar.NewInt("oldxr_direct_dispatch_fallback")
	directDispatchSuccess  = expvar.NewInt("oldxr_direct_dispatch_success")
	directDispatchFailures = expvar.NewMap("oldxr_direct_dispatch_failures")
)

var directDataPathEnabled = func() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("XRAYR_DIRECT_DATAPATH"))) {
	case "0", "false", "off":
		return false
	default:
		return true
	}
}()

type cachedReader struct {
	sync.Mutex
	reader buf.Reader
	cache  buf.MultiBuffer
}

type replayReader struct {
	reader buf.Reader
	cache  buf.MultiBuffer
}

func (r *replayReader) TakeBuffered() buf.MultiBuffer {
	mb := r.cache
	r.cache = nil
	return mb
}

func (r *replayReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		return mb, nil
	}
	return r.reader.ReadMultiBuffer()
}

func (r *replayReader) Interrupt() {
	if r.cache != nil {
		r.cache = buf.ReleaseMulti(r.cache)
	}
	common.Interrupt(r.reader)
}

func (r *cachedReader) Cache(b *buf.Buffer) {
	var mb buf.MultiBuffer
	if timeoutReader, ok := r.reader.(buf.TimeoutReader); ok {
		mb, _ = timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 100)
	} else {
		mb, _ = r.reader.ReadMultiBuffer()
	}
	r.Lock()
	if !mb.IsEmpty() {
		r.cache, _ = buf.MergeMulti(r.cache, mb)
	}
	b.Clear()
	rawBytes := b.Extend(buf.Size)
	n := r.cache.Copy(rawBytes)
	b.Resize(0, int32(n))
	r.Unlock()
}

func (r *cachedReader) readInternal() buf.MultiBuffer {
	r.Lock()
	defer r.Unlock()

	if r.cache != nil && !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		return mb
	}

	return nil
}

func (r *cachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	if timeoutReader, ok := r.reader.(buf.TimeoutReader); ok {
		return timeoutReader.ReadMultiBufferTimeout(timeout)
	}
	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) Interrupt() {
	r.Lock()
	if r.cache != nil {
		r.cache = buf.ReleaseMulti(r.cache)
	}
	r.Unlock()
	common.Interrupt(r.reader)
}

func (r *cachedReader) TakeBuffered() buf.MultiBuffer {
	r.Lock()
	defer r.Unlock()
	mb := r.cache
	r.cache = nil
	return mb
}

func (r *cachedReader) ReplayReader() buf.Reader {
	r.Lock()
	defer r.Unlock()
	if r.cache.IsEmpty() {
		return r.reader
	}
	replay := &replayReader{
		reader: r.reader,
		cache:  r.cache,
	}
	r.cache = nil
	return replay
}

// DefaultDispatcher is a default implementation of Dispatcher.
type DefaultDispatcher struct {
	ohm         outbound.Manager
	router      routing.Router
	policy      policy.Manager
	stats       stats.Manager
	dns         dns.Client
	fdns        dns.FakeDNSEngine
	Limiter     *limiter.Limiter
	RuleManager *rule.Manager
	userFlows   userFlowRegistry
}

type userIO struct {
	bucket          *rate.Limiter
	speedLimited    bool
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter
	runtime         *userFlowRuntime
	releaseOnce     sync.Once
}

func (u *userIO) OwnerEligible() bool {
	if !u.speedLimited || u.bucket == nil {
		return true
	}
	// The owner keeps at most one 64 KiB readiness batch per direction. Smaller
	// token bursts continue through the generic WaitN path, which can split the
	// write without stalling an event loop.
	return u.bucket.Burst() >= 64*1024
}

func (u *userIO) Acquire(bytes int) (time.Duration, bool) {
	if bytes <= 0 || !u.speedLimited || u.bucket == nil {
		return 0, true
	}
	burst := u.bucket.Burst()
	if burst <= 0 {
		return 0, false
	}
	now := time.Now()
	var ready time.Duration
	for bytes > 0 {
		chunk := bytes
		if chunk > burst {
			chunk = burst
		}
		reservation := u.bucket.ReserveN(now, chunk)
		if !reservation.OK() {
			return 0, false
		}
		if delay := reservation.DelayFrom(now); delay > ready {
			ready = delay
		}
		bytes -= chunk
	}
	return ready, true
}

func (u *userIO) AddUplink(bytes int64) {
	if u.uplinkCounter != nil && bytes > 0 {
		u.uplinkCounter.Add(bytes)
	}
}

func (u *userIO) AddDownlink(bytes int64) {
	if u.downlinkCounter != nil && bytes > 0 {
		u.downlinkCounter.Add(bytes)
	}
}

func (u *userIO) Release() {
	if u == nil {
		return
	}
	u.releaseOnce.Do(func() {
		if u.runtime != nil {
			u.runtime.release()
		}
	})
}

func (d *DefaultDispatcher) getUserIO(ctx context.Context) (*userIO, error) {
	result := new(userIO)
	sessionInbound := session.InboundFromContext(ctx)
	if sessionInbound == nil || sessionInbound.User == nil || len(sessionInbound.User.Email) == 0 {
		return result, nil
	}

	user := sessionInbound.User
	runtime, allowed := d.userFlows.acquire(sessionInbound.Tag, user.Email)
	if !allowed {
		return nil, newError("user is no longer active: ", user.Email)
	}
	result.runtime = runtime
	keepRuntime := false
	defer func() {
		if !keepRuntime {
			result.Release()
		}
	}()
	bucket, ok, reject := d.Limiter.GetUserBucket(sessionInbound.Tag, user.Email, sessionInbound.Source.Address.IP().String())
	if reject {
		newError("Devices reach the limit: ", user.Email).AtWarning().WriteToLog()
		return nil, newError("Devices reach the limit: ", user.Email)
	}
	result.bucket = bucket
	result.speedLimited = ok

	p := d.policy.ForLevel(user.Level)
	if p.Stats.UserUplink {
		name := userUplinkCounterName(user.Email)
		result.uplinkCounter, _ = getOrRegisterCounter(d.stats, name)
	}
	if p.Stats.UserDownlink {
		name := userDownlinkCounterName(user.Email)
		result.downlinkCounter, _ = getOrRegisterCounter(d.stats, name)
	}

	keepRuntime = true
	return result, nil
}

func getOrRegisterCounter(manager stats.Manager, name string) (stats.Counter, error) {
	counter, err := stats.GetOrRegisterCounter(manager, name)
	if err != nil {
		// GetOrRegisterCounter is intentionally generic and can lose a concurrent
		// RegisterCounter race. Re-read the manager before surfacing the error.
		if counter = manager.GetCounter(name); counter != nil {
			return counter, nil
		}
	}
	return counter, err
}

func (d *DefaultDispatcher) wrapUserWriter(ctx context.Context, writer buf.Writer, bucket *rate.Limiter, speedLimited bool, counter stats.Counter) buf.Writer {
	if speedLimited {
		writer = d.Limiter.RateWriterContext(ctx, writer, bucket)
	}
	if counter != nil {
		writer = &SizeStatWriter{Counter: counter, Writer: writer}
	}
	return writer
}

func (d *DefaultDispatcher) wrapUserReader(ctx context.Context, reader buf.Reader, bucket *rate.Limiter, speedLimited bool, counter stats.Counter) buf.Reader {
	if counter != nil {
		reader = &SizeStatReader{Counter: counter, Reader: reader}
	}
	if speedLimited {
		reader = d.Limiter.RateReaderContext(ctx, reader, bucket)
	}
	return reader
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DefaultDispatcher)
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager, dc dns.Client) error {
			core.RequireFeatures(ctx, func(fdns dns.FakeDNSEngine) {
				d.fdns = fdns
			})
			return d.Init(config.(*Config), om, router, pm, sm, dc)
		}); err != nil {
			return nil, err
		}
		return d, nil
	}))
}

// Init initializes DefaultDispatcher.
func (d *DefaultDispatcher) Init(config *Config, om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager, dns dns.Client) error {
	d.ohm = om
	d.router = router
	d.policy = pm
	d.stats = sm
	d.Limiter = limiter.New()
	d.RuleManager = rule.New()
	d.dns = dns
	return nil
}

// Type implements common.HasType.
func (*DefaultDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

// Start implements common.Runnable.
func (*DefaultDispatcher) Start() error {
	return nil
}

// Close implements common.Closable.
func (*DefaultDispatcher) Close() error {
	return nil
}

func (d *DefaultDispatcher) getLink(ctx context.Context, network net.Network, sniffing session.SniffingRequest) (*transport.Link, *transport.Link, error) {
	downOpt := pipe.OptionsFromContext(ctx)
	upOpt := downOpt

	if network == net.Network_UDP {
		var ip2domain *sync.Map // net.IP.String() => domain, this map is used by server side when client turn on fakedns
		// Client will send domain address in the buffer.UDP.Address, server record all possible target IP addrs.
		// When target replies, server will restore the domain and send back to client.
		// Note: this map is not global but per connection context
		upOpt = append(upOpt, pipe.OnTransmission(func(mb buf.MultiBuffer) buf.MultiBuffer {
			for i, buffer := range mb {
				if buffer.UDP == nil {
					continue
				}
				addr := buffer.UDP.Address
				if addr.Family().IsIP() {
					if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && fkr0.IsIPInIPPool(addr) && sniffing.Enabled {
						domain := fkr0.GetDomainFromFakeDNS(addr)
						if len(domain) > 0 {
							buffer.UDP.Address = net.DomainAddress(domain)
							newError("[fakedns client] override with domain: ", domain, " for xUDP buffer at ", i).WriteToLog(session.ExportIDToError(ctx))
						} else {
							newError("[fakedns client] failed to find domain! :", addr.String(), " for xUDP buffer at ", i).AtWarning().WriteToLog(session.ExportIDToError(ctx))
						}
					}
				} else {
					if ip2domain == nil {
						ip2domain = new(sync.Map)
						newError("[fakedns client] create a new map").WriteToLog(session.ExportIDToError(ctx))
					}
					domain := addr.Domain()
					ips, err := d.dns.LookupIP(domain, dns.IPOption{IPv4Enable: true, IPv6Enable: true})
					if err == nil {
						for _, ip := range ips {
							ip2domain.Store(ip.String(), domain)
						}
						newError("[fakedns client] candidate ip: "+fmt.Sprintf("%v", ips), " for xUDP buffer at ", i).WriteToLog(session.ExportIDToError(ctx))
					} else {
						newError("[fakedns client] failed to look up IP for ", domain, " for xUDP buffer at ", i).Base(err).WriteToLog(session.ExportIDToError(ctx))
					}
				}
			}
			return mb
		}))
		downOpt = append(downOpt, pipe.OnTransmission(func(mb buf.MultiBuffer) buf.MultiBuffer {
			for i, buffer := range mb {
				if buffer.UDP == nil {
					continue
				}
				addr := buffer.UDP.Address
				if addr.Family().IsIP() {
					if ip2domain == nil {
						continue
					}
					if domain, found := ip2domain.Load(addr.IP().String()); found {
						buffer.UDP.Address = net.DomainAddress(domain.(string))
						newError("[fakedns client] restore domain: ", domain.(string), " for xUDP buffer at ", i).WriteToLog(session.ExportIDToError(ctx))
					}
				} else {
					if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok {
						fakeIp := fkr0.GetFakeIPForDomain(addr.Domain())
						buffer.UDP.Address = fakeIp[0]
						newError("[fakedns client] restore FakeIP: ", buffer.UDP, fmt.Sprintf("%v", fakeIp), " for xUDP buffer at ", i).WriteToLog(session.ExportIDToError(ctx))
					}
				}
			}
			return mb
		}))
	}
	uplinkReader, uplinkWriter := pipe.New(upOpt...)
	downlinkReader, downlinkWriter := pipe.New(downOpt...)

	inboundLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	outboundLink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	io, err := d.getUserIO(ctx)
	if err != nil {
		common.Close(outboundLink.Writer)
		common.Close(inboundLink.Writer)
		common.Interrupt(outboundLink.Reader)
		common.Interrupt(inboundLink.Reader)
		return nil, nil, err
	}
	inboundLink.Writer = d.wrapUserWriter(ctx, inboundLink.Writer, io.bucket, io.speedLimited, io.uplinkCounter)
	outboundLink.Writer = d.wrapUserWriter(ctx, outboundLink.Writer, io.bucket, io.speedLimited, io.downlinkCounter)
	lifecycle := newUserConnectionLifecycle(io, 2)
	inboundLink.Writer = &lifecycleWriter{Writer: inboundLink.Writer, lifecycle: lifecycle}
	outboundLink.Writer = &lifecycleWriter{Writer: outboundLink.Writer, lifecycle: lifecycle}

	return inboundLink, outboundLink, nil
}

func (d *DefaultDispatcher) shouldOverride(ctx context.Context, result SniffResult, request session.SniffingRequest, destination net.Destination) bool {
	domain := result.Domain()
	for _, d := range request.ExcludeForDomain {
		if strings.ToLower(domain) == d {
			return false
		}
	}
	protocolString := result.Protocol()
	if resComp, ok := result.(SnifferResultComposite); ok {
		protocolString = resComp.ProtocolForDomainResult()
	}
	for _, p := range request.OverrideDestinationForProtocol {
		if strings.HasPrefix(protocolString, p) {
			return true
		}
		if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && protocolString != "bittorrent" && p == "fakedns" &&
			destination.Address.Family().IsIP() && fkr0.IsIPInIPPool(destination.Address) {
			newError("Using sniffer ", protocolString, " since the fake DNS missed").WriteToLog(session.ExportIDToError(ctx))
			return true
		}
		if resultSubset, ok := result.(SnifferIsProtoSubsetOf); ok {
			if resultSubset.IsProtoSubsetOf(p) {
				return true
			}
		}
	}

	return false
}

// Dispatch implements routing.Dispatcher.
func (d *DefaultDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if !destination.IsValid() {
		panic("Dispatcher: Invalid destination.")
	}
	ob := &session.Outbound{
		Target: destination,
	}
	ctx = session.ContextWithOutbound(ctx, ob)
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}

	sniffingRequest := content.SniffingRequest
	inbound, outbound, err := d.getLink(ctx, destination.Network, sniffingRequest)
	if err != nil {
		return nil, err
	}
	if !sniffingRequest.Enabled {
		go d.routedDispatch(ctx, outbound, destination)
	} else {
		go func() {
			cReader := &cachedReader{
				reader: outbound.Reader.(*pipe.Reader),
			}
			outbound.Reader = cReader
			result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
			if err == nil {
				content.Protocol = result.Protocol()
			}
			if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
				domain := result.Domain()
				newError("sniffed domain: ", domain).WriteToLog(session.ExportIDToError(ctx))
				destination.Address = net.ParseAddress(domain)
				if sniffingRequest.RouteOnly && result.Protocol() != "fakedns" {
					ob.RouteTarget = destination
				} else {
					ob.Target = destination
				}
			}
			d.routedDispatch(ctx, outbound, destination)
		}()
	}
	return inbound, nil
}

// DispatchLink implements routing.Dispatcher.
func (d *DefaultDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	if !destination.IsValid() {
		return newError("Dispatcher: Invalid destination.")
	}
	ob := &session.Outbound{
		Target: destination,
	}
	ctx = session.ContextWithOutbound(ctx, ob)
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}
	sniffingRequest := content.SniffingRequest
	if !sniffingRequest.Enabled {
		go d.routedDispatch(ctx, outbound, destination)
	} else {
		go func() {
			cReader := &cachedReader{
				reader: outbound.Reader.(*pipe.Reader),
			}
			outbound.Reader = cReader
			result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
			if err == nil {
				content.Protocol = result.Protocol()
			}
			if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
				domain := result.Domain()
				newError("sniffed domain: ", domain).WriteToLog(session.ExportIDToError(ctx))
				destination.Address = net.ParseAddress(domain)
				if sniffingRequest.RouteOnly && result.Protocol() != "fakedns" {
					ob.RouteTarget = destination
				} else {
					ob.Target = destination
				}
			}
			d.routedDispatch(ctx, outbound, destination)
		}()
	}

	return nil
}

func sniffer(ctx context.Context, cReader *cachedReader, metadataOnly bool, network net.Network) (SniffResult, error) {
	payload := buf.New()
	defer payload.Release()

	sniffer := NewSniffer(ctx)

	metaresult, metadataErr := sniffer.SniffMetadata(ctx)

	if metadataOnly {
		return metaresult, metadataErr
	}

	contentResult, contentErr := func() (SniffResult, error) {
		totalAttempt := 0
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				totalAttempt++
				if totalAttempt > 2 {
					return nil, errSniffingTimeout
				}

				cReader.Cache(payload)
				if !payload.IsEmpty() {
					result, err := sniffer.Sniff(ctx, payload.Bytes(), network)
					if err != common.ErrNoClue {
						return result, err
					}
				}
				if payload.IsFull() {
					return nil, errUnknownContent
				}
			}
		}
	}()
	if contentErr != nil && metadataErr == nil {
		return metaresult, nil
	}
	if contentErr == nil && metadataErr == nil {
		return CompositeResult(metaresult, contentResult), nil
	}
	return contentResult, contentErr
}

type outboundSelection struct {
	handler     outbound.Handler
	destination net.Destination
	inboundTag  string
	pickRoute   int
}

func (d *DefaultDispatcher) selectOutbound(ctx context.Context, destination net.Destination) (*outboundSelection, error) {
	ob := session.OutboundFromContext(ctx)
	if ob == nil {
		return nil, newError("outbound session not found")
	}
	if hosts, ok := d.dns.(dns.HostsLookup); ok && destination.Address.Family().IsDomain() {
		proxied := hosts.LookupHosts(ob.Target.String())
		if proxied != nil {
			ro := ob.RouteTarget == destination
			destination.Address = *proxied
			if ro {
				ob.RouteTarget = destination
			} else {
				ob.Target = destination
			}
		}
	}

	var handler outbound.Handler

	// Check if domain and protocol hit the rule
	sessionInbound := session.InboundFromContext(ctx)
	// Whether the inbound connection contains a user
	if sessionInbound != nil && sessionInbound.User != nil {
		if d.RuleManager.Detect(sessionInbound.Tag, destination.String(), sessionInbound.User.Email) {
			newError(fmt.Sprintf("User %s access %s reject by rule", sessionInbound.User.Email, destination.String())).AtError().WriteToLog()
			return nil, newError("destination is reject by rule")
		}
	}

	routingLink := routingSession.AsRoutingContext(ctx)
	inTag := routingLink.GetInboundTag()
	isPickRoute := 0
	if forcedOutboundTag := session.GetForcedOutboundTagFromContext(ctx); forcedOutboundTag != "" {
		ctx = session.SetForcedOutboundTagToContext(ctx, "")
		if h := d.ohm.GetHandler(forcedOutboundTag); h != nil {
			isPickRoute = 1
			newError("taking platform initialized detour [", forcedOutboundTag, "] for [", destination, "]").WriteToLog(session.ExportIDToError(ctx))
			handler = h
		} else {
			newError("non existing tag for platform initialized detour: ", forcedOutboundTag).AtError().WriteToLog(session.ExportIDToError(ctx))
			return nil, newError("non existing tag for platform initialized detour: ", forcedOutboundTag)
		}
	} else if d.router != nil {
		if route, err := d.router.PickRoute(routingLink); err == nil {
			outTag := route.GetOutboundTag()
			if h := d.ohm.GetHandler(outTag); h != nil {
				isPickRoute = 2
				newError("taking detour [", outTag, "] for [", destination, "]").WriteToLog(session.ExportIDToError(ctx))
				handler = h
			} else {
				newError("non existing outTag: ", outTag).AtWarning().WriteToLog(session.ExportIDToError(ctx))
			}
		} else {
			newError("default route for ", destination).WriteToLog(session.ExportIDToError(ctx))
		}
	}

	if handler == nil {
		handler = d.ohm.GetHandler(inTag) // Default outbound handler tag should be as same as the inbound tag
	}

	// If there is no outbound with tag as same as the inbound tag
	if handler == nil {
		handler = d.ohm.GetDefaultHandler()
	}

	if handler == nil {
		newError("default outbound handler not exist").WriteToLog(session.ExportIDToError(ctx))
		return nil, newError("default outbound handler not exist")
	}

	return &outboundSelection{
		handler:     handler,
		destination: ob.Target,
		inboundTag:  inTag,
		pickRoute:   isPickRoute,
	}, nil
}

func recordAccess(ctx context.Context, selection *outboundSelection) {
	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil {
		if tag := selection.handler.Tag(); tag != "" {
			if selection.inboundTag == "" {
				accessMessage.Detour = tag
			} else if selection.pickRoute == 1 {
				accessMessage.Detour = selection.inboundTag + " ==> " + tag
			} else if selection.pickRoute == 2 {
				accessMessage.Detour = selection.inboundTag + " -> " + tag
			} else {
				accessMessage.Detour = selection.inboundTag + " >> " + tag
			}
		}
		log.Record(accessMessage)
	}
}

// DispatchDirect performs sniffing and routing synchronously, then transfers
// ownership of a supported direct outbound socket to the protocol handler. Any
// bytes consumed while sniffing are returned through the replay reader so the
// regular dispatcher remains a lossless fallback.
func (d *DefaultDispatcher) DispatchDirect(ctx context.Context, destination net.Destination, input buf.Reader) (*transport.DirectLink, buf.Reader, error) {
	if !directDataPathEnabled {
		return nil, input, nil
	}
	directDispatchAttempts.Add(1)
	if !destination.IsValid() {
		directDispatchFailures.Add("invalid_destination", 1)
		return nil, input, newError("Dispatcher: Invalid destination.")
	}
	if destination.Network != net.Network_TCP {
		return nil, input, nil
	}

	ob := &session.Outbound{Target: destination}
	ctx = session.ContextWithOutbound(ctx, ob)
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}
	userIO, err := d.getUserIO(ctx)
	if err != nil {
		directDispatchFailures.Add("user_io", 1)
		return nil, input, err
	}

	replayReader := input
	sniffingRequest := content.SniffingRequest
	if sniffingRequest.Enabled {
		cReader := &cachedReader{reader: input}
		result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
		if err == nil {
			content.Protocol = result.Protocol()
		}
		if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
			domain := result.Domain()
			newError("sniffed domain: ", domain).WriteToLog(session.ExportIDToError(ctx))
			destination.Address = net.ParseAddress(domain)
			if sniffingRequest.RouteOnly && result.Protocol() != "fakedns" {
				ob.RouteTarget = destination
			} else {
				ob.Target = destination
			}
		}
		replayReader = cReader.ReplayReader()
	}

	selection, err := d.selectOutbound(ctx, destination)
	if err != nil {
		directDispatchFailures.Add("select_outbound", 1)
		userIO.Release()
		return nil, replayReader, err
	}
	directHandler, ok := selection.handler.(outbound.DirectHandler)
	if !ok {
		directDispatchFallback.Add(1)
		userIO.Release()
		return nil, replayReader, nil
	}

	directLink, supported, err := directHandler.OpenDirect(ctx, selection.destination)
	if err != nil {
		directDispatchFailures.Add("open_direct", 1)
		userIO.Release()
		return nil, replayReader, err
	}
	if !supported {
		directDispatchFallback.Add(1)
		userIO.Release()
		return nil, replayReader, nil
	}
	if directLink == nil || directLink.Reader == nil || directLink.Writer == nil {
		directDispatchFailures.Add("invalid_link", 1)
		if directLink != nil {
			_ = directLink.Close()
		}
		userIO.Release()
		return nil, replayReader, newError("direct outbound returned an invalid link")
	}

	directLink.SetFlow(userIO)
	directLink.Writer = d.wrapUserWriter(ctx, directLink.Writer, userIO.bucket, userIO.speedLimited, userIO.uplinkCounter)
	directLink.Reader = d.wrapUserReader(ctx, directLink.Reader, userIO.bucket, userIO.speedLimited, userIO.downlinkCounter)
	recordAccess(ctx, selection)
	directDispatchSuccess.Add(1)
	return directLink, replayReader, nil
}

func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {
	selection, err := d.selectOutbound(ctx, destination)
	if err != nil {
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return
	}

	recordAccess(ctx, selection)
	selection.handler.Dispatch(ctx, link)
}
