package shadowsocks

import (
	"context"
	stdnet "net"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/owner"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/udp"
)

type Server struct {
	config        *ServerConfig
	validator     *Validator
	policyManager policy.Manager
	cone          bool
}

func authenticationSourceAddress(inbound *session.Inbound, remote stdnet.Addr) net.Address {
	if inbound != nil && inbound.Source.Address != nil && inbound.Source.Address.Family().IsIP() {
		return inbound.Source.Address
	}
	switch address := remote.(type) {
	case *stdnet.TCPAddr:
		if len(address.IP) == 0 {
			return nil
		}
		return net.IPAddress(address.IP)
	case *stdnet.UDPAddr:
		if len(address.IP) == 0 {
			return nil
		}
		return net.IPAddress(address.IP)
	default:
		return nil
	}
}

// NewServer create a new Shadowsocks server.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	validator := new(Validator)
	users := make([]*protocol.MemoryUser, 0, len(config.Users))
	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, newError("failed to get shadowsocks user").Base(err).AtError()
		}
		users = append(users, u)
	}
	if err := validator.addUsers(users); err != nil {
		return nil, newError("failed to add users").Base(err).AtError()
	}

	v := core.MustFromContext(ctx)
	s := &Server{
		config:        config,
		validator:     validator,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
	}

	return s, nil
}

// AddUser implements proxy.UserManager.AddUser().
func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	return s.validator.Add(u)
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (s *Server) RemoveUser(ctx context.Context, e string) error {
	return s.validator.Del(e)
}

func (s *Server) Network() []net.Network {
	list := s.config.Network
	if len(list) == 0 {
		list = append(list, net.Network_TCP)
	}
	return list
}

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	switch network {
	case net.Network_TCP:
		return s.handleConnection(ctx, conn, dispatcher)
	case net.Network_UDP:
		return s.handleUDPPayload(ctx, conn, dispatcher)
	default:
		return newError("unknown network: ", network)
	}
}

func (s *Server) handleUDPPayload(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	udpServer := udp.NewDispatcher(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
		request := protocol.RequestHeaderFromContext(ctx)
		if request == nil {
			return
		}

		payload := packet.Payload

		if payload.UDP != nil {
			request = &protocol.RequestHeader{
				User:    request.User,
				Address: payload.UDP.Address,
				Port:    payload.UDP.Port,
			}
		}

		data, err := EncodeUDPPacket(request, payload.Bytes())
		payload.Release()
		if err != nil {
			newError("failed to encode UDP packet").Base(err).AtWarning().WriteToLog(session.ExportIDToError(ctx))
			return
		}
		defer data.Release()

		conn.Write(data.Bytes())
	})

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}

	var dest *net.Destination
	sourceAddress := authenticationSourceAddress(inbound, conn.RemoteAddr())

	reader := buf.NewPacketReader(conn)
	for {
		mpayload, err := reader.ReadMultiBuffer()
		if err != nil {
			break
		}

		for _, payload := range mpayload {
			var request *protocol.RequestHeader
			var data *buf.Buffer
			var err error

			if inbound.User != nil {
				validator := new(Validator)
				validator.Add(inbound.User)
				request, data, err = DecodeUDPPacket(validator, payload)
			} else {
				request, data, err = decodeUDPPacketWithSource(s.validator, payload, sourceAddress)
				if err == nil {
					inbound.User = request.User
				}
			}

			if err != nil {
				if inbound.Source.IsValid() {
					newError("dropping invalid UDP packet from: ", inbound.Source).Base(err).WriteToLog(session.ExportIDToError(ctx))
					log.Record(&log.AccessMessage{
						From:   inbound.Source,
						To:     "",
						Status: log.AccessRejected,
						Reason: err,
					})
				}
				payload.Release()
				continue
			}

			destination := request.Destination()

			currentPacketCtx := ctx
			if inbound.Source.IsValid() {
				currentPacketCtx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
					From:   inbound.Source,
					To:     destination,
					Status: log.AccessAccepted,
					Reason: "",
					Email:  request.User.Email,
				})
			}
			newError("tunnelling request to ", destination).WriteToLog(session.ExportIDToError(currentPacketCtx))

			data.UDP = &destination

			if !s.cone || dest == nil {
				dest = &destination
			}

			currentPacketCtx = protocol.ContextWithRequestHeader(currentPacketCtx, request)
			udpServer.Dispatch(currentPacketCtx, *dest, data)
		}
	}

	return nil
}

func (s *Server) handleConnection(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := s.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return newError("unable to set read deadline").Base(err).AtWarning()
	}

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}
	sourceAddress := authenticationSourceAddress(inbound, conn.RemoteAddr())

	var (
		request            *protocol.RequestHeader
		bodyReader         buf.Reader
		ownerReader        *ownerTCPReader
		ownerInbound       *stdnet.TCPConn
		ownerInboundReads  []stats.Counter
		ownerInboundWrites []stats.Counter
		err                error
	)
	ownerInbound, ownerInboundReads, ownerInboundWrites, ownerCandidate := s.ownerEligible(conn, dispatcher)
	if ownerCandidate {
		request, ownerReader, err = readOwnerTCPSession(s.validator, conn, sourceAddress)
		bodyReader = ownerReader
		ownerSSAttempts.Add(1)
	} else {
		bufferedReader := buf.BufferedReader{Reader: buf.NewReader(conn)}
		request, bodyReader, err = readTCPSessionWithSource(s.validator, &bufferedReader, sourceAddress)
	}
	if err != nil {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: err,
		})
		return newError("failed to create request from: ", conn.RemoteAddr()).Base(err)
	}
	conn.SetReadDeadline(time.Time{})

	inbound.User = request.User

	dest := request.Destination()
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  request.User.Email,
	})
	newError("tunnelling request to ", dest).WriteToLog(session.ExportIDToError(ctx))

	sessionPolicy = s.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)
	var responseReader buf.Reader
	var requestWriter buf.Writer
	var closeRequestWriter bool
	var closeDirect func() error

	if directDispatcher, ok := dispatcher.(routing.DirectDispatcher); ok {
		if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err == nil {
			directLink, replayReader, directErr := directDispatcher.DispatchDirect(ctx, dest, bodyReader)
			if replayReader != nil {
				bodyReader = replayReader
			}
			if resetErr := conn.SetReadDeadline(time.Time{}); resetErr != nil {
				newError("unable to reset direct sniff deadline").Base(resetErr).WriteToLog(session.ExportIDToError(ctx))
			}
			if directErr != nil {
				return newError("failed to dispatch direct request to ", dest).Base(directErr)
			}
			if directLink != nil {
				flow := directLink.Flow()
				if ownerReader != nil && directLink.Connection != nil && flow != nil && flow.OwnerEligible() {
					pending, buffered := takeOwnerBuffered(bodyReader)
					if buffered {
						flow = directLink.TakeFlow()
						ownerSession := newOwnerSSSession(ownerReader, request, directLink, flow, sessionPolicy.Timeouts, pending, ownerInboundReads, ownerInboundWrites)
						if ownerErr := owner.AdoptPair(ownerInbound, directLink.Connection, ownerSession); ownerErr != nil {
							flow.Release()
							ownerSession.flow = nil
							_ = directLink.Close()
							cancel()
							return newError("failed to transfer Shadowsocks sockets to owner reactor").Base(ownerErr)
						}
						ownerSSSuccess.Add(1)
						_ = directLink.Close()
						cancel()
						return nil
					}
				}
				if ownerReader != nil {
					ownerSSFallback.Add(1)
				}
				responseReader = directLink.Reader
				requestWriter = directLink.Writer
				closeDirect = directLink.Close
				defer closeDirect()
			}
		} else {
			newError("unable to set direct sniff deadline; using generic dispatcher").WriteToLog(session.ExportIDToError(ctx))
		}
	}

	if requestWriter == nil {
		link, err := dispatcher.Dispatch(ctx, dest)
		if err != nil {
			return err
		}
		responseReader = link.Reader
		requestWriter = link.Writer
		closeRequestWriter = true
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		responseWriter, err := WriteTCPResponse(request, bufferedWriter)
		if err != nil {
			return newError("failed to write response").Base(err)
		}

		{
			payload, err := responseReader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			if err := responseWriter.WriteMultiBuffer(payload); err != nil {
				return err
			}
		}

		if err := bufferedWriter.SetBuffered(false); err != nil {
			return err
		}

		if err := buf.Copy(responseReader, responseWriter, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transport all TCP response").Base(err)
		}

		return nil
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		if err := buf.Copy(bodyReader, requestWriter, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transport all TCP request").Base(err)
		}

		return nil
	}

	requestDoneAndCloseWriter := requestDone
	if closeRequestWriter {
		requestDoneAndCloseWriter = task.OnSuccess(requestDone, task.Close(requestWriter))
	}
	if err := task.Run(ctx, requestDoneAndCloseWriter, responseDone); err != nil {
		if closeDirect != nil {
			_ = closeDirect()
		} else {
			common.Interrupt(responseReader)
			common.Interrupt(requestWriter)
		}
		return newError("connection ends").Base(err)
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
