//go:build linux

package owner

import (
	"errors"
	"expvar"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/panjf2000/gnet/v2"
	"github.com/pawelgaczynski/giouring"
	"golang.org/x/sys/unix"
)

const (
	advancedUringOwnerLoops            = 2
	advancedUringOwnerEntries          = 4096
	advancedUringOwnerCQBatch          = 64
	advancedUringOwnerSetupQueue       = 2048
	advancedUringOwnerTaskQueue        = 8192
	advancedUringOwnerMaxSessions      = 2048
	advancedUringOwnerBuffers          = 2048
	advancedUringOwnerBufferSize       = 16 * 1024
	advancedUringOwnerRetainReadBytes  = 64 * 1024
	advancedUringOwnerRetainReadChunks = 8
	advancedUringOwnerStarvedFanout    = 8
	advancedUringOwnerMaxWrite         = 64 * 1024
	advancedUringOwnerRecvMultishot    = true
	advancedUringOwnerBufferGroup      = 0
	advancedUringOwnerWakeUserData     = ^uint64(0)
	advancedUringOwnerOperationBits    = 3
	advancedUringOwnerSideShift        = 2
)

const (
	advancedUringOwnerRecv uint64 = iota
	advancedUringOwnerSend
	advancedUringOwnerCancelRecv
)

const (
	advancedUringOwnerTaskWake uint8 = iota
	advancedUringOwnerTaskClose
)

var (
	advancedUringOwnerAttempts     = expvar.NewInt("xray_socket_owner_uring_attempts")
	advancedUringOwnerSuccess      = expvar.NewInt("xray_socket_owner_uring_success")
	advancedUringOwnerFailures     = expvar.NewInt("xray_socket_owner_uring_failures")
	advancedUringOwnerRecvs        = expvar.NewInt("xray_socket_owner_uring_recv_completions")
	advancedUringOwnerSends        = expvar.NewInt("xray_socket_owner_uring_send_completions")
	advancedUringOwnerCancels      = expvar.NewInt("xray_socket_owner_uring_cancel_completions")
	advancedUringOwnerWakes        = expvar.NewInt("xray_socket_owner_uring_wake_tasks")
	advancedUringOwnerSkippedWakes = expvar.NewInt("xray_socket_owner_uring_skipped_wake_tasks")
	advancedUringOwnerRearms       = expvar.NewInt("xray_socket_owner_uring_recv_rearms")
	advancedUringOwnerStarvations  = expvar.NewInt("xray_socket_owner_uring_recv_starvations")
	advancedUringOwnerRecoveries   = expvar.NewInt("xray_socket_owner_uring_recv_recoveries")
	advancedUringOwnerCloses       = expvar.NewMap("xray_socket_owner_uring_closes")
	advancedUringOwnerLoopErrors   = expvar.NewMap("xray_socket_owner_uring_loop_errors")
	advancedUringOwnerFallbacks    = expvar.NewMap("xray_socket_owner_uring_fallbacks")
)

type advancedUringOwnerReadChunk struct {
	buffer uint16
	length int
	offset int
}

type advancedUringOwnerEndpoint struct {
	conn *advancedUringOwnerConn

	readQueue      []advancedUringOwnerReadChunk
	readHead       int
	readBuffered   int
	readRetired    []uint16
	readScratch    []byte
	readArmed      bool
	cancelPending  bool
	readPaused     bool
	readStarved    bool
	readEOF        bool
	readNotified   bool
	resumeWakeNoop atomic.Bool

	sendBuffer             []byte
	sendPending            bool
	sendCompletion         bool
	sendN                  int
	sendErr                error
	writeArmed             bool
	writeShutdown          bool
	writeShutdownRequested bool
}

type advancedUringOwnerSession struct {
	id       uint64
	fds      [2]int
	slots    [2]uint32
	handler  Session
	endpoint [2]advancedUringOwnerEndpoint

	closing       bool
	closed        bool
	closeNotified bool
}

type advancedUringOwnerSetup struct {
	fds     [2]int
	handler Session
	result  chan error
}

type advancedUringOwnerTask struct {
	kind     uint8
	conn     *advancedUringOwnerConn
	callback gnet.AsyncCallback
}

type advancedUringOwnerLoop struct {
	ring          *giouring.Ring
	wakeFD        int
	setup         chan advancedUringOwnerSetup
	tasks         chan advancedUringOwnerTask
	sessions      []*advancedUringOwnerSession
	freeIDs       []uint32
	nextID        uint32
	bufferMemory  []byte
	bufferRing    *giouring.BufAndRing
	bufferBase    uintptr
	bufferOffset  int
	bufferCount   int
	bufferMask    int
	buffersHeld   int
	bufferEpoch   uint64
	starvedCount  int
	rearmBudget   int
	starvedCursor uint32
	probeEpoch    uint64
	probeUsed     bool
	stopping      atomic.Bool
	done          chan struct{}
	wg            sync.WaitGroup
	err           atomic.Pointer[error]
}

type advancedUringOwnerReactor struct {
	loops    []*advancedUringOwnerLoop
	next     atomic.Uint32
	stopping atomic.Bool
}

type advancedUringOwnerConn struct {
	loop    *advancedUringOwnerLoop
	session *advancedUringOwnerSession
	side    int
}

var defaultAdvancedUringOwner struct {
	once    sync.Once
	reactor *advancedUringOwnerReactor
	err     error
}

func advancedUringOwnerClient() (*advancedUringOwnerReactor, error) {
	defaultAdvancedUringOwner.once.Do(func() {
		defaultAdvancedUringOwner.reactor, defaultAdvancedUringOwner.err = newAdvancedUringOwnerReactor(advancedUringOwnerLoops)
	})
	return defaultAdvancedUringOwner.reactor, defaultAdvancedUringOwner.err
}

func adoptAdvancedUringPair(inbound, outbound *net.TCPConn, session Session) error {
	reactor, err := advancedUringOwnerClient()
	if err != nil {
		advancedUringOwnerFailures.Add(1)
		return err
	}
	return adoptAdvancedUringPairWith(reactor, inbound, outbound, session)
}

func adoptAdvancedUringPairWith(reactor *advancedUringOwnerReactor, inbound, outbound *net.TCPConn, session Session) error {
	if inbound == nil || outbound == nil || session == nil {
		return errors.New("owner: invalid advanced io_uring relay pair")
	}
	advancedUringOwnerAttempts.Add(1)
	if err := reactor.adoptPair(inbound, outbound, session); err != nil {
		advancedUringOwnerFailures.Add(1)
		return err
	}
	advancedUringOwnerSuccess.Add(1)
	return nil
}

func newAdvancedUringOwnerReactor(loopCount int) (*advancedUringOwnerReactor, error) {
	return newAdvancedUringOwnerReactorSized(loopCount, advancedUringOwnerEntries)
}

func newAdvancedUringOwnerReactorSized(loopCount, entries int) (*advancedUringOwnerReactor, error) {
	return newAdvancedUringOwnerReactorConfigured(loopCount, entries, advancedUringOwnerBuffers)
}

func newAdvancedUringOwnerReactorConfigured(loopCount, entries, bufferCount int) (*advancedUringOwnerReactor, error) {
	if loopCount <= 0 {
		return nil, errors.New("owner: advanced io_uring requires at least one loop")
	}
	if entries <= 0 {
		return nil, errors.New("owner: advanced io_uring requires a positive queue size")
	}
	if bufferCount <= 0 || bufferCount > 1<<15 || bufferCount&(bufferCount-1) != 0 {
		return nil, errors.New("owner: advanced io_uring buffer count must be a power of two no greater than 32768")
	}
	reactor := &advancedUringOwnerReactor{loops: make([]*advancedUringOwnerLoop, loopCount)}
	for index := range reactor.loops {
		loop, err := startAdvancedUringOwnerLoop(entries, bufferCount)
		if err != nil {
			for previous := 0; previous < index; previous++ {
				reactor.loops[previous].close()
			}
			return nil, fmt.Errorf("owner: initialize advanced io_uring loop %d: %w", index, err)
		}
		reactor.loops[index] = loop
	}
	return reactor, nil
}

type advancedUringOwnerLoopResult struct {
	loop *advancedUringOwnerLoop
	err  error
}

func startAdvancedUringOwnerLoop(entries, bufferCount int) (*advancedUringOwnerLoop, error) {
	result := make(chan advancedUringOwnerLoopResult, 1)
	go func() {
		runtime.LockOSThread()
		loop, err := newAdvancedUringOwnerLoop(entries, bufferCount)
		if err != nil {
			runtime.UnlockOSThread()
			result <- advancedUringOwnerLoopResult{err: err}
			return
		}
		loop.wg.Add(1)
		result <- advancedUringOwnerLoopResult{loop: loop}
		loop.runLocked()
	}()
	started := <-result
	return started.loop, started.err
}

func newAdvancedUringOwnerLoop(entries, bufferCount int) (*advancedUringOwnerLoop, error) {
	ring := giouring.NewRing()
	flags := giouring.SetupSingleIssuer | giouring.SetupCoopTaskrun | giouring.SetupDeferTaskrun
	if err := ring.QueueInit(uint32(entries), flags); err != nil {
		return nil, fmt.Errorf("queue init: %w", err)
	}
	if _, err := ring.RegisterFilesSparse(advancedUringOwnerMaxSessions * 2); err != nil {
		ring.QueueExit()
		return nil, fmt.Errorf("register sparse files: %w", err)
	}

	ringBytes := int(giouring.RingBufStructSize) * bufferCount
	bufferBytes := advancedUringOwnerBufferSize * bufferCount
	memory, err := syscall.Mmap(-1, 0, ringBytes+bufferBytes, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE)
	if err != nil {
		ring.QueueExit()
		return nil, fmt.Errorf("mmap provided buffers: %w", err)
	}
	bufferRing := (*giouring.BufAndRing)(unsafe.Pointer(&memory[0]))
	bufferRing.BufRingInit()
	registration := &giouring.BufReg{
		RingAddr:    uint64(uintptr(unsafe.Pointer(bufferRing))),
		RingEntries: uint32(bufferCount),
		Bgid:        advancedUringOwnerBufferGroup,
	}
	if _, err := ring.RegisterBufferRing(registration, 0); err != nil {
		_ = syscall.Munmap(memory)
		ring.QueueExit()
		return nil, fmt.Errorf("register provided buffer ring: %w", err)
	}
	bufferBase := uintptr(unsafe.Pointer(&memory[0])) + uintptr(ringBytes)
	mask := giouring.BufRingMask(uint32(bufferCount))
	for index := 0; index < bufferCount; index++ {
		bufferRing.BufRingAdd(bufferBase+uintptr(index*advancedUringOwnerBufferSize), advancedUringOwnerBufferSize, uint16(index), mask, index)
	}
	bufferRing.BufRingAdvance(bufferCount)

	wakeFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_, _ = ring.UnregisterBufferRing(advancedUringOwnerBufferGroup)
		_ = syscall.Munmap(memory)
		ring.QueueExit()
		return nil, os.NewSyscallError("eventfd", err)
	}
	loop := &advancedUringOwnerLoop{
		ring:         ring,
		wakeFD:       wakeFD,
		setup:        make(chan advancedUringOwnerSetup, advancedUringOwnerSetupQueue),
		tasks:        make(chan advancedUringOwnerTask, advancedUringOwnerTaskQueue),
		sessions:     make([]*advancedUringOwnerSession, advancedUringOwnerMaxSessions+1),
		bufferMemory: memory,
		bufferRing:   bufferRing,
		bufferBase:   bufferBase,
		bufferOffset: ringBytes,
		bufferCount:  bufferCount,
		bufferMask:   mask,
		done:         make(chan struct{}),
	}
	if err := loop.submitWakePoll(); err != nil {
		_ = unix.Close(wakeFD)
		_, _ = ring.UnregisterBufferRing(advancedUringOwnerBufferGroup)
		_ = syscall.Munmap(memory)
		ring.QueueExit()
		return nil, err
	}
	return loop, nil
}

func (reactor *advancedUringOwnerReactor) adoptPair(inbound, outbound *net.TCPConn, handler Session) error {
	if reactor.stopping.Load() {
		return errors.New("owner: advanced io_uring reactor is stopping")
	}
	inboundFD, err := duplicateAdvancedUringTCP(inbound)
	if err != nil {
		return err
	}
	outboundFD, err := duplicateAdvancedUringTCP(outbound)
	if err != nil {
		_ = unix.Close(inboundFD)
		return err
	}
	loopIndex := (reactor.next.Add(1) - 1) % uint32(len(reactor.loops))
	loop := reactor.loops[loopIndex]
	request := advancedUringOwnerSetup{
		fds:     [2]int{inboundFD, outboundFD},
		handler: handler,
		result:  make(chan error, 1),
	}
	select {
	case loop.setup <- request:
		if err := loop.wake(); err != nil {
			return err
		}
	case <-loop.done:
		_ = unix.Close(inboundFD)
		_ = unix.Close(outboundFD)
		return loop.failure()
	default:
		_ = unix.Close(inboundFD)
		_ = unix.Close(outboundFD)
		return errors.New("owner: advanced io_uring setup queue is full")
	}
	select {
	case err := <-request.result:
		if err == nil {
			_ = inbound.Close()
			_ = outbound.Close()
		}
		return err
	case <-loop.done:
		return loop.failure()
	}
}

func duplicateAdvancedUringTCP(connection *net.TCPConn) (int, error) {
	_ = connection.SetNoDelay(true)
	raw, err := connection.SyscallConn()
	if err != nil {
		return -1, err
	}
	fd := -1
	var duplicateErr error
	controlErr := raw.Control(func(socket uintptr) {
		fd, duplicateErr = unix.Dup(int(socket))
	})
	if controlErr != nil {
		return -1, controlErr
	}
	if duplicateErr != nil {
		return -1, duplicateErr
	}
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (reactor *advancedUringOwnerReactor) close() {
	if !reactor.stopping.CompareAndSwap(false, true) {
		return
	}
	for _, loop := range reactor.loops {
		loop.close()
	}
}

func (loop *advancedUringOwnerLoop) close() {
	if loop.stopping.CompareAndSwap(false, true) {
		_ = loop.wake()
	}
	loop.wg.Wait()
}

func (loop *advancedUringOwnerLoop) failure() error {
	if stored := loop.err.Load(); stored != nil {
		return *stored
	}
	return errors.New("owner: advanced io_uring loop stopped")
}

func (loop *advancedUringOwnerLoop) wake() error {
	var value [8]byte
	value[0] = 1
	_, err := unix.Write(loop.wakeFD, value[:])
	if err != nil && !errors.Is(err, unix.EAGAIN) {
		return os.NewSyscallError("eventfd write", err)
	}
	return nil
}

func (loop *advancedUringOwnerLoop) getSQE() (*giouring.SubmissionQueueEntry, error) {
	entry := loop.ring.GetSQE()
	if entry != nil {
		return entry, nil
	}
	if _, err := loop.ring.Submit(); err != nil {
		return nil, err
	}
	entry = loop.ring.GetSQE()
	if entry == nil {
		return nil, errors.New("owner: advanced io_uring submission queue is full")
	}
	return entry, nil
}

func (loop *advancedUringOwnerLoop) submitWakePoll() error {
	entry, err := loop.getSQE()
	if err != nil {
		return err
	}
	entry.PreparePollAdd(loop.wakeFD, unix.POLLIN)
	entry.UserData = advancedUringOwnerWakeUserData
	return nil
}

func (loop *advancedUringOwnerLoop) runLocked() {
	defer loop.wg.Done()
	defer runtime.UnlockOSThread()
	defer close(loop.done)
	defer loop.cleanup()

	cqes := make([]*giouring.CompletionQueueEvent, advancedUringOwnerCQBatch)
	for !loop.stopping.Load() {
		if _, err := loop.ring.SubmitAndWait(1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			loop.storeError(fmt.Errorf("submit and wait: %w", err))
			return
		}
		for {
			count := loop.ring.PeekBatchCQE(cqes)
			if count == 0 {
				break
			}
			for index := uint32(0); index < count; index++ {
				completion := cqes[index]
				loop.handleCompletion(completion.UserData, completion.Res, completion.Flags)
			}
			loop.ring.CQAdvance(count)
			// Buffer-ring ownership returned while processing this batch must be
			// visible before a replacement recv can consume it. Rearming before
			// CQAdvance permits the kernel to observe a new SQE while the batch's
			// provided-buffer completions are still outstanding.
			loop.rearmStarvedRecvs()
			if count == uint32(len(cqes)) {
				if _, err := loop.ring.Submit(); err != nil && !errors.Is(err, unix.EINTR) {
					loop.storeError(fmt.Errorf("submit during completion burst: %w", err))
					return
				}
			}
		}
	}
}

func (loop *advancedUringOwnerLoop) cleanup() {
	for _, session := range loop.sessions {
		if session != nil {
			loop.forceCloseSession(session, Inbound, loop.failure())
		}
	}
	for {
		select {
		case request := <-loop.setup:
			_ = unix.Close(request.fds[0])
			_ = unix.Close(request.fds[1])
			request.result <- loop.failure()
		default:
			_ = unix.Close(loop.wakeFD)
			_, _ = loop.ring.UnregisterBufferRing(advancedUringOwnerBufferGroup)
			_ = syscall.Munmap(loop.bufferMemory)
			loop.ring.QueueExit()
			return
		}
	}
}

func (loop *advancedUringOwnerLoop) handleCompletion(userData uint64, result int32, flags uint32) {
	if userData == advancedUringOwnerWakeUserData {
		if result < 0 {
			errno := unix.Errno(-result)
			if errors.Is(errno, unix.EINTR) {
				if err := loop.submitWakePoll(); err != nil {
					loop.storeError(fmt.Errorf("rearm eventfd poll after interrupt: %w", err))
					loop.stopping.Store(true)
				}
				return
			}
			loop.storeError(fmt.Errorf("eventfd poll completion: %w", errno))
			loop.stopping.Store(true)
			return
		}
		var counter [8]byte
		if _, err := unix.Read(loop.wakeFD, counter[:]); err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			loop.storeError(fmt.Errorf("drain eventfd: %w", err))
			loop.stopping.Store(true)
			return
		}
		loop.drainSetup()
		loop.drainTasks()
		if !loop.stopping.Load() {
			if err := loop.submitWakePoll(); err != nil {
				loop.storeError(fmt.Errorf("rearm eventfd poll: %w", err))
				loop.stopping.Store(true)
			}
		}
		return
	}

	sessionID, side, operation := decodeAdvancedUringOwnerUserData(userData)
	if sessionID == 0 || sessionID >= uint64(len(loop.sessions)) {
		loop.recycleCompletionBuffer(flags)
		return
	}
	session := loop.sessions[sessionID]
	if session == nil || session.closed {
		loop.recycleCompletionBuffer(flags)
		return
	}
	switch operation {
	case advancedUringOwnerRecv:
		loop.handleRecv(session, side, result, flags)
	case advancedUringOwnerSend:
		loop.handleSend(session, side, result)
	case advancedUringOwnerCancelRecv:
		loop.handleRecvCancel(session, side, result)
	default:
		loop.beginClose(session, roleForSide(side), errors.New("owner: unknown advanced io_uring completion"))
	}
}

func (loop *advancedUringOwnerLoop) drainSetup() {
	for {
		select {
		case request := <-loop.setup:
			if loop.stopping.Load() {
				_ = unix.Close(request.fds[0])
				_ = unix.Close(request.fds[1])
				request.result <- loop.failure()
				continue
			}
			request.result <- loop.addSession(request)
		default:
			return
		}
	}
}

func (loop *advancedUringOwnerLoop) drainTasks() {
	for {
		select {
		case task := <-loop.tasks:
			advancedUringOwnerWakes.Add(1)
			if task.conn == nil || task.conn.session == nil {
				continue
			}
			session := task.conn.session
			if session.closed || session.id >= uint64(len(loop.sessions)) || loop.sessions[session.id] != session {
				if task.callback != nil {
					_ = task.callback(nil, net.ErrClosed)
				}
				continue
			}
			switch task.kind {
			case advancedUringOwnerTaskWake:
				loop.invokeTraffic(session, task.conn.side)
				if !session.closing {
					loop.settleRead(session, task.conn.side)
					loop.maybeShutdownWrites(session)
				}
				if task.callback != nil {
					_ = task.callback(nil, nil)
				}
			case advancedUringOwnerTaskClose:
				loop.beginClose(session, roleForSide(task.conn.side), nil)
			}
		default:
			return
		}
	}
}

func (loop *advancedUringOwnerLoop) acquireSessionID() (uint32, error) {
	if count := len(loop.freeIDs); count > 0 {
		id := loop.freeIDs[count-1]
		loop.freeIDs = loop.freeIDs[:count-1]
		return id, nil
	}
	if loop.nextID >= advancedUringOwnerMaxSessions {
		return 0, errors.New("owner: advanced io_uring session capacity reached")
	}
	loop.nextID++
	return loop.nextID, nil
}

// reserveSessionRecvEntries guarantees that both initial receive operations can
// be staged before a session ID or fixed-file slot becomes visible. Without
// this all-or-nothing check, an exceptionally full SQ could submit the first
// recv and then fail the second one; immediately recycling that session ID
// would let the late completion address a different connection generation.
func (loop *advancedUringOwnerLoop) reserveSessionRecvEntries() error {
	if loop.ring.SQSpaceLeft() >= 2 {
		return nil
	}
	if _, err := loop.ring.Submit(); err != nil {
		return fmt.Errorf("owner: submit pending operations before session setup: %w", err)
	}
	if available := loop.ring.SQSpaceLeft(); available < 2 {
		return fmt.Errorf("owner: insufficient submission queue space for session setup: have=%d need=2", available)
	}
	return nil
}

func (loop *advancedUringOwnerLoop) addSession(request advancedUringOwnerSetup) error {
	if err := loop.reserveSessionRecvEntries(); err != nil {
		_ = unix.Close(request.fds[0])
		_ = unix.Close(request.fds[1])
		return err
	}
	id, err := loop.acquireSessionID()
	if err != nil {
		_ = unix.Close(request.fds[0])
		_ = unix.Close(request.fds[1])
		return err
	}
	session := &advancedUringOwnerSession{id: uint64(id), fds: request.fds, handler: request.handler}
	session.slots[0] = uint32(id-1) * 2
	session.slots[1] = session.slots[0] + 1
	registered := 0
	for side := range session.fds {
		// giouring exposes []int while Linux consumes an int32 array. Updating
		// one slot at a time avoids the 64-bit multi-element ABI mismatch.
		if _, err := loop.ring.RegisterFilesUpdate(uint(session.slots[side]), []int{session.fds[side]}); err != nil {
			for previous := 0; previous < registered; previous++ {
				_, _ = loop.ring.RegisterFilesUpdate(uint(session.slots[previous]), []int{-1})
			}
			_ = unix.Close(request.fds[0])
			_ = unix.Close(request.fds[1])
			loop.freeIDs = append(loop.freeIDs, id)
			return fmt.Errorf("owner: register fixed file %d: %w", side, err)
		}
		registered++
	}
	for side := range session.endpoint {
		conn := &advancedUringOwnerConn{loop: loop, session: session, side: side}
		session.endpoint[side].conn = conn
	}
	loop.sessions[id] = session
	if err := loop.submitRecv(session, 0); err != nil {
		loop.rollbackSession(session)
		return err
	}
	if err := loop.submitRecv(session, 1); err != nil {
		loop.rollbackSession(session)
		return err
	}
	session.handler.OnOpen(Outbound, session.endpoint[1].conn)
	session.handler.OnOpen(Inbound, session.endpoint[0].conn)
	return nil
}

func (loop *advancedUringOwnerLoop) rollbackSession(session *advancedUringOwnerSession) {
	for side := range session.slots {
		_, _ = loop.ring.RegisterFilesUpdate(uint(session.slots[side]), []int{-1})
		_ = unix.Close(session.fds[side])
	}
	loop.sessions[session.id] = nil
	loop.freeIDs = append(loop.freeIDs, uint32(session.id))
}

func (loop *advancedUringOwnerLoop) submitRecv(session *advancedUringOwnerSession, side int) error {
	endpoint := &session.endpoint[side]
	if endpoint.readArmed || endpoint.cancelPending || endpoint.readPaused || endpoint.readStarved || endpoint.readEOF || session.closing {
		return nil
	}
	entry, err := loop.getSQE()
	if err != nil {
		return err
	}
	if advancedUringOwnerRecvMultishot {
		entry.PrepareRecvMultishot(int(session.slots[side]), 0, 0, 0)
	} else {
		entry.PrepareRecv(int(session.slots[side]), 0, advancedUringOwnerBufferSize, 0)
	}
	entry.Flags |= giouring.SqeBufferSelect | giouring.SqeFixedFile
	entry.BufIG = advancedUringOwnerBufferGroup
	entry.UserData = encodeAdvancedUringOwnerUserData(session.id, side, advancedUringOwnerRecv)
	endpoint.readArmed = true
	advancedUringOwnerRearms.Add(1)
	return nil
}

func (loop *advancedUringOwnerLoop) cancelRecv(session *advancedUringOwnerSession, side int) error {
	endpoint := &session.endpoint[side]
	if !endpoint.readArmed || endpoint.cancelPending || session.closing {
		return nil
	}
	entry, err := loop.getSQE()
	if err != nil {
		return err
	}
	entry.PrepareCancel64(encodeAdvancedUringOwnerUserData(session.id, side, advancedUringOwnerRecv), 0)
	entry.UserData = encodeAdvancedUringOwnerUserData(session.id, side, advancedUringOwnerCancelRecv)
	endpoint.cancelPending = true
	return nil
}

func (loop *advancedUringOwnerLoop) submitSend(session *advancedUringOwnerSession, side int, payload []byte) error {
	endpoint := &session.endpoint[side]
	if endpoint.sendPending || endpoint.sendCompletion || session.closing {
		return errors.New("owner: advanced io_uring send state is busy")
	}
	if len(payload) == 0 {
		return nil
	}
	if len(payload) > advancedUringOwnerMaxWrite {
		return fmt.Errorf("owner: advanced io_uring write exceeds %d bytes", advancedUringOwnerMaxWrite)
	}
	endpoint.sendBuffer = append(endpoint.sendBuffer[:0], payload...)
	return loop.resubmitSend(session, side)
}

func (loop *advancedUringOwnerLoop) resubmitSend(session *advancedUringOwnerSession, side int) error {
	endpoint := &session.endpoint[side]
	if len(endpoint.sendBuffer) == 0 || endpoint.sendPending || session.closing {
		return nil
	}
	entry, err := loop.getSQE()
	if err != nil {
		return err
	}
	entry.PrepareSend(
		int(session.slots[side]),
		uintptr(unsafe.Pointer(&endpoint.sendBuffer[0])),
		uint32(len(endpoint.sendBuffer)),
		unix.MSG_NOSIGNAL,
	)
	entry.Flags |= giouring.SqeFixedFile
	entry.UserData = encodeAdvancedUringOwnerUserData(session.id, side, advancedUringOwnerSend)
	endpoint.sendPending = true
	return nil
}

func encodeAdvancedUringOwnerUserData(sessionID uint64, side int, operation uint64) uint64 {
	return sessionID<<advancedUringOwnerOperationBits | uint64(side&1)<<advancedUringOwnerSideShift | operation
}

func decodeAdvancedUringOwnerUserData(value uint64) (uint64, int, uint64) {
	return value >> advancedUringOwnerOperationBits, int((value >> advancedUringOwnerSideShift) & 1), value & 3
}

func roleForSide(side int) Role {
	if side == 0 {
		return Inbound
	}
	return Outbound
}

func (loop *advancedUringOwnerLoop) bufferPointer(buffer uint16) uintptr {
	return loop.bufferBase + uintptr(int(buffer)*advancedUringOwnerBufferSize)
}

func (loop *advancedUringOwnerLoop) bufferSlice(buffer uint16, offset, length int) []byte {
	start := loop.bufferOffset + int(buffer)*advancedUringOwnerBufferSize + offset
	return loop.bufferMemory[start : start+length]
}

func (loop *advancedUringOwnerLoop) recycleBuffer(buffer uint16) {
	loop.buffersHeld--
	loop.bufferRing.BufRingAdd(loop.bufferPointer(buffer), advancedUringOwnerBufferSize, buffer, loop.bufferMask, 0)
	loop.bufferRing.BufRingAdvance(1)
	loop.bufferEpoch++
	loop.probeEpoch = loop.bufferEpoch
	loop.probeUsed = false
	if loop.starvedCount > 0 && loop.rearmBudget < loop.bufferCount {
		loop.rearmBudget++
	}
}

func (loop *advancedUringOwnerLoop) claimCompletionBuffer(flags uint32) (uint16, bool) {
	if flags&giouring.CQEFBuffer == 0 {
		return 0, false
	}
	buffer := uint16(flags >> giouring.CQEBufferShift)
	loop.buffersHeld++
	return buffer, true
}

func (loop *advancedUringOwnerLoop) markRecvStarved(endpoint *advancedUringOwnerEndpoint) {
	if endpoint.readStarved {
		return
	}
	endpoint.readStarved = true
	loop.starvedCount++
	advancedUringOwnerStarvations.Add(1)
}

func (loop *advancedUringOwnerLoop) clearRecvStarved(endpoint *advancedUringOwnerEndpoint) {
	if !endpoint.readStarved {
		return
	}
	endpoint.readStarved = false
	loop.starvedCount--
}

func (loop *advancedUringOwnerLoop) rearmStarvedRecvs() {
	if loop.starvedCount == 0 || loop.rearmBudget == 0 {
		return
	}
	endpointCount := (len(loop.sessions) - 1) * 2
	maxRearms := loop.rearmBudget * advancedUringOwnerStarvedFanout
	if maxRearms > endpointCount {
		maxRearms = endpointCount
	}
	rearmed := 0
	for checked := 0; checked < endpointCount && rearmed < maxRearms && loop.starvedCount > 0; checked++ {
		index := int(loop.starvedCursor % uint32(endpointCount))
		loop.starvedCursor = uint32((index + 1) % endpointCount)
		sessionID := index/2 + 1
		side := index & 1
		session := loop.sessions[sessionID]
		if session == nil || session.closed {
			continue
		}
		endpoint := &session.endpoint[side]
		if !endpoint.readStarved {
			continue
		}
		if session.closing || endpoint.readPaused || endpoint.cancelPending || endpoint.readArmed || endpoint.readEOF {
			continue
		}
		loop.clearRecvStarved(endpoint)
		rearmed++
		if err := loop.submitRecv(session, side); err != nil {
			loop.beginClose(session, roleForSide(side), err)
		} else {
			advancedUringOwnerRecoveries.Add(1)
		}
	}
	usedCredits := (rearmed + advancedUringOwnerStarvedFanout - 1) / advancedUringOwnerStarvedFanout
	loop.rearmBudget -= usedCredits
	if loop.starvedCount == 0 {
		loop.rearmBudget = 0
	}
}

func (loop *advancedUringOwnerLoop) recycleCompletionBuffer(flags uint32) {
	if buffer, ok := loop.claimCompletionBuffer(flags); ok {
		loop.recycleBuffer(buffer)
	}
}

func (loop *advancedUringOwnerLoop) handleRecv(session *advancedUringOwnerSession, side int, result int32, flags uint32) {
	advancedUringOwnerRecvs.Add(1)
	endpoint := &session.endpoint[side]
	if flags&giouring.CQEFMore == 0 {
		endpoint.readArmed = false
	}
	if session.closing {
		loop.recycleCompletionBuffer(flags)
		loop.maybeCloseSession(session)
		return
	}
	if result > 0 {
		buffer, ok := loop.claimCompletionBuffer(flags)
		if !ok {
			loop.beginClose(session, roleForSide(side), errors.New("owner: recv completion omitted selected buffer"))
			return
		}
		endpoint.readQueue = append(endpoint.readQueue, advancedUringOwnerReadChunk{buffer: buffer, length: int(result)})
		endpoint.readBuffered += int(result)
		queuedChunks := len(endpoint.readRetired) + len(endpoint.readQueue) - endpoint.readHead
		if loop.buffersHeld > loop.bufferCount || endpoint.readBuffered > loop.bufferCount*advancedUringOwnerBufferSize || queuedChunks > loop.bufferCount {
			loop.beginClose(session, roleForSide(side), fmt.Errorf(
				"owner: provided recv buffer ownership invariant exceeded: bytes=%d chunks=%d held=%d pool=%d",
				endpoint.readBuffered,
				queuedChunks,
				loop.buffersHeld,
				loop.bufferCount,
			))
			return
		}
		if endpoint.readPaused {
			// A normal record pauses its source only until the paired async send
			// completes. Avoid cancelling and recreating a multishot recv for
			// that common microsecond-scale interval. If more data actually
			// arrives while paused, cancel then; the bounded queue remains the
			// hard memory/backpressure limit.
			if err := loop.cancelRecv(session, side); err != nil {
				loop.beginClose(session, roleForSide(side), err)
				return
			}
		} else {
			loop.settleRead(session, side)
		}
		if !endpoint.readArmed {
			if err := loop.submitRecv(session, side); err != nil {
				loop.beginClose(session, roleForSide(side), err)
			}
		}
		return
	}
	loop.recycleCompletionBuffer(flags)
	if result == 0 {
		endpoint.readEOF = true
		loop.settleRead(session, side)
		return
	}
	errno := unix.Errno(-result)
	if errors.Is(errno, unix.ECANCELED) {
		if !endpoint.readPaused && !endpoint.cancelPending {
			if err := loop.submitRecv(session, side); err != nil {
				loop.beginClose(session, roleForSide(side), err)
			}
		}
		return
	}
	if errors.Is(errno, unix.EAGAIN) || errors.Is(errno, unix.EINTR) {
		if err := loop.submitRecv(session, side); err != nil {
			loop.beginClose(session, roleForSide(side), err)
		}
		return
	}
	if errors.Is(errno, unix.ENOBUFS) {
		loop.markRecvStarved(endpoint)
		// A terminal ENOBUFS completion can be observed after earlier CQEs in
		// the same batch have already returned buffers. When userspace owns
		// fewer buffers than the fixed pool, permit one probe for this recycle
		// epoch. A failed probe cannot spin; another attempt requires a real
		// buffer return, which advances bufferEpoch and creates one credit.
		if loop.buffersHeld < loop.bufferCount && (loop.probeEpoch != loop.bufferEpoch || !loop.probeUsed) {
			loop.probeEpoch = loop.bufferEpoch
			loop.probeUsed = true
			if loop.rearmBudget == 0 {
				loop.rearmBudget = 1
			}
		}
		return
	}
	loop.beginClose(session, roleForSide(side), os.NewSyscallError("io_uring recv", errno))
}

func (loop *advancedUringOwnerLoop) handleRecvCancel(session *advancedUringOwnerSession, side int, result int32) {
	advancedUringOwnerCancels.Add(1)
	endpoint := &session.endpoint[side]
	endpoint.cancelPending = false
	if result < 0 {
		errno := unix.Errno(-result)
		if !errors.Is(errno, unix.ENOENT) && !errors.Is(errno, unix.EALREADY) && !errors.Is(errno, unix.ECANCELED) {
			loop.beginClose(session, roleForSide(side), os.NewSyscallError("io_uring cancel recv", errno))
			return
		}
	}
	if !endpoint.readPaused && !endpoint.readArmed && !endpoint.readStarved && !endpoint.readEOF {
		if err := loop.submitRecv(session, side); err != nil {
			loop.beginClose(session, roleForSide(side), err)
		}
	}
	if !endpoint.readPaused {
		loop.settleRead(session, side)
	}
}

func (loop *advancedUringOwnerLoop) handleSend(session *advancedUringOwnerSession, side int, result int32) {
	advancedUringOwnerSends.Add(1)
	endpoint := &session.endpoint[side]
	if !endpoint.sendPending {
		loop.beginClose(session, roleForSide(side), errors.New("owner: unexpected send completion"))
		return
	}
	endpoint.sendPending = false
	if session.closing {
		endpoint.sendBuffer = endpoint.sendBuffer[:0]
		loop.maybeCloseSession(session)
		return
	}
	if result < 0 {
		errno := unix.Errno(-result)
		if errors.Is(errno, unix.EAGAIN) || errors.Is(errno, unix.EINTR) {
			if err := loop.resubmitSend(session, side); err != nil {
				loop.beginClose(session, roleForSide(side), err)
			}
			return
		}
		endpoint.sendCompletion = true
		endpoint.sendN = 0
		endpoint.sendErr = os.NewSyscallError("io_uring send", errno)
	} else if result == 0 {
		endpoint.sendCompletion = true
		endpoint.sendN = 0
		endpoint.sendErr = io.ErrUnexpectedEOF
	} else if int(result) > len(endpoint.sendBuffer) {
		loop.beginClose(session, roleForSide(side), errors.New("owner: send completion exceeded submitted length"))
		return
	} else {
		endpoint.sendCompletion = true
		endpoint.sendN = int(result)
		endpoint.sendErr = nil
	}
	loop.invokeWritable(session, side)
	if !session.closing {
		loop.maybeShutdownWrites(session)
	}
}

func (loop *advancedUringOwnerLoop) invokeTraffic(session *advancedUringOwnerSession, side int) {
	if session.closing || session.closed {
		return
	}
	endpoint := &session.endpoint[side]
	action := session.handler.OnTraffic(roleForSide(side), endpoint.conn)
	loop.trimReadScratch(endpoint)
	loop.recycleRetired(endpoint)
	if action == Close {
		loop.beginClose(session, roleForSide(side), nil)
	}
}

func (loop *advancedUringOwnerLoop) invokeWritable(session *advancedUringOwnerSession, side int) {
	if session.closing || session.closed {
		return
	}
	action := session.handler.OnWritable(roleForSide(side), session.endpoint[side].conn)
	if action == Close {
		loop.beginClose(session, roleForSide(side), nil)
	}
}

func (loop *advancedUringOwnerLoop) settleRead(session *advancedUringOwnerSession, side int) {
	if session.closing || session.closed {
		return
	}
	endpoint := &session.endpoint[side]
	if !endpoint.readPaused && endpoint.readBuffered > 0 {
		loop.invokeTraffic(session, side)
		if session.closing {
			return
		}
	}
	if endpoint.readEOF && !endpoint.readPaused && !endpoint.readNotified {
		endpoint.readNotified = true
		action := session.handler.OnReadClosed(roleForSide(side), endpoint.conn)
		loop.trimReadScratch(endpoint)
		loop.recycleRetired(endpoint)
		if action == Close {
			loop.beginClose(session, roleForSide(side), io.EOF)
			return
		}
	}
	loop.maybeShutdownWrites(session)
}

func (loop *advancedUringOwnerLoop) trimReadScratch(endpoint *advancedUringOwnerEndpoint) {
	if cap(endpoint.readScratch) > advancedUringOwnerRetainReadBytes {
		endpoint.readScratch = nil
	}
}

func (loop *advancedUringOwnerLoop) maybeShutdownWrites(session *advancedUringOwnerSession) {
	if session.closing || session.closed {
		return
	}
	for readSide := range session.endpoint {
		reader := &session.endpoint[readSide]
		writeSide := 1 - readSide
		writer := &session.endpoint[writeSide]
		if (!reader.readNotified && !writer.writeShutdownRequested) || writer.writeShutdown || writer.sendPending || writer.sendCompletion {
			continue
		}
		writer.writeShutdown = true
		writer.writeShutdownRequested = false
		_ = unix.Shutdown(session.fds[writeSide], unix.SHUT_WR)
	}
}

func (loop *advancedUringOwnerLoop) recycleRetired(endpoint *advancedUringOwnerEndpoint) {
	for _, buffer := range endpoint.readRetired {
		loop.recycleBuffer(buffer)
	}
	if cap(endpoint.readRetired) > advancedUringOwnerRetainReadChunks {
		endpoint.readRetired = nil
	} else {
		endpoint.readRetired = endpoint.readRetired[:0]
	}
	if endpoint.readHead == len(endpoint.readQueue) {
		if cap(endpoint.readQueue) > advancedUringOwnerRetainReadChunks {
			endpoint.readQueue = nil
		} else {
			endpoint.readQueue = endpoint.readQueue[:0]
		}
		endpoint.readHead = 0
	} else if endpoint.readHead >= 32 && endpoint.readHead*2 >= len(endpoint.readQueue) {
		copy(endpoint.readQueue, endpoint.readQueue[endpoint.readHead:])
		endpoint.readQueue = endpoint.readQueue[:len(endpoint.readQueue)-endpoint.readHead]
		endpoint.readHead = 0
	}
}

func (loop *advancedUringOwnerLoop) recycleReadQueue(endpoint *advancedUringOwnerEndpoint) {
	loop.recycleRetired(endpoint)
	for endpoint.readHead < len(endpoint.readQueue) {
		loop.recycleBuffer(endpoint.readQueue[endpoint.readHead].buffer)
		endpoint.readHead++
	}
	if cap(endpoint.readQueue) > advancedUringOwnerRetainReadChunks {
		endpoint.readQueue = nil
	} else {
		endpoint.readQueue = endpoint.readQueue[:0]
	}
	endpoint.readHead = 0
	endpoint.readBuffered = 0
}

func (loop *advancedUringOwnerLoop) beginClose(session *advancedUringOwnerSession, role Role, err error) {
	if session.closed {
		return
	}
	if !session.closeNotified {
		reason := "requested"
		if err != nil {
			reason = err.Error()
		}
		advancedUringOwnerCloses.Add(reason, 1)
		session.closeNotified = true
		session.handler.OnClose(role, session.endpoint[int(role)-1].conn, err)
	}
	if session.closing {
		return
	}
	session.closing = true
	_ = unix.Shutdown(session.fds[0], unix.SHUT_RDWR)
	_ = unix.Shutdown(session.fds[1], unix.SHUT_RDWR)
	for side := range session.endpoint {
		loop.clearRecvStarved(&session.endpoint[side])
		loop.recycleReadQueue(&session.endpoint[side])
	}
	loop.maybeCloseSession(session)
}

func (loop *advancedUringOwnerLoop) maybeCloseSession(session *advancedUringOwnerSession) {
	if session.closed || !session.closing {
		return
	}
	for side := range session.endpoint {
		endpoint := &session.endpoint[side]
		if endpoint.readArmed || endpoint.cancelPending || endpoint.sendPending {
			return
		}
	}
	loop.forceCloseSession(session, Inbound, nil)
}

func (loop *advancedUringOwnerLoop) forceCloseSession(session *advancedUringOwnerSession, role Role, err error) {
	if session.closed {
		return
	}
	if !session.closeNotified {
		session.closeNotified = true
		session.handler.OnClose(role, session.endpoint[int(role)-1].conn, err)
	}
	session.closing = true
	session.closed = true
	for side := range session.endpoint {
		loop.clearRecvStarved(&session.endpoint[side])
		loop.recycleReadQueue(&session.endpoint[side])
		_, _ = loop.ring.RegisterFilesUpdate(uint(session.slots[side]), []int{-1})
		_ = unix.Close(session.fds[side])
	}
	if session.id < uint64(len(loop.sessions)) && loop.sessions[session.id] == session {
		loop.sessions[session.id] = nil
		loop.freeIDs = append(loop.freeIDs, uint32(session.id))
	}
}

func (loop *advancedUringOwnerLoop) storeError(err error) {
	if err == nil {
		return
	}
	advancedUringOwnerLoopErrors.Add(err.Error(), 1)
	errCopy := err
	loop.err.CompareAndSwap(nil, &errCopy)
}

func (conn *advancedUringOwnerConn) state() *advancedUringOwnerEndpoint {
	return &conn.session.endpoint[conn.side]
}

func (conn *advancedUringOwnerConn) Write(payload []byte) (int, error) {
	return conn.TryWrite(payload)
}

func (conn *advancedUringOwnerConn) TryWrite(payload []byte) (int, error) {
	if conn.session.closing || conn.session.closed {
		return 0, net.ErrClosed
	}
	endpoint := conn.state()
	if endpoint.sendCompletion {
		written, completionErr := endpoint.sendN, endpoint.sendErr
		endpoint.sendCompletion = false
		endpoint.sendN = 0
		endpoint.sendErr = nil
		if written > len(payload) {
			return 0, errors.New("owner: async completion exceeds pending payload")
		}
		endpoint.sendBuffer = endpoint.sendBuffer[:0]
		if completionErr == nil && written < len(payload) {
			if err := conn.loop.submitSend(conn.session, conn.side, payload[written:]); err != nil {
				return written, err
			}
		}
		return written, completionErr
	}
	if endpoint.sendPending {
		return 0, nil
	}
	if len(payload) == 0 {
		return 0, nil
	}
	if err := conn.loop.submitSend(conn.session, conn.side, payload); err != nil {
		return 0, err
	}
	return 0, nil
}

func (conn *advancedUringOwnerConn) Next(length int) ([]byte, error) {
	endpoint := conn.state()
	if length <= 0 {
		length = endpoint.readBuffered
	}
	if length > endpoint.readBuffered {
		return nil, io.ErrShortBuffer
	}
	if length == 0 {
		return nil, nil
	}
	first := &endpoint.readQueue[endpoint.readHead]
	available := first.length - first.offset
	if available >= length {
		result := conn.loop.bufferSlice(first.buffer, first.offset, length)
		conn.consumeRead(length)
		return result, nil
	}
	if cap(endpoint.readScratch) < length {
		endpoint.readScratch = make([]byte, length)
	} else {
		endpoint.readScratch = endpoint.readScratch[:length]
	}
	written := 0
	remaining := length
	for remaining > 0 {
		chunk := &endpoint.readQueue[endpoint.readHead]
		available := chunk.length - chunk.offset
		copyLength := available
		if copyLength > remaining {
			copyLength = remaining
		}
		copy(endpoint.readScratch[written:written+copyLength], conn.loop.bufferSlice(chunk.buffer, chunk.offset, copyLength))
		conn.consumeRead(copyLength)
		written += copyLength
		remaining -= copyLength
	}
	return endpoint.readScratch, nil
}

func (conn *advancedUringOwnerConn) consumeRead(length int) {
	endpoint := conn.state()
	remaining := length
	for remaining > 0 && endpoint.readHead < len(endpoint.readQueue) {
		chunk := &endpoint.readQueue[endpoint.readHead]
		available := chunk.length - chunk.offset
		consumed := available
		if consumed > remaining {
			consumed = remaining
		}
		chunk.offset += consumed
		endpoint.readBuffered -= consumed
		remaining -= consumed
		if chunk.offset == chunk.length {
			endpoint.readRetired = append(endpoint.readRetired, chunk.buffer)
			endpoint.readHead++
		}
	}
}

func (conn *advancedUringOwnerConn) Discard(length int) (int, error) {
	endpoint := conn.state()
	if length <= 0 || length > endpoint.readBuffered {
		length = endpoint.readBuffered
	}
	conn.consumeRead(length)
	return length, nil
}

func (conn *advancedUringOwnerConn) InboundBuffered() int {
	buffered := conn.state().readBuffered
	if buffered > advancedUringOwnerBufferSize {
		return advancedUringOwnerBufferSize
	}
	return buffered
}

func (conn *advancedUringOwnerConn) SuspendRead() error {
	if conn.session.closing || conn.session.closed {
		return net.ErrClosed
	}
	endpoint := conn.state()
	if endpoint.readPaused {
		return nil
	}
	endpoint.readPaused = true
	return nil
}

func (conn *advancedUringOwnerConn) ResumeRead() error {
	if conn.session.closing || conn.session.closed {
		return net.ErrClosed
	}
	endpoint := conn.state()
	if !endpoint.readPaused {
		return nil
	}
	endpoint.readPaused = false
	if !endpoint.cancelPending && !endpoint.readArmed && !endpoint.readEOF {
		if err := conn.loop.submitRecv(conn.session, conn.side); err != nil {
			return err
		}
	}
	// Protocol owner sessions call Wake(nil) immediately after ResumeRead so
	// gnet revisits bytes already held in its userspace input buffer. A
	// successfully rearmed io_uring recv will revisit the socket without an
	// eventfd task. Mark only that immediate wake as redundant. The atomic
	// handoff keeps a concurrent limiter-timer wake from being lost.
	endpoint.resumeWakeNoop.Store(endpoint.readBuffered == 0 && endpoint.readArmed && !endpoint.cancelPending && !endpoint.readEOF)
	return nil
}

func (conn *advancedUringOwnerConn) ArmWrite() error {
	if conn.session.closing || conn.session.closed {
		return net.ErrClosed
	}
	conn.state().writeArmed = true
	return nil
}

func (conn *advancedUringOwnerConn) DisarmWrite() error {
	if conn.session.closing || conn.session.closed {
		return net.ErrClosed
	}
	conn.state().writeArmed = false
	return nil
}

func (conn *advancedUringOwnerConn) ShutdownWrite() error {
	if conn.session.closing || conn.session.closed {
		return net.ErrClosed
	}
	endpoint := conn.state()
	if endpoint.writeShutdown {
		return nil
	}
	endpoint.writeShutdownRequested = true
	conn.loop.maybeShutdownWrites(conn.session)
	return nil
}

func (conn *advancedUringOwnerConn) Wake(callback gnet.AsyncCallback) error {
	if conn.loop.stopping.Load() {
		return net.ErrClosed
	}
	resumeWakeNoop := conn.state().resumeWakeNoop.Swap(false)
	if callback == nil && resumeWakeNoop {
		advancedUringOwnerSkippedWakes.Add(1)
		return nil
	}
	task := advancedUringOwnerTask{kind: advancedUringOwnerTaskWake, conn: conn, callback: callback}
	select {
	case conn.loop.tasks <- task:
		return conn.loop.wake()
	case <-conn.loop.done:
		return conn.loop.failure()
	default:
		return errors.New("owner: advanced io_uring task queue is full")
	}
}

func (conn *advancedUringOwnerConn) Close() error {
	if conn.loop.stopping.Load() {
		return nil
	}
	task := advancedUringOwnerTask{kind: advancedUringOwnerTaskClose, conn: conn}
	select {
	case conn.loop.tasks <- task:
		return conn.loop.wake()
	case <-conn.loop.done:
		return nil
	default:
		return errors.New("owner: advanced io_uring task queue is full")
	}
}

var _ Conn = (*advancedUringOwnerConn)(nil)
