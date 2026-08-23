use crate::accounting::complete_record_write;
use crate::diagnostics::{connection_error, ErrorScope};
use crate::netaddr::{
    peer_ip, resolve_target, socket_address, socket_domain, RawSocketAddress, ResolvedTarget,
};
use crate::sniff::{Decision as SniffDecision, State as SniffState};
use crate::timeout::{TcpTimeoutState, TcpTimeouts};
use io_uring::{opcode, squeue, types, IoUring};
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use shadowsocks_crypto::{
    kind::CipherKind,
    utils::random_iv_or_salt,
    v1::{openssl_bytes_to_key, Cipher},
};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque},
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr,
    time::{Duration, Instant},
};

const KIND: CipherKind = CipherKind::AES_128_GCM;
const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
const LENGTH_PACKET_LEN: usize = 2 + TAG_LEN;
const MAX_PAYLOAD_LEN: usize = 0x3fff;
// One maximum classic AEAD record plus framing, with enough headroom for a
// partially received following record. Keeping this connection-local working
// set small matters with thousands of idle credentials/connections.
const INPUT_CAPACITY: usize = 20 * 1024;
// Sniffing follows the legacy dispatcher contract and may retain two maximum
// AEAD records before deciding whether HTTP Host/TLS SNI overrides the target.
const UPLOAD_CAPACITY: usize = 36 * 1024;
const DOWNLOAD_PLAINTEXT_CAPACITY: usize = 8 * 1024;
const DOWNLOAD_CIPHERTEXT_CAPACITY: usize =
    SALT_LEN + LENGTH_PACKET_LEN + DOWNLOAD_PLAINTEXT_CAPACITY + TAG_LEN;
const LIMITER_RESERVATION: usize = 64 * 1024;
const UDP_PACKET_CAPACITY: usize = 65_535;
const UDP_MIN_HEADER_LEN: usize = 4;
const UDP_IPV4_HEADER_LEN: usize = 7;
const UDP_IPV6_HEADER_LEN: usize = 19;
const UDP_MAX_HEADER_LEN: usize = UDP_IPV6_HEADER_LEN;
const UDP_RESPONSE_HEADROOM: usize = SALT_LEN + UDP_MAX_HEADER_LEN;
const UDP_TARGET_PAYLOAD_CAPACITY: usize = UDP_PACKET_CAPACITY - UDP_RESPONSE_HEADROOM - TAG_LEN;
const MAX_UDP_ASSOCIATIONS: usize = 4096;
const MAX_UDP_QUEUE_PER_ASSOCIATION: usize = 64;
const MAX_UDP_QUEUED_BYTES: usize = 64 * 1024 * 1024;
const UDP_RECEIVE_BUFFER_BYTES: libc::c_int = 4 * 1024 * 1024;

const MAX_CONNECTIONS: usize = 4096;
const ENGINE_TAG: u64 = 1 << 63;

const OP_ACCEPT: u8 = 1;
const OP_CONNECT: u8 = 2;
const OP_RECV_INBOUND: u8 = 3;
const OP_SEND_OUTBOUND: u8 = 4;
const OP_RECV_OUTBOUND: u8 = 5;
const OP_SEND_INBOUND: u8 = 6;
const OP_RECV_UDP_INBOUND: u8 = 16;
const OP_SEND_UDP_OUTBOUND: u8 = 17;
const OP_RECV_UDP_OUTBOUND: u8 = 18;
const OP_SEND_UDP_INBOUND: u8 = 19;
const OP_CANCEL_UDP_RECV: u8 = 20;
const TIMER_UPLOAD: u8 = 1;
const TIMER_DOWNLOAD: u8 = 2;
const TIMER_UDP_UPLOAD: u8 = 1;
const TIMER_UDP_DOWNLOAD: u8 = 2;
const TIMER_UDP_EXPIRE: u8 = 3;

#[derive(Clone, Copy)]
struct Features {
    traffic: bool,
    limiter: bool,
    device: bool,
    rule: bool,
}

impl Features {
    fn parse(value: &str) -> Self {
        match value {
            "none" => Self {
                traffic: false,
                limiter: false,
                device: false,
                rule: false,
            },
            "traffic" => Self {
                traffic: true,
                limiter: false,
                device: false,
                rule: false,
            },
            "traffic-limiter" => Self {
                traffic: true,
                limiter: true,
                device: false,
                rule: false,
            },
            "traffic-limiter-device" => Self {
                traffic: true,
                limiter: true,
                device: true,
                rule: false,
            },
            "full" => Self {
                traffic: true,
                limiter: true,
                device: true,
                rule: true,
            },
            _ => panic!("--features 值无效"),
        }
    }
}

struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(bytes_per_second: u64) -> Self {
        let rate = bytes_per_second as f64;
        let burst = rate.max(1.0);
        Self {
            rate,
            burst,
            tokens: burst,
            last: Instant::now(),
        }
    }

    fn reserve(&mut self, count: usize) -> Option<Duration> {
        if self.rate <= 0.0 || count == 0 {
            return None;
        }
        let now = Instant::now();
        if now > self.last {
            self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate)
                .min(self.burst);
            self.last = now;
        }
        let count = count as f64;
        if self.tokens >= count {
            self.tokens -= count;
            return None;
        }
        let wait = self.last.saturating_duration_since(now)
            + Duration::from_secs_f64((count - self.tokens) / self.rate);
        self.tokens = 0.0;
        self.last = now + wait;
        Some(wait)
    }

    fn reservation(&self) -> usize {
        (self.burst as usize).clamp(1, LIMITER_RESERVATION)
    }

    fn update_rate(&mut self, bytes_per_second: u64) {
        *self = Self::new(bytes_per_second);
    }
}

struct UserRuntime {
    uid: u64,
    key: [u8; 16],
    upload: u64,
    download: u64,
    active: u32,
    limiter: TokenBucket,
    device_ips: HashMap<IpAddr, u32>,
    state: UserSlotState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserSlotState {
    Live,
    Retired,
    Free,
}

#[derive(Deserialize)]
pub struct NormalizedUser {
    pub uid: u64,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrafficRecord {
    pub uid: u64,
    pub upload: u64,
    pub download: u64,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct ReplayKey {
    credential: [u8; 16],
    salt: [u8; SALT_LEN],
}

struct ReplayFilter {
    current: HashSet<ReplayKey>,
    previous: HashSet<ReplayKey>,
    rotated_at: Instant,
    window: Duration,
    capacity: usize,
}

impl ReplayFilter {
    fn new(capacity: usize, window: Duration) -> Self {
        Self {
            current: HashSet::new(),
            previous: HashSet::new(),
            rotated_at: Instant::now(),
            window,
            capacity,
        }
    }

    fn check_and_add(&mut self, credential: [u8; 16], salt: [u8; SALT_LEN]) -> bool {
        self.check_and_add_at(credential, salt, Instant::now())
    }

    fn check_and_add_at(
        &mut self,
        credential: [u8; 16],
        salt: [u8; SALT_LEN],
        now: Instant,
    ) -> bool {
        let elapsed = now.duration_since(self.rotated_at);
        if elapsed >= self.window {
            if elapsed >= self.window.saturating_mul(2) {
                self.previous.clear();
            } else {
                self.previous = mem::take(&mut self.current);
            }
            self.current.clear();
            self.rotated_at = now;
        }
        let key = ReplayKey { credential, salt };
        if self.current.contains(&key) || self.previous.contains(&key) {
            return true;
        }
        if self.current.len() >= self.capacity {
            return true;
        }
        self.current.insert(key);
        false
    }

    fn generate_unique_salt(&mut self, credential: [u8; 16]) -> io::Result<[u8; SALT_LEN]> {
        const ATTEMPTS: usize = 8;
        for _ in 0..ATTEMPTS {
            let mut salt = [0u8; SALT_LEN];
            random_iv_or_salt(&mut salt);
            if !self.check_and_add(credential, salt) {
                return Ok(salt);
            }
        }
        Err(io::Error::other("SS outgoing salt replay set is saturated"))
    }
}

struct SiteState {
    users: Vec<UserRuntime>,
    live_users: Vec<usize>,
    free_users: Vec<usize>,
    pending_traffic: HashMap<u64, (u64, u64)>,
    speed_bytes_per_second: u64,
    device_limit: usize,
    replay: ReplayFilter,
    blocked_hosts: HashSet<String>,
    rules: Option<RegexSet>,
    replay_rejects: u64,
    device_rejects: u64,
    rule_rejects: u64,
    sniffing: bool,
}

struct Connection {
    _inbound: OwnedFd,
    outbound: Option<OwnedFd>,
    inbound_slot: u32,
    outbound_slot: u32,
    target: Option<Box<RawSocketAddress>>,
    pending_target: Option<ResolvedTarget>,
    sniff: SniffState,
    site: usize,
    peer_ip: IpAddr,
    input: Box<[u8; INPUT_CAPACITY]>,
    input_start: usize,
    input_length: usize,
    decryptor: Option<Cipher>,
    expected_payload: Option<usize>,
    pending_salt: Option<[u8; SALT_LEN]>,
    user: Option<usize>,
    header_complete: bool,
    upload: Box<[u8; UPLOAD_CAPACITY]>,
    upload_direct_start: Option<usize>,
    upload_length: usize,
    upload_offset: usize,
    upload_budget: usize,
    download_ciphertext: Box<[u8; DOWNLOAD_CIPHERTEXT_CAPACITY]>,
    download_payload_offset: usize,
    download_length: usize,
    download_offset: usize,
    download_plaintext_length: usize,
    download_budget: usize,
    upload_ready_at: Option<Instant>,
    upload_scheduled_at: Option<Instant>,
    download_ready_at: Option<Instant>,
    download_scheduled_at: Option<Instant>,
    encryptor: Option<Cipher>,
    connected: bool,
    connecting: bool,
    device_admitted: bool,
    inbound_read_eof: bool,
    outbound_read_eof: bool,
    outbound_write_shutdown: bool,
    inbound_write_shutdown: bool,
    inflight: usize,
    closing: bool,
    failed: bool,
    generation: u64,
    timeout: TcpTimeoutState,
}

struct UdpListenerState {
    socket: UdpSocket,
    buffer: Box<[u8; UDP_PACKET_CAPACITY]>,
    source: Box<libc::sockaddr_storage>,
    iovec: Box<libc::iovec>,
    message: Box<libc::msghdr>,
    armed: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpAssociationKey {
    site: usize,
    client: SocketAddr,
    target: SocketAddr,
}

struct UdpAssociation {
    outbound: OwnedFd,
    key: UdpAssociationKey,
    user: usize,
    peer_ip: IpAddr,
    device_admitted: bool,
    current_upload: Option<Box<[u8]>>,
    upload_queue: VecDeque<Box<[u8]>>,
    upload_budget: usize,
    upload_ready_at: Option<Instant>,
    upload_inflight: bool,
    response: Box<[u8; UDP_PACKET_CAPACITY]>,
    response_length: usize,
    response_plaintext_length: usize,
    download_budget: usize,
    download_ready_at: Option<Instant>,
    response_inflight: bool,
    client_address: Box<RawSocketAddress>,
    response_iovec: Box<libc::iovec>,
    response_message: Box<libc::msghdr>,
    recv_inflight: bool,
    inflight: usize,
    closing: bool,
    cancel_queued: bool,
    expires_at: Instant,
    generation: u64,
}

macro_rules! queue_connection {
    ($state:expr, $pending:expr, $entry:expr) => {{
        let entry = $entry;
        ($state).inflight += 1;
        ($pending).push(entry);
    }};
}

impl Connection {
    fn compact_input(&mut self) {
        if self.input_start == self.input_length {
            self.input_start = 0;
            self.input_length = 0;
        } else if self.input_start != 0 {
            self.input
                .copy_within(self.input_start..self.input_length, 0);
            self.input_length -= self.input_start;
            self.input_start = 0;
        }
    }
}

fn tag(connection: usize, operation: u8) -> u64 {
    ENGINE_TAG | ((connection as u64) << 8) | operation as u64
}

fn decode_tag(value: u64) -> (usize, u8) {
    (((value & !ENGINE_TAG) >> 8) as usize, value as u8)
}

pub fn owns(value: u64) -> bool {
    value & ENGINE_TAG != 0
}

fn set_nodelay(descriptor: RawFd, enabled: bool) -> io::Result<()> {
    let enabled: libc::c_int = i32::from(enabled);
    let result = unsafe {
        libc::setsockopt(
            descriptor,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            (&enabled as *const libc::c_int).cast(),
            mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn tcp_socket(tcp_nodelay: bool, address: SocketAddr) -> io::Result<OwnedFd> {
    let descriptor = unsafe {
        libc::socket(
            socket_domain(address),
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    set_nodelay(descriptor.as_raw_fd(), tcp_nodelay)?;
    Ok(descriptor)
}

fn connected_udp_socket(target: SocketAddr) -> io::Result<OwnedFd> {
    let descriptor = unsafe {
        libc::socket(
            socket_domain(target),
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let target = RawSocketAddress::new(target);
    let result = unsafe { libc::connect(descriptor.as_raw_fd(), target.as_ptr(), target.len()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(descriptor)
}

fn tune_udp_receive_buffer(descriptor: RawFd) {
    let requested = UDP_RECEIVE_BUFFER_BYTES;
    let pointer = (&requested as *const libc::c_int).cast();
    let length = mem::size_of_val(&requested) as libc::socklen_t;
    unsafe {
        // SO_RCVBUF is portable but capped by net.core.rmem_max. oldxr is
        // normally started as root, so Linux can honor the same bounded size
        // with SO_RCVBUFFORCE without requiring a global sysctl mutation.
        libc::setsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            pointer,
            length,
        );
        libc::setsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            pointer,
            length,
        );
    }
}

impl UdpListenerState {
    fn bind(address: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(address)?;
        socket.set_nonblocking(true)?;
        tune_udp_receive_buffer(socket.as_raw_fd());
        let mut state = Self {
            socket,
            buffer: Box::new([0; UDP_PACKET_CAPACITY]),
            source: Box::new(unsafe { mem::zeroed() }),
            iovec: Box::new(unsafe { mem::zeroed() }),
            message: Box::new(unsafe { mem::zeroed() }),
            armed: false,
        };
        state.reset_message();
        Ok(state)
    }

    fn reset_message(&mut self) {
        *self.source = unsafe { mem::zeroed() };
        self.iovec.iov_base = self.buffer.as_mut_ptr().cast();
        self.iovec.iov_len = self.buffer.len();
        self.message.msg_name = (&mut *self.source as *mut libc::sockaddr_storage).cast();
        self.message.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        self.message.msg_iov = &mut *self.iovec;
        self.message.msg_iovlen = 1;
        self.message.msg_control = ptr::null_mut();
        self.message.msg_controllen = 0;
        self.message.msg_flags = 0;
    }
}

impl UdpAssociation {
    fn new(
        key: UdpAssociationKey,
        user: usize,
        peer_ip: IpAddr,
        device_admitted: bool,
        generation: u64,
        idle_timeout: Duration,
    ) -> io::Result<Self> {
        let outbound = connected_udp_socket(key.target)?;
        let mut state = Self {
            outbound,
            key,
            user,
            peer_ip,
            device_admitted,
            current_upload: None,
            upload_queue: VecDeque::new(),
            upload_budget: 0,
            upload_ready_at: None,
            upload_inflight: false,
            response: Box::new([0; UDP_PACKET_CAPACITY]),
            response_length: 0,
            response_plaintext_length: 0,
            download_budget: 0,
            download_ready_at: None,
            response_inflight: false,
            client_address: Box::new(RawSocketAddress::new(key.client)),
            response_iovec: Box::new(unsafe { mem::zeroed() }),
            response_message: Box::new(unsafe { mem::zeroed() }),
            recv_inflight: false,
            inflight: 0,
            closing: false,
            cancel_queued: false,
            expires_at: Instant::now() + idle_timeout,
            generation,
        };
        state.reset_response_message();
        Ok(state)
    }

    fn reset_response_message(&mut self) {
        self.response_iovec.iov_base = self.response.as_mut_ptr().cast();
        self.response_iovec.iov_len = self.response_length;
        self.response_message.msg_name = self.client_address.as_ptr().cast_mut().cast();
        self.response_message.msg_namelen = self.client_address.len();
        self.response_message.msg_iov = &mut *self.response_iovec;
        self.response_message.msg_iovlen = 1;
        self.response_message.msg_control = ptr::null_mut();
        self.response_message.msg_controllen = 0;
        self.response_message.msg_flags = 0;
    }
}

fn recv_udp_inbound_entry(site: usize, listener: &mut UdpListenerState) -> squeue::Entry {
    listener.reset_message();
    listener.armed = true;
    opcode::RecvMsg::new(
        types::Fd(listener.socket.as_raw_fd()),
        &mut *listener.message,
    )
    .ioprio(1)
    .build()
    .user_data(tag(site, OP_RECV_UDP_INBOUND))
}

fn send_udp_outbound_entry(identifier: usize, state: &mut UdpAssociation) -> squeue::Entry {
    let upload = state.current_upload.as_ref().expect("SS UDP upload");
    state.upload_inflight = true;
    opcode::Send::new(
        types::Fd(state.outbound.as_raw_fd()),
        upload.as_ptr(),
        upload.len() as u32,
    )
    .ioprio(1)
    .build()
    .user_data(tag(identifier, OP_SEND_UDP_OUTBOUND))
}

fn recv_udp_outbound_entry(identifier: usize, state: &mut UdpAssociation) -> squeue::Entry {
    state.recv_inflight = true;
    opcode::Recv::new(
        types::Fd(state.outbound.as_raw_fd()),
        unsafe { state.response.as_mut_ptr().add(UDP_RESPONSE_HEADROOM) },
        UDP_TARGET_PAYLOAD_CAPACITY as u32,
    )
    .ioprio(1)
    .build()
    .user_data(tag(identifier, OP_RECV_UDP_OUTBOUND))
}

fn send_udp_inbound_entry(
    identifier: usize,
    listener: &UdpListenerState,
    state: &mut UdpAssociation,
) -> squeue::Entry {
    state.reset_response_message();
    state.response_inflight = true;
    opcode::SendMsg::new(
        types::Fd(listener.socket.as_raw_fd()),
        &*state.response_message,
    )
    .ioprio(1)
    .build()
    .user_data(tag(identifier, OP_SEND_UDP_INBOUND))
}

fn cancel_udp_recv_entry(identifier: usize) -> squeue::Entry {
    opcode::AsyncCancel::new(tag(identifier, OP_RECV_UDP_OUTBOUND))
        .build()
        .user_data(tag(identifier, OP_CANCEL_UDP_RECV))
}

fn begin_udp_close(state: &mut UdpAssociation) {
    if !state.closing {
        state.closing = true;
        shutdown(state.outbound.as_raw_fd());
    }
}

fn accept_entry(listener: RawFd, site: usize) -> squeue::Entry {
    opcode::Accept::new(types::Fd(listener), ptr::null_mut(), ptr::null_mut())
        .flags(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC)
        .build()
        .user_data(tag(site, OP_ACCEPT))
}

fn connect_entry(connection: usize, state: &Connection) -> squeue::Entry {
    let target = state.target.as_ref().expect("connect target");
    opcode::Connect::new(
        types::Fixed(state.outbound_slot),
        target.as_ptr(),
        target.len(),
    )
    .build()
    .user_data(tag(connection, OP_CONNECT))
}

fn start_target_connect(
    connection: usize,
    state: &mut Connection,
    target: SocketAddr,
    tcp_nodelay: bool,
    ring: &mut IoUring,
    pending: &mut Vec<squeue::Entry>,
) -> io::Result<()> {
    let outbound = tcp_socket(tcp_nodelay, target)?;
    register_file(ring, state.outbound_slot, outbound.as_raw_fd())?;
    state.target = Some(Box::new(RawSocketAddress::new(target)));
    state.outbound = Some(outbound);
    state.connecting = true;
    queue_connection!(state, pending, connect_entry(connection, state));
    Ok(())
}

fn recv_inbound_entry(connection: usize, state: &mut Connection) -> io::Result<squeue::Entry> {
    state.compact_input();
    let remaining = INPUT_CAPACITY.saturating_sub(state.input_length);
    if remaining == 0 {
        return Err(io::Error::other("encrypted input buffer is full"));
    }
    Ok(opcode::Recv::new(
        types::Fixed(state.inbound_slot),
        unsafe { state.input.as_mut_ptr().add(state.input_length) },
        remaining as u32,
    )
    .ioprio(1)
    .build()
    .user_data(tag(connection, OP_RECV_INBOUND)))
}

fn send_outbound_entry(connection: usize, state: &Connection) -> squeue::Entry {
    let address = if let Some(start) = state.upload_direct_start {
        unsafe { state.input.as_ptr().add(start + state.upload_offset) }
    } else {
        unsafe { state.upload.as_ptr().add(state.upload_offset) }
    };
    opcode::Send::new(
        types::Fixed(state.outbound_slot),
        address,
        (state.upload_length - state.upload_offset) as u32,
    )
    .ioprio(1)
    .build()
    .user_data(tag(connection, OP_SEND_OUTBOUND))
}

fn recv_outbound_entry(connection: usize, state: &mut Connection) -> squeue::Entry {
    state.download_payload_offset = if state.encryptor.is_none() {
        SALT_LEN + LENGTH_PACKET_LEN
    } else {
        LENGTH_PACKET_LEN
    };
    opcode::Recv::new(
        types::Fixed(state.outbound_slot),
        unsafe {
            state
                .download_ciphertext
                .as_mut_ptr()
                .add(state.download_payload_offset)
        },
        DOWNLOAD_PLAINTEXT_CAPACITY as u32,
    )
    .ioprio(1)
    .build()
    .user_data(tag(connection, OP_RECV_OUTBOUND))
}

fn send_inbound_entry(connection: usize, state: &Connection) -> squeue::Entry {
    opcode::Send::new(
        types::Fixed(state.inbound_slot),
        unsafe {
            state
                .download_ciphertext
                .as_ptr()
                .add(state.download_offset)
        },
        (state.download_length - state.download_offset) as u32,
    )
    .ioprio(1)
    .build()
    .user_data(tag(connection, OP_SEND_INBOUND))
}

fn register_file(ring: &mut IoUring, slot: u32, descriptor: RawFd) -> io::Result<()> {
    ring.submitter()
        .register_files_update(slot, &[descriptor])
        .map(|_| ())
}

fn unregister_file(ring: &mut IoUring, slot: u32) -> io::Result<()> {
    register_file(ring, slot, -1)
}

fn shutdown(descriptor: RawFd) {
    unsafe {
        libc::shutdown(descriptor, libc::SHUT_RDWR);
    }
}

fn shutdown_write(descriptor: RawFd) {
    unsafe {
        libc::shutdown(descriptor, libc::SHUT_WR);
    }
}

fn finish_upload_half(state: &mut Connection) {
    if state.inbound_read_eof
        && state.connected
        && state.upload_length == 0
        && !state.outbound_write_shutdown
    {
        if let Some(outbound) = state.outbound.as_ref() {
            shutdown_write(outbound.as_raw_fd());
            state.outbound_write_shutdown = true;
        }
    }
}

fn finish_download_half(state: &mut Connection) {
    if state.outbound_read_eof && state.download_length == 0 && !state.inbound_write_shutdown {
        shutdown_write(state._inbound.as_raw_fd());
        state.inbound_write_shutdown = true;
    }
}

fn finish_graceful_close(state: &mut Connection) {
    if state.outbound_write_shutdown
        && state.inbound_write_shutdown
        && state.upload_length == 0
        && state.download_length == 0
    {
        begin_close(state);
    }
}

fn begin_close(state: &mut Connection) {
    if !state.closing {
        state.closing = true;
        shutdown(state._inbound.as_raw_fd());
        if let Some(outbound) = state.outbound.as_ref() {
            shutdown(outbound.as_raw_fd());
        }
    }
}

fn fail(state: &mut Connection, error: impl std::fmt::Display) {
    if !state.failed {
        connection_error(ErrorScope::FastSs, error);
    }
    state.failed = true;
    begin_close(state);
}

fn fail_io(state: &mut Connection, error: io::Error) {
    if matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    ) || error.raw_os_error() == Some(libc::ECANCELED)
    {
        begin_close(state);
    } else {
        fail(state, error);
    }
}

fn complete_while_closing(
    state: &mut Connection,
    operation: u8,
    result: i32,
    sites: &mut [SiteState],
    features: Features,
) {
    if result <= 0 {
        return;
    }
    match operation {
        OP_SEND_OUTBOUND => {
            let count = result as usize;
            state.upload_offset = (state.upload_offset + count).min(state.upload_length);
            if features.traffic {
                if let Some(user) = state.user {
                    sites[state.site].users[user].upload += count as u64;
                }
            }
        }
        OP_SEND_INBOUND => {
            let credited = complete_record_write(
                &mut state.download_offset,
                state.download_length,
                &mut state.download_plaintext_length,
                result as usize,
            );
            if credited != 0 && features.traffic {
                if let Some(user) = state.user {
                    sites[state.site].users[user].download += credited;
                }
            }
        }
        _ => {}
    }
}

fn user_runtime(uid: u64, key: [u8; 16], speed_bytes_per_second: u64) -> UserRuntime {
    UserRuntime {
        uid,
        key,
        upload: 0,
        download: 0,
        active: 0,
        limiter: TokenBucket::new(speed_bytes_per_second),
        device_ips: HashMap::new(),
        state: UserSlotState::Live,
    }
}

impl SiteState {
    fn new(
        speed_bytes_per_second: u64,
        blocked_host: &str,
        device_limit: usize,
        sniffing: bool,
    ) -> Self {
        let mut blocked_hosts = HashSet::new();
        if !blocked_host.is_empty() {
            blocked_hosts.insert(blocked_host.to_ascii_lowercase());
        }
        Self {
            users: Vec::new(),
            live_users: Vec::new(),
            free_users: Vec::new(),
            pending_traffic: HashMap::new(),
            speed_bytes_per_second,
            device_limit,
            replay: ReplayFilter::new(131_072, Duration::from_secs(600)),
            blocked_hosts,
            rules: None,
            replay_rejects: 0,
            device_rejects: 0,
            rule_rejects: 0,
            sniffing,
        }
    }

    fn update_policy(
        &mut self,
        speed_bytes_per_second: u64,
        device_limit: usize,
        rules: Vec<String>,
    ) -> io::Result<()> {
        if rules.len() > 4096 || rules.iter().any(|rule| rule.len() > 8192) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SS rule set exceeds the bounded size",
            ));
        }
        let compiled = if rules.is_empty() {
            None
        } else {
            Some(
                RegexSet::new(rules)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
            )
        };
        self.speed_bytes_per_second = speed_bytes_per_second;
        self.device_limit = device_limit;
        self.rules = compiled;
        for user in &mut self.users {
            if user.state != UserSlotState::Free {
                user.limiter.update_rate(speed_bytes_per_second);
            }
        }
        Ok(())
    }

    fn allocate_user(&mut self, uid: u64, key: [u8; 16]) -> usize {
        let user = user_runtime(uid, key, self.speed_bytes_per_second);
        if let Some(index) = self.free_users.pop() {
            self.users[index] = user;
            index
        } else {
            let index = self.users.len();
            self.users.push(user);
            index
        }
    }

    fn replace_users(&mut self, users: Vec<NormalizedUser>) -> io::Result<(usize, usize)> {
        let mut normalized = Vec::with_capacity(users.len());
        let mut seen_uids = HashSet::with_capacity(users.len());
        let mut seen_keys = HashSet::with_capacity(users.len());
        for user in users {
            if user.password.is_empty() || !seen_uids.insert(user.uid) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SS update has an empty password or duplicate UID",
                ));
            }
            let mut key = [0u8; 16];
            openssl_bytes_to_key(user.password.as_bytes(), &mut key);
            if !seen_keys.insert(key) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SS update has duplicate credentials",
                ));
            }
            normalized.push((user.uid, key));
        }

        let old_live = mem::take(&mut self.live_users);
        let old_by_uid: HashMap<u64, usize> = old_live
            .iter()
            .map(|&index| (self.users[index].uid, index))
            .collect();
        let mut reused = HashSet::with_capacity(normalized.len());
        let mut new_live = Vec::with_capacity(normalized.len());
        for (uid, key) in normalized {
            if let Some(&index) = old_by_uid.get(&uid) {
                if self.users[index].key == key {
                    reused.insert(index);
                    new_live.push(index);
                    continue;
                }
            }
            new_live.push(self.allocate_user(uid, key));
        }
        for index in old_live {
            if !reused.contains(&index) {
                self.users[index].state = UserSlotState::Retired;
            }
        }
        self.live_users = new_live;
        self.prune_retired();
        Ok((self.live_users.len(), self.retired_users()))
    }

    fn retired_users(&self) -> usize {
        self.users
            .iter()
            .filter(|user| user.state == UserSlotState::Retired)
            .count()
    }

    #[allow(dead_code)]
    fn take_traffic(&mut self) -> Vec<TrafficRecord> {
        let mut totals = BTreeMap::<u64, (u64, u64)>::new();
        for (uid, traffic) in self.pending_traffic.drain() {
            totals.insert(uid, traffic);
        }
        for user in &mut self.users {
            if user.state == UserSlotState::Free {
                continue;
            }
            let upload = mem::take(&mut user.upload);
            let download = mem::take(&mut user.download);
            if upload != 0 || download != 0 {
                let total = totals.entry(user.uid).or_default();
                total.0 = total.0.saturating_add(upload);
                total.1 = total.1.saturating_add(download);
            }
        }
        self.prune_retired();
        totals
            .into_iter()
            .map(|(uid, (upload, download))| TrafficRecord {
                uid,
                upload,
                download,
            })
            .collect()
    }

    #[allow(dead_code)]
    fn restore_traffic(&mut self, traffic: Vec<TrafficRecord>) {
        for record in traffic {
            let total = self.pending_traffic.entry(record.uid).or_default();
            total.0 = total.0.saturating_add(record.upload);
            total.1 = total.1.saturating_add(record.download);
        }
    }

    fn prune_retired(&mut self) {
        for (index, user) in self.users.iter_mut().enumerate() {
            if user.state != UserSlotState::Retired
                || user.active != 0
                || user.upload != 0
                || user.download != 0
            {
                continue;
            }
            user.uid = 0;
            user.key.fill(0);
            user.device_ips = HashMap::new();
            user.state = UserSlotState::Free;
            self.free_users.push(index);
        }
    }

    fn traffic_totals(&self) -> (u64, u64) {
        let mut upload = 0u64;
        let mut download = 0u64;
        for &(pending_upload, pending_download) in self.pending_traffic.values() {
            upload = upload.saturating_add(pending_upload);
            download = download.saturating_add(pending_download);
        }
        for user in &self.users {
            upload = upload.saturating_add(user.upload);
            download = download.saturating_add(user.download);
        }
        (upload, download)
    }
}

fn build_sites(
    sites: usize,
    sniffing: &[bool],
    users: usize,
    revision: usize,
    speed_bytes_per_second: u64,
    blocked_host: &str,
    device_limit: usize,
) -> Vec<SiteState> {
    (1..=sites)
        .map(|site| {
            let users = (1..=users)
                .map(|uid| NormalizedUser {
                    uid: uid as u64,
                    password: format!("ss-site-{site:02}-user-{uid:06}-r{revision}-phase4-secret"),
                })
                .collect();
            let mut state = SiteState::new(
                speed_bytes_per_second,
                blocked_host,
                device_limit,
                sniffing[site - 1],
            );
            state
                .replace_users(users)
                .expect("generated SS users must be valid");
            state
        })
        .collect()
}

fn parse_target(payload: &[u8]) -> io::Result<(SocketAddr, String, usize)> {
    let atyp = *payload
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty SS target"))?;
    match atyp {
        1 => {
            if payload.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated IPv4 target",
                ));
            }
            let address = Ipv4Addr::new(payload[1], payload[2], payload[3], payload[4]);
            let port = u16::from_be_bytes([payload[5], payload[6]]);
            Ok((
                SocketAddr::new(IpAddr::V4(address), port),
                address.to_string(),
                7,
            ))
        }
        3 => {
            let length = *payload.get(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "truncated domain target")
            })? as usize;
            let header_length = 2 + length + 2;
            if payload.len() < header_length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated domain target",
                ));
            }
            let host = std::str::from_utf8(&payload[2..2 + length])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid target name"))?;
            let port = u16::from_be_bytes([payload[2 + length], payload[3 + length]]);
            let address = resolve_target(host, port)?;
            Ok((address, host.to_owned(), header_length))
        }
        4 => {
            if payload.len() < UDP_IPV6_HEADER_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated IPv6 target",
                ));
            }
            let address = Ipv6Addr::from(<[u8; 16]>::try_from(&payload[1..17]).unwrap());
            let port = u16::from_be_bytes([payload[17], payload[18]]);
            Ok((
                SocketAddr::new(IpAddr::V6(address), port),
                address.to_string(),
                UDP_IPV6_HEADER_LEN,
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported SS target address type",
        )),
    }
}

struct DecryptedUdpPacket {
    user: usize,
    target: SocketAddr,
    host: String,
    payload: Box<[u8]>,
}

fn decrypt_udp_packet(
    packet: &[u8],
    site: &mut SiteState,
    cached_user: Option<usize>,
) -> io::Result<DecryptedUdpPacket> {
    if packet.len() < SALT_LEN + TAG_LEN + UDP_MIN_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short SS UDP packet",
        ));
    }
    let salt: [u8; SALT_LEN] = packet[..SALT_LEN].try_into().unwrap();
    let ciphertext = &packet[SALT_LEN..];
    let plaintext_length = ciphertext.len() - TAG_LEN;
    let mut trial = vec![0u8; ciphertext.len()];
    let mut authenticated = None;

    if let Some(user) = cached_user.filter(|&user| {
        site.users
            .get(user)
            .is_some_and(|runtime| runtime.state == UserSlotState::Live)
    }) {
        trial.copy_from_slice(ciphertext);
        let mut cipher = Cipher::new(KIND, &site.users[user].key, &salt);
        if cipher.decrypt_packet(&mut trial) {
            authenticated = Some(user);
        }
    }
    if authenticated.is_none() {
        for &user in &site.live_users {
            if Some(user) == cached_user {
                continue;
            }
            trial.copy_from_slice(ciphertext);
            let mut cipher = Cipher::new(KIND, &site.users[user].key, &salt);
            if cipher.decrypt_packet(&mut trial) {
                authenticated = Some(user);
                break;
            }
        }
    }
    let user = authenticated.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SS UDP user authentication failed",
        )
    })?;
    let key = site.users[user].key;
    if site.replay.check_and_add(key, salt) {
        site.replay_rejects = site.replay_rejects.saturating_add(1);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SS UDP replay rejected",
        ));
    }
    let (target, host, header_length) = parse_target(&trial[..plaintext_length])?;
    Ok(DecryptedUdpPacket {
        user,
        target,
        host,
        payload: trial[header_length..plaintext_length]
            .to_vec()
            .into_boxed_slice(),
    })
}

fn prepare_udp_response(
    association: &mut UdpAssociation,
    site: &mut SiteState,
    features: Features,
    payload_length: usize,
) -> io::Result<()> {
    if payload_length > UDP_TARGET_PAYLOAD_CAPACITY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SS UDP response exceeds the packet bound",
        ));
    }
    let user = association.user;
    let wait = reserve_budget(
        &mut site.users[user],
        &mut association.download_budget,
        payload_length,
        features.limiter,
    );
    extend_deadline(&mut association.download_ready_at, wait);
    let target = association.key.target;
    let header_length = match target {
        SocketAddr::V4(target) => {
            association.response[SALT_LEN] = 1;
            association.response[SALT_LEN + 1..SALT_LEN + 5].copy_from_slice(&target.ip().octets());
            association.response[SALT_LEN + 5..SALT_LEN + 7]
                .copy_from_slice(&target.port().to_be_bytes());
            UDP_IPV4_HEADER_LEN
        }
        SocketAddr::V6(target) => {
            association.response[SALT_LEN] = 4;
            association.response[SALT_LEN + 1..SALT_LEN + 17]
                .copy_from_slice(&target.ip().octets());
            association.response[SALT_LEN + 17..SALT_LEN + 19]
                .copy_from_slice(&target.port().to_be_bytes());
            UDP_IPV6_HEADER_LEN
        }
    };
    let payload_start = SALT_LEN + header_length;
    association.response.copy_within(
        UDP_RESPONSE_HEADROOM..UDP_RESPONSE_HEADROOM + payload_length,
        payload_start,
    );
    let salt = site.replay.generate_unique_salt(site.users[user].key)?;
    association.response[..SALT_LEN].copy_from_slice(&salt);
    let plaintext_length = header_length + payload_length;
    let encrypted_end = SALT_LEN + plaintext_length + TAG_LEN;
    association.response[SALT_LEN + plaintext_length..encrypted_end].fill(0);
    let mut cipher = Cipher::new(KIND, &site.users[user].key, &salt);
    cipher.encrypt_packet(&mut association.response[SALT_LEN..encrypted_end]);
    association.response_length = encrypted_end;
    association.response_plaintext_length = payload_length;
    Ok(())
}

fn reserve_budget(
    user: &mut UserRuntime,
    budget: &mut usize,
    count: usize,
    enabled: bool,
) -> Option<Duration> {
    if !enabled || count == 0 {
        return None;
    }
    if *budget >= count {
        *budget -= count;
        return None;
    }
    let request = count.max(user.limiter.reservation());
    let wait = user.limiter.reserve(request);
    *budget = request - count;
    wait
}

fn extend_deadline(deadline: &mut Option<Instant>, wait: Option<Duration>) {
    let Some(wait) = wait else {
        return;
    };
    let ready_at = Instant::now() + wait;
    if deadline.is_none_or(|current| ready_at > current) {
        *deadline = Some(ready_at);
    }
}

fn append_upload_from_input(
    connection: &mut Connection,
    source_start: usize,
    count: usize,
) -> io::Result<()> {
    if connection.upload_length + count > UPLOAD_CAPACITY {
        return Err(io::Error::other("plaintext upload buffer exceeded bound"));
    }
    if connection.upload_length == 0 {
        connection.upload_direct_start = Some(source_start);
        connection.upload_length = count;
        return Ok(());
    }
    if let Some(previous_start) = connection.upload_direct_start.take() {
        connection.upload[..connection.upload_length].copy_from_slice(
            &connection.input[previous_start..previous_start + connection.upload_length],
        );
    }
    let destination_start = connection.upload_length;
    connection.upload[destination_start..destination_start + count]
        .copy_from_slice(&connection.input[source_start..source_start + count]);
    connection.upload_length += count;
    Ok(())
}

fn finalize_pending_target(
    connection: &mut Connection,
    site: &mut SiteState,
    features: Features,
    force_original: bool,
) -> io::Result<Option<SocketAddr>> {
    let Some(original) = connection.pending_target.as_ref() else {
        return Ok(None);
    };
    let decision = if force_original {
        SniffDecision::Original
    } else if let Some(start) = connection.upload_direct_start {
        connection
            .sniff
            .inspect(&connection.input[start..start + connection.upload_length])
    } else {
        connection
            .sniff
            .inspect(&connection.upload[..connection.upload_length])
    };
    let target = match decision {
        SniffDecision::NeedMore => {
            if let Some(start) = connection.upload_direct_start.take() {
                connection.upload[..connection.upload_length]
                    .copy_from_slice(&connection.input[start..start + connection.upload_length]);
            }
            return Ok(None);
        }
        SniffDecision::Original => original.clone(),
        SniffDecision::Override(host) => ResolvedTarget::resolve(&host, original.address.port())?,
    };
    connection.pending_target = None;
    let destination = format!("tcp:{}:{}", target.host, target.address.port());
    if features.rule
        && (site
            .blocked_hosts
            .contains(&target.host.to_ascii_lowercase())
            || site
                .rules
                .as_ref()
                .is_some_and(|rules| rules.is_match(&destination)))
    {
        site.rule_rejects = site.rule_rejects.saturating_add(1);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SS rule rejected target",
        ));
    }
    Ok(Some(target.address))
}

fn decrypt_length(connection: &mut Connection) -> io::Result<bool> {
    if connection.input_length - connection.input_start < LENGTH_PACKET_LEN {
        return Ok(false);
    }
    let start = connection.input_start;
    let end = start + LENGTH_PACKET_LEN;
    if !connection
        .decryptor
        .as_mut()
        .expect("authenticated decryptor")
        .decrypt_packet(&mut connection.input[start..end])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SS length authentication failed",
        ));
    }
    let length =
        u16::from_be_bytes([connection.input[start], connection.input[start + 1]]) as usize;
    if length == 0 || length > MAX_PAYLOAD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SS payload length",
        ));
    }
    connection.input_start = end;
    connection.expected_payload = Some(length);
    Ok(true)
}

fn process_encrypted(
    connection: &mut Connection,
    site: &mut SiteState,
    features: Features,
) -> io::Result<Option<SocketAddr>> {
    if connection.decryptor.is_none() {
        if connection.input_length - connection.input_start < SALT_LEN + LENGTH_PACKET_LEN {
            return Ok(None);
        }
        let base = connection.input_start;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&connection.input[base..base + SALT_LEN]);
        let mut encrypted_length = [0u8; LENGTH_PACKET_LEN];
        encrypted_length.copy_from_slice(
            &connection.input[base + SALT_LEN..base + SALT_LEN + LENGTH_PACKET_LEN],
        );
        let mut authenticated = None;
        for &user_index in &site.live_users {
            let user = &site.users[user_index];
            let mut cipher = Cipher::new(KIND, &user.key, &salt);
            let mut trial = encrypted_length;
            if cipher.decrypt_packet(&mut trial) {
                let length = u16::from_be_bytes([trial[0], trial[1]]) as usize;
                if (1..=MAX_PAYLOAD_LEN).contains(&length) {
                    authenticated = Some((user_index, cipher, length));
                    break;
                }
            }
        }
        let Some((user, cipher, length)) = authenticated else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SS user authentication failed",
            ));
        };
        connection.decryptor = Some(cipher);
        connection.expected_payload = Some(length);
        connection.pending_salt = Some(salt);
        connection.user = Some(user);
        connection.input_start += SALT_LEN + LENGTH_PACKET_LEN;
    }

    loop {
        if connection.expected_payload.is_none() && !decrypt_length(connection)? {
            break;
        }
        let length = connection.expected_payload.expect("expected payload");
        if connection.input_length - connection.input_start < length + TAG_LEN {
            break;
        }
        let start = connection.input_start;
        let end = start + length + TAG_LEN;
        if !connection
            .decryptor
            .as_mut()
            .expect("authenticated decryptor")
            .decrypt_packet(&mut connection.input[start..end])
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SS payload authentication failed",
            ));
        }

        let user_index = connection.user.expect("authenticated user");
        if !connection.header_complete {
            let salt = connection.pending_salt.take().expect("initial salt");
            let key = site.users[user_index].key;
            if site.replay.check_and_add(key, salt) {
                site.replay_rejects += 1;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SS replay rejected",
                ));
            }
            let (address, host, header_length) =
                parse_target(&connection.input[start..start + length])?;
            if features.device {
                let devices = &mut site.users[user_index].device_ips;
                if site.device_limit != 0
                    && !devices.contains_key(&connection.peer_ip)
                    && devices.len() >= site.device_limit
                {
                    site.device_rejects += 1;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SS device limit rejected",
                    ));
                }
                *devices.entry(connection.peer_ip).or_default() += 1;
                connection.device_admitted = true;
            }
            site.users[user_index].active += 1;
            let payload_start = start + header_length;
            let payload_length = start + length - payload_start;
            let wait = reserve_budget(
                &mut site.users[user_index],
                &mut connection.upload_budget,
                payload_length,
                features.limiter,
            );
            extend_deadline(&mut connection.upload_ready_at, wait);
            append_upload_from_input(connection, payload_start, payload_length)?;
            connection.pending_target = Some(ResolvedTarget { address, host });
            connection.header_complete = true;
            connection.timeout.authenticated(Instant::now());
        } else {
            let wait = reserve_budget(
                &mut site.users[user_index],
                &mut connection.upload_budget,
                length,
                features.limiter,
            );
            extend_deadline(&mut connection.upload_ready_at, wait);
            append_upload_from_input(connection, start, length)?;
        }
        connection.input_start = end;
        connection.expected_payload = None;
    }
    if connection.upload_direct_start.is_none() {
        connection.compact_input();
    }
    finalize_pending_target(connection, site, features, false)
}

fn prepare_download(
    connection: &mut Connection,
    site: &mut SiteState,
    features: Features,
    count: usize,
) -> io::Result<()> {
    let user_index = connection.user.expect("authenticated user");
    let wait = reserve_budget(
        &mut site.users[user_index],
        &mut connection.download_budget,
        count,
        features.limiter,
    );
    extend_deadline(&mut connection.download_ready_at, wait);
    let payload_start = connection.download_payload_offset;
    let offset = payload_start - LENGTH_PACKET_LEN;
    if connection.encryptor.is_none() {
        let key = site.users[user_index].key;
        let salt = site.replay.generate_unique_salt(key)?;
        connection.download_ciphertext[..SALT_LEN].copy_from_slice(&salt);
        connection.encryptor = Some(Cipher::new(KIND, &key, &salt));
    }
    connection.download_ciphertext[offset..offset + 2]
        .copy_from_slice(&(count as u16).to_be_bytes());
    connection.download_ciphertext[offset + 2..offset + LENGTH_PACKET_LEN].fill(0);
    connection
        .encryptor
        .as_mut()
        .expect("download encryptor")
        .encrypt_packet(&mut connection.download_ciphertext[offset..offset + LENGTH_PACKET_LEN]);
    connection.download_ciphertext[payload_start + count..payload_start + count + TAG_LEN].fill(0);
    connection
        .encryptor
        .as_mut()
        .expect("download encryptor")
        .encrypt_packet(
            &mut connection.download_ciphertext[payload_start..payload_start + count + TAG_LEN],
        );
    connection.download_length = payload_start + count + TAG_LEN;
    connection.download_offset = 0;
    connection.download_plaintext_length = count;
    Ok(())
}

pub const FILE_SLOT_COUNT: u32 = (MAX_CONNECTIONS * 2 + 2) as u32;

pub struct Status {
    pub live_users: usize,
    pub retired_users: usize,
    pub runtime_users: usize,
    pub slots: usize,
    pub free: usize,
    pub open: usize,
    pub closing: usize,
    pub inflight: usize,
    pub active_users: usize,
    pub upload: u64,
    pub download: u64,
    pub replay_rejects: u64,
    pub device_rejects: u64,
    pub rule_rejects: u64,
    pub udp_input_drops: u64,
    pub udp_queue_drops: u64,
    pub udp_listener_errors: u64,
    pub udp_upload_errors: u64,
    pub udp_receive_errors: u64,
    pub udp_response_errors: u64,
}

pub struct Engine {
    sites: Vec<SiteState>,
    listeners: Vec<TcpListener>,
    udp_listeners: Vec<UdpListenerState>,
    udp_associations: Vec<Option<UdpAssociation>>,
    free_udp_associations: Vec<usize>,
    udp_association_index: HashMap<UdpAssociationKey, usize>,
    udp_user_cache: HashMap<(usize, SocketAddr), usize>,
    udp_timers: BinaryHeap<Reverse<(Instant, usize, u64, u8)>>,
    udp_queued_bytes: usize,
    active_udp_associations: usize,
    udp_idle_timeout: Duration,
    udp_input_drops: u64,
    udp_queue_drops: u64,
    udp_listener_errors: u64,
    udp_upload_errors: u64,
    udp_receive_errors: u64,
    udp_response_errors: u64,
    accept_armed: Vec<bool>,
    accept_armed_count: usize,
    accept_cursor: usize,
    active_connections: usize,
    timers: BinaryHeap<Reverse<(Instant, usize, u64, u8)>>,
    next_generation: u64,
    connections: Vec<Option<Connection>>,
    free_connections: Vec<usize>,
    features: Features,
    tcp_nodelay: bool,
    fixed_file_base: u32,
    tcp_timeouts: TcpTimeouts,
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_addresses(
        listen_addresses: &[String],
        sniffing: &[bool],
        user_count: usize,
        revision: usize,
        features: &str,
        speed_mbps: u64,
        blocked_host: &str,
        device_limit: usize,
        tcp_nodelay: bool,
        fixed_file_base: u32,
        udp_idle_timeout: Duration,
        tcp_timeouts: TcpTimeouts,
    ) -> io::Result<Self> {
        if sniffing.len() != listen_addresses.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SS sniffing flags must match listen addresses",
            ));
        }
        let speed_bytes_per_second = speed_mbps.saturating_mul(1_000_000) / 8;
        let sites = build_sites(
            listen_addresses.len(),
            sniffing,
            user_count,
            revision,
            speed_bytes_per_second,
            blocked_host,
            device_limit,
        );
        let mut listeners = Vec::with_capacity(listen_addresses.len());
        let mut udp_listeners = Vec::with_capacity(listen_addresses.len());
        for address in listen_addresses {
            let listener = TcpListener::bind(address)?;
            listener.set_nonblocking(true)?;
            listeners.push(listener);
            udp_listeners.push(UdpListenerState::bind(address)?);
        }
        let mut connections = Vec::with_capacity(MAX_CONNECTIONS + 1);
        connections.push(None);
        let mut udp_associations = Vec::with_capacity(MAX_UDP_ASSOCIATIONS + 1);
        udp_associations.push(None);
        Ok(Self {
            sites,
            accept_armed: vec![false; listeners.len()],
            accept_armed_count: 0,
            listeners,
            udp_listeners,
            udp_associations,
            free_udp_associations: Vec::with_capacity(MAX_UDP_ASSOCIATIONS),
            udp_association_index: HashMap::with_capacity(MAX_UDP_ASSOCIATIONS),
            udp_user_cache: HashMap::with_capacity(MAX_UDP_ASSOCIATIONS),
            udp_timers: BinaryHeap::new(),
            udp_queued_bytes: 0,
            active_udp_associations: 0,
            udp_idle_timeout,
            udp_input_drops: 0,
            udp_queue_drops: 0,
            udp_listener_errors: 0,
            udp_upload_errors: 0,
            udp_receive_errors: 0,
            udp_response_errors: 0,
            accept_cursor: 0,
            active_connections: 0,
            timers: BinaryHeap::new(),
            next_generation: 1,
            connections,
            free_connections: Vec::with_capacity(MAX_CONNECTIONS),
            features: Features::parse(features),
            tcp_nodelay,
            fixed_file_base,
            tcp_timeouts,
        })
    }

    fn arm_accepts(&mut self, pending: &mut Vec<squeue::Entry>) {
        if self.listeners.is_empty() {
            return;
        }
        let capacity = MAX_CONNECTIONS.saturating_sub(1);
        if self.accept_armed_count >= self.listeners.len()
            || self.active_connections + self.accept_armed_count >= capacity
        {
            return;
        }
        for _ in 0..self.listeners.len() {
            if self.active_connections + self.accept_armed_count >= capacity {
                break;
            }
            let site = self.accept_cursor;
            self.accept_cursor = (self.accept_cursor + 1) % self.listeners.len();
            if self.accept_armed[site] {
                continue;
            }
            self.accept_armed[site] = true;
            self.accept_armed_count += 1;
            pending.push(accept_entry(self.listeners[site].as_raw_fd(), site));
        }
    }

    fn arm_udp_listeners(&mut self, pending: &mut Vec<squeue::Entry>) {
        for (site, listener) in self.udp_listeners.iter_mut().enumerate() {
            if !listener.armed {
                pending.push(recv_udp_inbound_entry(site, listener));
            }
        }
    }

    pub fn arm(&mut self, pending: &mut Vec<squeue::Entry>) {
        self.arm_accepts(pending);
        self.arm_udp_listeners(pending);
    }

    pub fn status(&self) -> Status {
        let mut open = 0;
        let mut closing = 0;
        let mut inflight = 0;
        for state in self.connections.iter().flatten() {
            open += 1;
            closing += usize::from(state.closing);
            inflight += state.inflight;
        }
        for state in self.udp_associations.iter().flatten() {
            open += 1;
            closing += usize::from(state.closing);
            inflight += state.inflight;
        }
        let mut active_users = 0;
        let mut live_users = 0;
        let mut retired_users = 0;
        let mut upload = 0u64;
        let mut download = 0u64;
        for site in &self.sites {
            live_users += site.live_users.len();
            retired_users += site.retired_users();
            for user in &site.users {
                active_users += usize::from(user.active != 0);
            }
            let (site_upload, site_download) = site.traffic_totals();
            upload = upload.saturating_add(site_upload);
            download = download.saturating_add(site_download);
        }
        Status {
            live_users,
            retired_users,
            runtime_users: live_users + retired_users,
            slots: self.connections.len().saturating_sub(1),
            free: self.free_connections.len(),
            open,
            closing,
            inflight,
            active_users,
            upload,
            download,
            replay_rejects: self.sites.iter().map(|site| site.replay_rejects).sum(),
            device_rejects: self.sites.iter().map(|site| site.device_rejects).sum(),
            rule_rejects: self.sites.iter().map(|site| site.rule_rejects).sum(),
            udp_input_drops: self.udp_input_drops,
            udp_queue_drops: self.udp_queue_drops,
            udp_listener_errors: self.udp_listener_errors,
            udp_upload_errors: self.udp_upload_errors,
            udp_receive_errors: self.udp_receive_errors,
            udp_response_errors: self.udp_response_errors,
        }
    }

    pub fn open_connections(&self) -> usize {
        self.active_connections + self.active_udp_associations
    }

    pub fn has_tcp_connections(&self) -> bool {
        self.active_connections != 0
    }

    pub fn expire_tcp(&mut self, now: Instant) {
        for state in self.connections.iter_mut().flatten() {
            if !state.closing && state.timeout.expired(now, self.tcp_timeouts) {
                begin_close(state);
            }
        }
    }

    pub fn replace_users(
        &mut self,
        site: usize,
        users: Vec<NormalizedUser>,
    ) -> io::Result<(usize, usize)> {
        let index = site.checked_sub(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "SS site must be one-based")
        })?;
        let result = self
            .sites
            .get_mut(index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "SS site was not found"))?
            .replace_users(users)?;
        self.udp_user_cache
            .retain(|(cached_site, _), _| *cached_site != index);
        for association in self.udp_associations.iter_mut().flatten() {
            if association.key.site == index
                && self.sites[index].users[association.user].state != UserSlotState::Live
            {
                association.closing = true;
                shutdown(association.outbound.as_raw_fd());
            }
        }
        Ok(result)
    }

    pub fn take_traffic(&mut self, site: usize) -> io::Result<Vec<TrafficRecord>> {
        Ok(self
            .sites
            .get_mut(site.checked_sub(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "SS site must be one-based")
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "SS site was not found"))?
            .take_traffic())
    }

    pub fn restore_traffic(&mut self, site: usize, traffic: Vec<TrafficRecord>) -> io::Result<()> {
        self.sites
            .get_mut(site.checked_sub(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "SS site must be one-based")
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "SS site was not found"))?
            .restore_traffic(traffic);
        Ok(())
    }

    pub fn update_policy(
        &mut self,
        site: usize,
        speed_bytes_per_second: u64,
        device_limit: usize,
        rules: Vec<String>,
    ) -> io::Result<()> {
        self.sites
            .get_mut(site.checked_sub(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "SS site must be one-based")
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "SS site was not found"))?
            .update_policy(speed_bytes_per_second, device_limit, rules)
    }

    fn schedule_waits(
        timers: &mut BinaryHeap<Reverse<(Instant, usize, u64, u8)>>,
        identifier: usize,
        state: &mut Connection,
    ) {
        if let Some(deadline) = state.upload_ready_at {
            if state.upload_scheduled_at != Some(deadline) {
                timers.push(Reverse((
                    deadline,
                    identifier,
                    state.generation,
                    TIMER_UPLOAD,
                )));
                state.upload_scheduled_at = Some(deadline);
            }
        }
        if let Some(deadline) = state.download_ready_at {
            if state.download_scheduled_at != Some(deadline) {
                timers.push(Reverse((
                    deadline,
                    identifier,
                    state.generation,
                    TIMER_DOWNLOAD,
                )));
                state.download_scheduled_at = Some(deadline);
            }
        }
    }

    fn timer_is_current(&self, entry: (Instant, usize, u64, u8)) -> bool {
        let (deadline, identifier, generation, direction) = entry;
        let Some(state) = self.connections.get(identifier).and_then(Option::as_ref) else {
            return false;
        };
        if state.closing || state.generation != generation {
            return false;
        }
        match direction {
            TIMER_UPLOAD => state.upload_ready_at == Some(deadline),
            TIMER_DOWNLOAD => state.download_ready_at == Some(deadline),
            _ => false,
        }
    }

    fn schedule_udp_waits(&mut self, identifier: usize, state: &UdpAssociation) {
        if let Some(deadline) = state.upload_ready_at {
            self.udp_timers.push(Reverse((
                deadline,
                identifier,
                state.generation,
                TIMER_UDP_UPLOAD,
            )));
        }
        if let Some(deadline) = state.download_ready_at {
            self.udp_timers.push(Reverse((
                deadline,
                identifier,
                state.generation,
                TIMER_UDP_DOWNLOAD,
            )));
        }
        self.udp_timers.push(Reverse((
            state.expires_at,
            identifier,
            state.generation,
            TIMER_UDP_EXPIRE,
        )));
    }

    fn udp_timer_is_current(&self, entry: (Instant, usize, u64, u8)) -> bool {
        let (deadline, identifier, generation, direction) = entry;
        let Some(state) = self
            .udp_associations
            .get(identifier)
            .and_then(Option::as_ref)
        else {
            return false;
        };
        if state.closing || state.generation != generation {
            return false;
        }
        match direction {
            TIMER_UDP_UPLOAD => state.upload_ready_at == Some(deadline),
            TIMER_UDP_DOWNLOAD => state.download_ready_at == Some(deadline),
            TIMER_UDP_EXPIRE => state.expires_at == deadline,
            _ => false,
        }
    }

    pub fn next_deadline(&mut self) -> Option<Instant> {
        let tcp = loop {
            let Some(entry) = self.timers.peek().map(|entry| entry.0) else {
                break None;
            };
            if self.timer_is_current(entry) {
                break Some(entry.0);
            }
            self.timers.pop();
        };
        let udp = loop {
            let Some(entry) = self.udp_timers.peek().map(|entry| entry.0) else {
                break None;
            };
            if self.udp_timer_is_current(entry) {
                break Some(entry.0);
            }
            self.udp_timers.pop();
        };
        match (tcp, udp) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left @ Some(_), None) => left,
            (None, right) => right,
        }
    }

    pub fn resume_due(&mut self, now: Instant, pending: &mut Vec<squeue::Entry>) {
        while let Some(Reverse(entry @ (deadline, _, _, _))) = self.timers.peek().copied() {
            if deadline > now {
                break;
            }
            self.timers.pop();
            if !self.timer_is_current(entry) {
                continue;
            }
            let (_, identifier, generation, direction) = entry;
            let Some(state) = self
                .connections
                .get_mut(identifier)
                .and_then(Option::as_mut)
            else {
                continue;
            };
            if state.generation != generation || state.closing {
                continue;
            }
            match direction {
                TIMER_UPLOAD => {
                    state.upload_ready_at = None;
                    state.upload_scheduled_at = None;
                    if state.connected && state.upload_length != 0 {
                        queue_connection!(state, pending, send_outbound_entry(identifier, state));
                    }
                }
                TIMER_DOWNLOAD => {
                    state.download_ready_at = None;
                    state.download_scheduled_at = None;
                    if state.download_length != 0 {
                        queue_connection!(state, pending, send_inbound_entry(identifier, state));
                    }
                }
                _ => {}
            }
        }
        while let Some(Reverse(entry @ (deadline, _, _, _))) = self.udp_timers.peek().copied() {
            if deadline > now {
                break;
            }
            self.udp_timers.pop();
            if !self.udp_timer_is_current(entry) {
                continue;
            }
            let (_, identifier, generation, direction) = entry;
            let Some(state) = self
                .udp_associations
                .get_mut(identifier)
                .and_then(Option::as_mut)
            else {
                continue;
            };
            if state.generation != generation || state.closing {
                continue;
            }
            match direction {
                TIMER_UDP_UPLOAD => {
                    state.upload_ready_at = None;
                    if state.current_upload.is_some() && !state.upload_inflight {
                        queue_connection!(
                            state,
                            pending,
                            send_udp_outbound_entry(identifier, state)
                        );
                    }
                }
                TIMER_UDP_DOWNLOAD => {
                    state.download_ready_at = None;
                    if state.response_length != 0 && !state.response_inflight {
                        let site = state.key.site;
                        queue_connection!(
                            state,
                            pending,
                            send_udp_inbound_entry(identifier, &self.udp_listeners[site], state)
                        );
                    }
                }
                TIMER_UDP_EXPIRE => {
                    begin_udp_close(state);
                    if state.recv_inflight && !state.cancel_queued {
                        state.cancel_queued = true;
                        queue_connection!(state, pending, cancel_udp_recv_entry(identifier));
                    }
                }
                _ => {}
            }
        }
    }

    fn start_udp_upload(
        &mut self,
        identifier: usize,
        state: &mut UdpAssociation,
        pending: &mut Vec<squeue::Entry>,
    ) {
        if state.current_upload.is_none() {
            if let Some(upload) = state.upload_queue.pop_front() {
                self.udp_queued_bytes = self.udp_queued_bytes.saturating_sub(upload.len());
                state.current_upload = Some(upload);
            }
        }
        let Some(length) = state.current_upload.as_ref().map(|upload| upload.len()) else {
            return;
        };
        if state.upload_inflight || state.upload_ready_at.is_some() {
            return;
        }
        let wait = reserve_budget(
            &mut self.sites[state.key.site].users[state.user],
            &mut state.upload_budget,
            length,
            self.features.limiter,
        );
        extend_deadline(&mut state.upload_ready_at, wait);
        if state.upload_ready_at.is_none() {
            queue_connection!(state, pending, send_udp_outbound_entry(identifier, state));
        }
    }

    fn handle_udp_datagram(
        &mut self,
        site_index: usize,
        client: SocketAddr,
        packet: &[u8],
        pending: &mut Vec<squeue::Entry>,
    ) -> io::Result<()> {
        let cached_user = self.udp_user_cache.get(&(site_index, client)).copied();
        let decoded = decrypt_udp_packet(packet, &mut self.sites[site_index], cached_user)?;
        let destination = format!("udp:{}:{}", decoded.host, decoded.target.port());
        if self.features.rule
            && (self.sites[site_index]
                .blocked_hosts
                .contains(&decoded.host.to_ascii_lowercase())
                || self.sites[site_index]
                    .rules
                    .as_ref()
                    .is_some_and(|rules| rules.is_match(&destination)))
        {
            self.sites[site_index].rule_rejects =
                self.sites[site_index].rule_rejects.saturating_add(1);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SS UDP rule rejected target",
            ));
        }
        let key = UdpAssociationKey {
            site: site_index,
            client,
            target: decoded.target,
        };
        let identifier = match self.udp_association_index.get(&key).copied() {
            Some(identifier)
                if self
                    .udp_associations
                    .get(identifier)
                    .and_then(Option::as_ref)
                    .is_some_and(|state| !state.closing && state.user == decoded.user) =>
            {
                identifier
            }
            Some(identifier) => {
                self.udp_association_index.remove(&key);
                if let Some(state) = self
                    .udp_associations
                    .get_mut(identifier)
                    .and_then(Option::as_mut)
                {
                    begin_udp_close(state);
                }
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "SS UDP association credential changed",
                ));
            }
            None => {
                if self.active_udp_associations >= MAX_UDP_ASSOCIATIONS {
                    return Err(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "SS UDP association capacity reached",
                    ));
                }
                let peer_ip = client.ip();
                if self.features.device {
                    let site = &self.sites[site_index];
                    let devices = &site.users[decoded.user].device_ips;
                    if site.device_limit != 0
                        && !devices.contains_key(&peer_ip)
                        && devices.len() >= site.device_limit
                    {
                        self.sites[site_index].device_rejects =
                            self.sites[site_index].device_rejects.saturating_add(1);
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "SS UDP device limit rejected",
                        ));
                    }
                }
                let generation = self.next_generation;
                self.next_generation = self.next_generation.wrapping_add(1).max(1);
                let identifier = self
                    .free_udp_associations
                    .pop()
                    .unwrap_or(self.udp_associations.len());
                let mut state = UdpAssociation::new(
                    key,
                    decoded.user,
                    peer_ip,
                    false,
                    generation,
                    self.udp_idle_timeout,
                )?;
                if self.features.device {
                    *self.sites[site_index].users[decoded.user]
                        .device_ips
                        .entry(peer_ip)
                        .or_default() += 1;
                    state.device_admitted = true;
                }
                self.sites[site_index].users[decoded.user].active += 1;
                queue_connection!(
                    &mut state,
                    pending,
                    recv_udp_outbound_entry(identifier, &mut state)
                );
                if identifier == self.udp_associations.len() {
                    self.udp_associations.push(Some(state));
                } else {
                    self.udp_associations[identifier] = Some(state);
                }
                self.udp_association_index.insert(key, identifier);
                self.active_udp_associations += 1;
                identifier
            }
        };
        // Cache only sources that own a live association. This keeps the
        // authentication shortcut bounded by MAX_UDP_ASSOCIATIONS even when
        // an authenticated client deliberately cycles source ports while its
        // packets are rejected by policy or capacity checks.
        self.udp_user_cache
            .insert((site_index, client), decoded.user);

        let Some(mut state) = self.udp_associations[identifier].take() else {
            return Ok(());
        };
        if state.current_upload.is_none() {
            state.current_upload = Some(decoded.payload);
        } else if state.upload_queue.len() < MAX_UDP_QUEUE_PER_ASSOCIATION
            && self.udp_queued_bytes.saturating_add(decoded.payload.len()) <= MAX_UDP_QUEUED_BYTES
        {
            self.udp_queued_bytes = self.udp_queued_bytes.saturating_add(decoded.payload.len());
            state.upload_queue.push_back(decoded.payload);
        } else {
            self.udp_queue_drops = self.udp_queue_drops.saturating_add(1);
        }
        state.expires_at = Instant::now() + self.udp_idle_timeout;
        self.start_udp_upload(identifier, &mut state, pending);
        self.schedule_udp_waits(identifier, &state);
        self.udp_associations[identifier] = Some(state);
        Ok(())
    }

    pub fn handle_completion(
        &mut self,
        ring: &mut IoUring,
        user_data: u64,
        result: i32,
        pending: &mut Vec<squeue::Entry>,
    ) -> io::Result<()> {
        let (id_or_site, operation) = decode_tag(user_data);
        if operation == OP_RECV_UDP_INBOUND {
            let site = id_or_site;
            let datagram = {
                let listener = &mut self.udp_listeners[site];
                listener.armed = false;
                if result < 0
                    || result as usize > listener.buffer.len()
                    || listener.message.msg_flags & libc::MSG_TRUNC != 0
                {
                    self.udp_listener_errors = self.udp_listener_errors.saturating_add(1);
                    None
                } else {
                    socket_address(&listener.source)
                        .ok()
                        .map(|source| (source, listener.buffer[..result as usize].to_vec()))
                }
            };
            if let Some((source, packet)) = datagram {
                // Invalid or unauthorized UDP packets are dropped without a
                // per-packet log, preventing an authentication log storm.
                if self
                    .handle_udp_datagram(site, source, &packet, pending)
                    .is_err()
                {
                    self.udp_input_drops = self.udp_input_drops.saturating_add(1);
                }
            }
            self.arm_udp_listeners(pending);
            return Ok(());
        }
        if matches!(
            operation,
            OP_SEND_UDP_OUTBOUND | OP_RECV_UDP_OUTBOUND | OP_SEND_UDP_INBOUND | OP_CANCEL_UDP_RECV
        ) {
            let identifier = id_or_site;
            let Some(mut state) = self
                .udp_associations
                .get_mut(identifier)
                .and_then(Option::take)
            else {
                return Ok(());
            };
            state.inflight = state.inflight.saturating_sub(1);
            match operation {
                OP_SEND_UDP_OUTBOUND => state.upload_inflight = false,
                OP_RECV_UDP_OUTBOUND => state.recv_inflight = false,
                OP_SEND_UDP_INBOUND => state.response_inflight = false,
                _ => {}
            }
            if state.closing {
                self.udp_associations[identifier] = Some(state);
                return Ok(());
            }
            if result < 0 {
                match operation {
                    OP_SEND_UDP_OUTBOUND => {
                        self.udp_upload_errors = self.udp_upload_errors.saturating_add(1)
                    }
                    OP_RECV_UDP_OUTBOUND => {
                        self.udp_receive_errors = self.udp_receive_errors.saturating_add(1)
                    }
                    OP_SEND_UDP_INBOUND => {
                        self.udp_response_errors = self.udp_response_errors.saturating_add(1)
                    }
                    _ => {}
                }
                begin_udp_close(&mut state);
                self.udp_associations[identifier] = Some(state);
                return Ok(());
            }
            let outcome = (|| -> io::Result<()> {
                match operation {
                    OP_SEND_UDP_OUTBOUND => {
                        let expected = state
                            .current_upload
                            .as_ref()
                            .map_or(0, |upload| upload.len());
                        if result as usize != expected {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "partial SS UDP target write",
                            ));
                        }
                        if self.features.traffic {
                            self.sites[state.key.site].users[state.user].upload =
                                self.sites[state.key.site].users[state.user]
                                    .upload
                                    .saturating_add(result as u64);
                        }
                        state.current_upload = None;
                        self.start_udp_upload(identifier, &mut state, pending);
                    }
                    OP_RECV_UDP_OUTBOUND => {
                        let payload_length = result as usize;
                        let site = state.key.site;
                        prepare_udp_response(
                            &mut state,
                            &mut self.sites[site],
                            self.features,
                            payload_length,
                        )?;
                        if state.download_ready_at.is_none() {
                            queue_connection!(
                                &mut state,
                                pending,
                                send_udp_inbound_entry(
                                    identifier,
                                    &self.udp_listeners[site],
                                    &mut state
                                )
                            );
                        }
                    }
                    OP_SEND_UDP_INBOUND => {
                        if result as usize != state.response_length {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "partial SS UDP client write",
                            ));
                        }
                        if self.features.traffic {
                            let user = &mut self.sites[state.key.site].users[state.user];
                            user.download = user
                                .download
                                .saturating_add(state.response_plaintext_length as u64);
                        }
                        state.response_length = 0;
                        state.response_plaintext_length = 0;
                        queue_connection!(
                            &mut state,
                            pending,
                            recv_udp_outbound_entry(identifier, &mut state)
                        );
                    }
                    OP_CANCEL_UDP_RECV => {}
                    _ => unreachable!(),
                }
                Ok(())
            })();
            if outcome.is_err() {
                match operation {
                    OP_SEND_UDP_OUTBOUND => {
                        self.udp_upload_errors = self.udp_upload_errors.saturating_add(1)
                    }
                    OP_RECV_UDP_OUTBOUND => {
                        self.udp_receive_errors = self.udp_receive_errors.saturating_add(1)
                    }
                    OP_SEND_UDP_INBOUND => {
                        self.udp_response_errors = self.udp_response_errors.saturating_add(1)
                    }
                    _ => {}
                }
                begin_udp_close(&mut state);
            } else {
                state.expires_at = Instant::now() + self.udp_idle_timeout;
                self.schedule_udp_waits(identifier, &state);
            }
            self.udp_associations[identifier] = Some(state);
            return Ok(());
        }
        if operation == OP_ACCEPT {
            let site = id_or_site;
            self.accept_armed[site] = false;
            self.accept_armed_count = self.accept_armed_count.saturating_sub(1);
            if result < 0 {
                self.arm_accepts(pending);
                return Ok(());
            }
            let inbound = unsafe { OwnedFd::from_raw_fd(result) };
            if self.active_connections >= MAX_CONNECTIONS.saturating_sub(1) {
                self.arm_accepts(pending);
                return Ok(());
            }
            if set_nodelay(inbound.as_raw_fd(), self.tcp_nodelay).is_err() {
                self.arm_accepts(pending);
                return Ok(());
            }
            let peer_ip = peer_ip(inbound.as_raw_fd()).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            let generation = self.next_generation;
            self.next_generation = self.next_generation.wrapping_add(1).max(1);
            let id = self
                .free_connections
                .pop()
                .unwrap_or(self.connections.len());
            let inbound_slot = self.fixed_file_base + (id * 2) as u32;
            let outbound_slot = inbound_slot + 1;
            register_file(ring, inbound_slot, inbound.as_raw_fd())?;
            let mut state = Connection {
                _inbound: inbound,
                outbound: None,
                inbound_slot,
                outbound_slot,
                target: None,
                pending_target: None,
                sniff: SniffState::new(self.sites[site].sniffing),
                site,
                peer_ip,
                input: Box::new([0; INPUT_CAPACITY]),
                input_start: 0,
                input_length: 0,
                decryptor: None,
                expected_payload: None,
                pending_salt: None,
                user: None,
                header_complete: false,
                upload: Box::new([0; UPLOAD_CAPACITY]),
                upload_direct_start: None,
                upload_length: 0,
                upload_offset: 0,
                upload_budget: 0,
                download_ciphertext: Box::new([0; DOWNLOAD_CIPHERTEXT_CAPACITY]),
                download_payload_offset: 0,
                download_length: 0,
                download_offset: 0,
                download_plaintext_length: 0,
                download_budget: 0,
                upload_ready_at: None,
                upload_scheduled_at: None,
                download_ready_at: None,
                download_scheduled_at: None,
                encryptor: None,
                connected: false,
                connecting: false,
                device_admitted: false,
                inbound_read_eof: false,
                outbound_read_eof: false,
                outbound_write_shutdown: false,
                inbound_write_shutdown: false,
                inflight: 0,
                closing: false,
                failed: false,
                generation,
                timeout: TcpTimeoutState::new(Instant::now()),
            };
            queue_connection!(&mut state, pending, recv_inbound_entry(id, &mut state)?);
            if id == self.connections.len() {
                self.connections.push(Some(state));
            } else {
                self.connections[id] = Some(state);
            }
            self.active_connections += 1;
            self.arm_accepts(pending);
            return Ok(());
        }

        let id = id_or_site;
        let features = self.features;
        let tcp_nodelay = self.tcp_nodelay;
        let tcp_timeouts = self.tcp_timeouts;
        let sites = &mut self.sites;
        let timers = &mut self.timers;
        let Some(state) = self.connections.get_mut(id).and_then(Option::as_mut) else {
            return Ok(());
        };
        state.inflight = state.inflight.saturating_sub(1);
        if state.closing {
            complete_while_closing(state, operation, result, sites, features);
            return Ok(());
        }
        if result < 0 {
            fail_io(state, io::Error::from_raw_os_error(-result));
            return Ok(());
        }

        let outcome = (|| -> io::Result<()> {
            match operation {
                OP_CONNECT => {
                    state.connected = true;
                    state.connecting = false;
                    queue_connection!(state, pending, recv_outbound_entry(id, state));
                    if state.upload_length != 0 && state.upload_ready_at.is_none() {
                        queue_connection!(state, pending, send_outbound_entry(id, state));
                    } else if state.upload_length == 0 && !state.inbound_read_eof {
                        queue_connection!(state, pending, recv_inbound_entry(id, state)?);
                    }
                    finish_upload_half(state);
                    finish_graceful_close(state);
                }
                OP_RECV_INBOUND => {
                    if result == 0 {
                        if !state.header_complete {
                            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                        }
                        if state.pending_target.is_some() {
                            let site = &mut sites[state.site];
                            if let Some(target) =
                                finalize_pending_target(state, site, features, true)?
                            {
                                start_target_connect(
                                    id,
                                    state,
                                    target,
                                    tcp_nodelay,
                                    ring,
                                    pending,
                                )?;
                            }
                        }
                        state.inbound_read_eof = true;
                        if state.timeout.upload_closed(Instant::now(), tcp_timeouts) {
                            begin_close(state);
                            return Ok(());
                        }
                        finish_upload_half(state);
                        finish_graceful_close(state);
                        return Ok(());
                    }
                    state.timeout.note_activity();
                    state.input_length += result as usize;
                    let site = &mut sites[state.site];
                    let target = process_encrypted(state, site, features)?;
                    if let Some(target) = target {
                        start_target_connect(id, state, target, tcp_nodelay, ring, pending)?;
                    } else if state.connected
                        && state.upload_length != 0
                        && state.upload_ready_at.is_none()
                    {
                        queue_connection!(state, pending, send_outbound_entry(id, state));
                    } else if !state.connecting
                        && state.upload_length == 0
                        && !state.inbound_read_eof
                    {
                        queue_connection!(state, pending, recv_inbound_entry(id, state)?);
                    }
                }
                OP_SEND_OUTBOUND => {
                    if result == 0 {
                        return Err(io::Error::from(io::ErrorKind::WriteZero));
                    }
                    let count = result as usize;
                    state.upload_offset += count;
                    if features.traffic {
                        let user = state.user.expect("authenticated user");
                        sites[state.site].users[user].upload += count as u64;
                    }
                    if state.upload_offset < state.upload_length {
                        queue_connection!(state, pending, send_outbound_entry(id, state));
                    } else {
                        state.upload_offset = 0;
                        state.upload_length = 0;
                        state.upload_direct_start = None;
                        if state.inbound_read_eof {
                            finish_upload_half(state);
                            finish_graceful_close(state);
                        } else {
                            queue_connection!(state, pending, recv_inbound_entry(id, state)?);
                        }
                    }
                }
                OP_RECV_OUTBOUND => {
                    if result == 0 {
                        state.outbound_read_eof = true;
                        if state.timeout.download_closed(Instant::now(), tcp_timeouts) {
                            begin_close(state);
                            return Ok(());
                        }
                        finish_download_half(state);
                        finish_graceful_close(state);
                        return Ok(());
                    }
                    state.timeout.note_activity();
                    let site = state.site;
                    prepare_download(state, &mut sites[site], features, result as usize)?;
                    if state.download_ready_at.is_none() {
                        queue_connection!(state, pending, send_inbound_entry(id, state));
                    }
                }
                OP_SEND_INBOUND => {
                    if result == 0 {
                        return Err(io::Error::from(io::ErrorKind::WriteZero));
                    }
                    let credited = complete_record_write(
                        &mut state.download_offset,
                        state.download_length,
                        &mut state.download_plaintext_length,
                        result as usize,
                    );
                    if state.download_offset < state.download_length {
                        queue_connection!(state, pending, send_inbound_entry(id, state));
                    } else {
                        if credited != 0 && features.traffic {
                            let user = state.user.expect("authenticated user");
                            sites[state.site].users[user].download += credited;
                        }
                        state.download_offset = 0;
                        state.download_length = 0;
                        if state.outbound_read_eof {
                            finish_download_half(state);
                            finish_graceful_close(state);
                        } else {
                            queue_connection!(state, pending, recv_outbound_entry(id, state));
                        }
                    }
                }
                _ => return Err(io::Error::other("unknown io_uring operation")),
            }
            Ok(())
        })();
        if let Err(error) = outcome {
            fail_io(state, error);
        }
        if !state.closing {
            Self::schedule_waits(timers, id, state);
        }
        Ok(())
    }

    pub fn finish_batch(
        &mut self,
        ring: &mut IoUring,
        pending: &mut Vec<squeue::Entry>,
    ) -> io::Result<()> {
        let cleanup_pending = self.connections.iter().flatten().any(|state| state.closing)
            || self
                .udp_associations
                .iter()
                .flatten()
                .any(|state| state.closing);
        if cleanup_pending {
            pending.retain(|entry| {
                let user_data = entry.get_user_data();
                if !owns(user_data) {
                    return true;
                }
                let (identifier, operation) = decode_tag(user_data);
                if matches!(operation, OP_ACCEPT | OP_RECV_UDP_INBOUND) {
                    return true;
                }
                if matches!(
                    operation,
                    OP_SEND_UDP_OUTBOUND
                        | OP_RECV_UDP_OUTBOUND
                        | OP_SEND_UDP_INBOUND
                        | OP_CANCEL_UDP_RECV
                ) {
                    let Some(state) = self
                        .udp_associations
                        .get_mut(identifier)
                        .and_then(Option::as_mut)
                    else {
                        return false;
                    };
                    if !state.closing {
                        return true;
                    }
                    state.inflight = state.inflight.saturating_sub(1);
                    return false;
                }
                let Some(state) = self
                    .connections
                    .get_mut(identifier)
                    .and_then(Option::as_mut)
                else {
                    return false;
                };
                if !state.closing {
                    return true;
                }
                state.inflight = state.inflight.saturating_sub(1);
                false
            });

            for (identifier, state) in self.udp_associations.iter_mut().enumerate().skip(1) {
                let Some(state) = state.as_mut() else {
                    continue;
                };
                if state.closing
                    && state.inflight != 0
                    && state.recv_inflight
                    && !state.cancel_queued
                {
                    state.cancel_queued = true;
                    queue_connection!(state, pending, cancel_udp_recv_entry(identifier));
                }
            }

            let retired_udp: Vec<_> = self
                .udp_associations
                .iter()
                .enumerate()
                .skip(1)
                .filter_map(|(identifier, state)| {
                    state
                        .as_ref()
                        .filter(|state| state.closing && state.inflight == 0)
                        .map(|_| identifier)
                })
                .collect();
            for identifier in retired_udp {
                let Some(state) = self.udp_associations[identifier].take() else {
                    continue;
                };
                self.udp_association_index.remove(&state.key);
                if !self
                    .udp_association_index
                    .keys()
                    .any(|key| key.site == state.key.site && key.client == state.key.client)
                {
                    self.udp_user_cache
                        .remove(&(state.key.site, state.key.client));
                }
                self.udp_queued_bytes = state
                    .upload_queue
                    .iter()
                    .fold(self.udp_queued_bytes, |total, upload| {
                        total.saturating_sub(upload.len())
                    });
                {
                    let user = &mut self.sites[state.key.site].users[state.user];
                    user.active = user.active.saturating_sub(1);
                    if state.device_admitted {
                        let remove = if let Some(count) = user.device_ips.get_mut(&state.peer_ip) {
                            *count = count.saturating_sub(1);
                            *count == 0
                        } else {
                            false
                        };
                        if remove {
                            user.device_ips.remove(&state.peer_ip);
                        }
                    }
                }
                self.sites[state.key.site].prune_retired();
                self.free_udp_associations.push(identifier);
                self.active_udp_associations = self.active_udp_associations.saturating_sub(1);
            }

            let retired: Vec<_> = self
                .connections
                .iter()
                .enumerate()
                .skip(1)
                .filter_map(|(identifier, state)| {
                    state
                        .as_ref()
                        .filter(|state| state.closing && state.inflight == 0)
                        .map(|_| identifier)
                })
                .collect();
            for identifier in retired {
                let Some(state) = self.connections[identifier].take() else {
                    continue;
                };
                if let Some(user_index) = state.user {
                    {
                        let user = &mut self.sites[state.site].users[user_index];
                        user.active = user.active.saturating_sub(1);
                        if state.device_admitted {
                            let remove =
                                if let Some(count) = user.device_ips.get_mut(&state.peer_ip) {
                                    *count = count.saturating_sub(1);
                                    *count == 0
                                } else {
                                    false
                                };
                            if remove {
                                user.device_ips.remove(&state.peer_ip);
                            }
                        }
                    }
                    self.sites[state.site].prune_retired();
                }
                unregister_file(ring, state.inbound_slot)?;
                unregister_file(ring, state.outbound_slot)?;
                self.free_connections.push(identifier);
                self.active_connections = self.active_connections.saturating_sub(1);
            }
        }
        self.arm_accepts(pending);
        self.arm_udp_listeners(pending);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypted_udp_packet(
        key: [u8; 16],
        salt: [u8; SALT_LEN],
        target: SocketAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let SocketAddr::V4(target) = target else {
            panic!("IPv4 fixture required")
        };
        let mut packet = vec![0u8; SALT_LEN + UDP_IPV4_HEADER_LEN + payload.len() + TAG_LEN];
        packet[..SALT_LEN].copy_from_slice(&salt);
        packet[SALT_LEN] = 1;
        packet[SALT_LEN + 1..SALT_LEN + 5].copy_from_slice(&target.ip().octets());
        packet[SALT_LEN + 5..SALT_LEN + 7].copy_from_slice(&target.port().to_be_bytes());
        packet[SALT_LEN + 7..SALT_LEN + 7 + payload.len()].copy_from_slice(payload);
        let mut cipher = Cipher::new(KIND, &key, &salt);
        cipher.encrypt_packet(&mut packet[SALT_LEN..]);
        packet
    }

    #[test]
    fn replay_is_scoped_to_user() {
        let mut replay = ReplayFilter::new(16, Duration::from_secs(60));
        let salt = [7u8; SALT_LEN];
        assert!(!replay.check_and_add([1u8; 16], salt));
        assert!(replay.check_and_add([1u8; 16], salt));
        assert!(!replay.check_and_add([2u8; 16], salt));
    }

    #[test]
    fn udp_authentication_preserves_payload_and_scopes_replay_to_user() {
        let mut site = test_site();
        let first = site.live_users[0];
        let second = site.live_users[1];
        let salt = [0x5a; SALT_LEN];
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19091);
        let packet = encrypted_udp_packet(site.users[first].key, salt, target, b"payload");
        let decoded = decrypt_udp_packet(&packet, &mut site, None).expect("first UDP packet");
        assert_eq!(decoded.user, first);
        assert_eq!(decoded.target, target);
        assert_eq!(&*decoded.payload, b"payload");
        assert!(decrypt_udp_packet(&packet, &mut site, Some(first)).is_err());

        let other = encrypted_udp_packet(site.users[second].key, salt, target, b"other");
        let decoded = decrypt_udp_packet(&other, &mut site, None).expect("cross-user salt");
        assert_eq!(decoded.user, second);
        assert_eq!(&*decoded.payload, b"other");
    }

    #[test]
    fn udp_authentication_rejects_tampering() {
        let mut site = test_site();
        let user = site.live_users[0];
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19091);
        let mut packet =
            encrypted_udp_packet(site.users[user].key, [0x33; SALT_LEN], target, b"payload");
        packet[SALT_LEN + 3] ^= 1;
        assert!(decrypt_udp_packet(&packet, &mut site, None).is_err());
    }

    #[test]
    fn replay_window_retains_one_previous_generation() {
        let window = Duration::from_secs(60);
        let mut replay = ReplayFilter::new(16, window);
        let started = replay.rotated_at;
        let credential = [1u8; 16];
        let salt = [2u8; SALT_LEN];

        assert!(!replay.check_and_add_at(credential, salt, started));
        assert!(replay.check_and_add_at(credential, salt, started + window));
        assert!(!replay.check_and_add_at(credential, salt, started + window.saturating_mul(2)));
    }

    #[test]
    fn replay_capacity_fails_closed() {
        let mut replay = ReplayFilter::new(2, Duration::from_secs(60));
        assert!(!replay.check_and_add([1u8; 16], [1u8; SALT_LEN]));
        assert!(!replay.check_and_add([1u8; 16], [2u8; SALT_LEN]));
        assert!(replay.check_and_add([1u8; 16], [3u8; SALT_LEN]));
        assert_eq!(replay.current.len(), 2);
    }

    #[test]
    fn outgoing_salt_is_registered_in_replay_window() {
        let mut replay = ReplayFilter::new(16, Duration::from_secs(60));
        let credential = [4u8; 16];
        let salt = replay.generate_unique_salt(credential).unwrap();
        assert!(replay.check_and_add(credential, salt));
        assert!(!replay.check_and_add([5u8; 16], salt));
    }

    #[test]
    fn outgoing_salt_generation_fails_closed_at_capacity() {
        let mut replay = ReplayFilter::new(1, Duration::from_secs(60));
        assert!(!replay.check_and_add([1u8; 16], [1u8; SALT_LEN]));
        let error = replay.generate_unique_salt([2u8; 16]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn replay_handles_one_hundred_thousand_unique_salts() {
        const COUNT: usize = 100_000;
        let mut replay = ReplayFilter::new(COUNT, Duration::from_secs(60));
        let credential = [9u8; 16];
        for value in 0..COUNT as u64 {
            let mut salt = [0u8; SALT_LEN];
            salt[..8].copy_from_slice(&value.to_le_bytes());
            salt[8..].copy_from_slice(&(!value).to_le_bytes());
            assert!(!replay.check_and_add(credential, salt));
        }
        assert_eq!(replay.current.len(), COUNT);
        let mut duplicate = [0u8; SALT_LEN];
        duplicate[..8].copy_from_slice(&42u64.to_le_bytes());
        duplicate[8..].copy_from_slice(&(!42u64).to_le_bytes());
        assert!(replay.check_and_add(credential, duplicate));
        assert!(replay.check_and_add(credential, [0x55; SALT_LEN]));
    }

    fn test_site() -> SiteState {
        let mut site = SiteState::new(1_000_000, "", 5, false);
        site.replace_users(vec![
            NormalizedUser {
                uid: 1,
                password: "first-password".to_owned(),
            },
            NormalizedUser {
                uid: 2,
                password: "second-password".to_owned(),
            },
        ])
        .unwrap();
        site
    }

    #[test]
    fn unchanged_user_reuses_slot_and_changed_credential_retires() {
        let mut site = test_site();
        let unchanged = site.live_users[0];
        let changed = site.live_users[1];
        let (live, retired) = site
            .replace_users(vec![
                NormalizedUser {
                    uid: 1,
                    password: "first-password".to_owned(),
                },
                NormalizedUser {
                    uid: 2,
                    password: "changed-password".to_owned(),
                },
            ])
            .unwrap();
        assert_eq!(live, 2);
        assert_eq!(retired, 0, "inactive empty retired slot should prune");
        assert_eq!(site.live_users[0], unchanged);
        assert_ne!(site.live_users[1], changed);
        assert_eq!(site.users[changed].state, UserSlotState::Free);
    }

    #[test]
    fn retiring_user_preserves_late_traffic_until_connection_closes() {
        let mut site = test_site();
        let removed = site.live_users[1];
        site.users[removed].active = 1;
        site.users[removed].upload = 42;
        let (_, retired) = site
            .replace_users(vec![NormalizedUser {
                uid: 1,
                password: "first-password".to_owned(),
            }])
            .unwrap();
        assert_eq!(retired, 1);

        assert_eq!(
            site.take_traffic(),
            vec![TrafficRecord {
                uid: 2,
                upload: 42,
                download: 0,
            }]
        );
        assert_eq!(site.users[removed].state, UserSlotState::Retired);
        site.users[removed].download = 17;
        site.users[removed].active = 0;
        assert_eq!(
            site.take_traffic(),
            vec![TrafficRecord {
                uid: 2,
                upload: 0,
                download: 17,
            }]
        );
        assert_eq!(site.users[removed].state, UserSlotState::Free);
    }

    #[test]
    fn failed_submit_restore_survives_slot_cleanup() {
        let mut site = test_site();
        let removed = site.live_users[0];
        site.users[removed].upload = 123;
        let traffic = site.take_traffic();
        site.restore_traffic(traffic);
        site.replace_users(Vec::new()).unwrap();
        assert_eq!(site.users[removed].state, UserSlotState::Free);
        assert_eq!(
            site.take_traffic(),
            vec![TrafficRecord {
                uid: 1,
                upload: 123,
                download: 0,
            }]
        );
    }

    #[test]
    fn invalid_update_does_not_replace_live_users() {
        let mut site = test_site();
        let original = site.live_users.clone();
        let error = site
            .replace_users(vec![
                NormalizedUser {
                    uid: 10,
                    password: "duplicate-key".to_owned(),
                },
                NormalizedUser {
                    uid: 11,
                    password: "duplicate-key".to_owned(),
                },
            ])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(site.live_users, original);
    }

    #[test]
    fn policy_update_is_transactional_and_updates_existing_users() {
        let mut site = test_site();
        site.update_policy(2_000_000, 7, vec![r"^tcp:blocked\.invalid:443$".into()])
            .expect("valid SS policy");
        assert_eq!(site.speed_bytes_per_second, 2_000_000);
        assert_eq!(site.device_limit, 7);
        assert!(site
            .rules
            .as_ref()
            .expect("rules")
            .is_match("tcp:blocked.invalid:443"));
        assert_eq!(site.users[site.live_users[0]].limiter.rate, 2_000_000.0);

        let previous_rate = site.speed_bytes_per_second;
        let previous_limit = site.device_limit;
        assert!(site.update_policy(3_000_000, 9, vec!["[".into()]).is_err());
        assert_eq!(site.speed_bytes_per_second, previous_rate);
        assert_eq!(site.device_limit, previous_limit);
    }

    #[test]
    fn parses_ipv4_target() {
        let payload = [1, 127, 0, 0, 1, 0x4a, 0x92];
        let (target, host, consumed) = parse_target(&payload).expect("target");
        assert_eq!(target, "127.0.0.1:19090".parse().unwrap());
        assert_eq!(host, "127.0.0.1");
        assert_eq!(consumed, payload.len());
    }

    #[test]
    fn parses_domain_and_ipv6_targets() {
        let mut domain = vec![3, 9];
        domain.extend_from_slice(b"localhost");
        domain.extend_from_slice(&19090u16.to_be_bytes());
        let (target, host, consumed) = parse_target(&domain).expect("domain target");
        assert_eq!(host, "localhost");
        assert_eq!(target.port(), 19090);
        assert_eq!(consumed, domain.len());

        let mut ipv6 = vec![4];
        ipv6.extend_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        ipv6.extend_from_slice(&19091u16.to_be_bytes());
        let (target, host, consumed) = parse_target(&ipv6).expect("IPv6 target");
        assert_eq!(target, "[2001:db8::7]:19091".parse().unwrap());
        assert_eq!(host, "2001:db8::7");
        assert_eq!(consumed, ipv6.len());
    }

    #[test]
    fn token_bucket_preserves_future_debt() {
        let mut limiter = TokenBucket::new(1_000);
        assert_eq!(limiter.reserve(1_000), None);
        let first = limiter.reserve(500).expect("first delay");
        let second = limiter.reserve(500).expect("second delay");
        assert!(first >= Duration::from_millis(490));
        assert!(second >= Duration::from_millis(990));
        assert!(second > first);
    }

    #[test]
    fn limiter_reservation_does_not_exceed_one_second_burst() {
        let limiter = TokenBucket::new(1_000);
        assert_eq!(limiter.reservation(), 1_000);
        let limiter = TokenBucket::new(1_000_000);
        assert_eq!(limiter.reservation(), LIMITER_RESERVATION);
    }
}
