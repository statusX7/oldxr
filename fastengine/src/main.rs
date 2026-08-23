mod accounting;
mod codec;
mod diagnostics;
mod netaddr;
mod routing;
mod sniff;
mod ss;
mod timeout;

use accounting::complete_record_write;
use codec::{
    Command as VmessCommand, Credentials, DecodeResult, Handshake, PaddingRandom, Session,
};
use diagnostics::{connection_error, ErrorScope};
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use netaddr::{peer_ip, socket_domain, RawSocketAddress, ResolvedTarget};
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use sniff::{Decision as SniffDecision, State as SniffState};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::ptr;
use std::sync::atomic::{fence, AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use timeout::{TcpTimeoutState, TcpTimeouts};
use uuid::Uuid;

const RING_ENTRIES: u32 = 4096;
const MAX_CONNECTIONS: usize = 4096;
const VMESS_FIXED_FILE_SLOTS: u32 = (MAX_CONNECTIONS * 2 + 2) as u32;
const FIXED_FILE_SLOTS: u32 = VMESS_FIXED_FILE_SLOTS + ss::FILE_SLOT_COUNT;
// The local buffer is used for the handshake and fragmented-frame fallback.
// Steady traffic arrives in 9 KiB provided buffers and bypasses this storage.
const CLIENT_INPUT_SIZE: usize = 18 * 1024;
const UPLOAD_BUFFER_GROUP: u16 = 1;
const UPLOAD_BUFFER_COUNT: u16 = 1024;
const UPLOAD_BUFFER_SIZE: usize = 9 * 1024;
const DOWNLOAD_BUFFER_GROUP: u16 = 2;
const DOWNLOAD_BUFFER_COUNT: u16 = 1024;
// XUDP may prepend up to a domain-sized metadata frame before VMess adds its
// response header and chunk length. Kernel reads begin after this headroom.
const DOWNLOAD_HEADROOM: usize = 384;
const DOWNLOAD_PAYLOAD_SIZE: usize = 8192;
const DOWNLOAD_BUFFER_SIZE: usize = DOWNLOAD_HEADROOM + DOWNLOAD_PAYLOAD_SIZE + 16 + 63;
const LIMITER_RESERVATION: usize = 64 * 1024;
const MULTISHOT_SAFE_RATE: f64 = 64.0 * 1024.0 * 1024.0;
const SNIFF_BUFFER_MAX: usize = 32 * 1024;

const OP_ACCEPT: u8 = 1;
const OP_RECV_CLIENT: u8 = 2;
const OP_CONNECT_TARGET: u8 = 3;
const OP_SEND_TARGET: u8 = 4;
const OP_RECV_TARGET: u8 = 5;
const OP_SEND_CLIENT: u8 = 6;
const OP_ADMIN: u8 = 7;
const OP_CANCEL_CLIENT_RECV: u8 = 8;
const OP_CANCEL_TARGET_RECV: u8 = 9;
const TIMER_UPLOAD: u8 = 1;
const TIMER_DOWNLOAD: u8 = 2;
const ADMIN_MAX_LINE: u64 = 4 * 1024 * 1024;
static VMESS_CLOSE_PENDING: AtomicBool = AtomicBool::new(false);
static VMESS_UPLOAD_BUFFER_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static VMESS_DOWNLOAD_BUFFER_FALLBACKS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IoBackend {
    UringAdvanced,
    UringCompat,
    Epoll,
}

impl IoBackend {
    fn name(self) -> &'static str {
        match self {
            Self::UringAdvanced => "io_uring-advanced",
            Self::UringCompat => "io_uring-compat",
            Self::Epoll => "epoll",
        }
    }

    fn fixed_files(self) -> bool {
        self == Self::UringAdvanced
    }
}

enum IoEntry {
    Uring(squeue::Entry),
    Poll {
        descriptor: RawFd,
        events: i16,
        user_data: u64,
    },
    CancelPoll {
        target: u64,
        user_data: u64,
    },
    Immediate {
        result: i32,
        user_data: u64,
    },
}

impl IoEntry {
    fn uring(entry: squeue::Entry) -> Self {
        Self::Uring(entry)
    }

    fn poll(descriptor: RawFd, events: i16) -> Self {
        Self::Poll {
            descriptor,
            events,
            user_data: 0,
        }
    }

    fn cancel_poll(target: u64) -> Self {
        Self::CancelPoll {
            target,
            user_data: 0,
        }
    }

    fn immediate(result: i32) -> Self {
        Self::Immediate {
            result,
            user_data: 0,
        }
    }

    fn user_data(mut self, value: u64) -> Self {
        match &mut self {
            Self::Uring(entry) => *entry = entry.clone().user_data(value),
            Self::Poll { user_data, .. }
            | Self::CancelPoll { user_data, .. }
            | Self::Immediate { user_data, .. } => *user_data = value,
        }
        self
    }

    fn get_user_data(&self) -> u64 {
        match self {
            Self::Uring(entry) => entry.get_user_data(),
            Self::Poll { user_data, .. }
            | Self::CancelPoll { user_data, .. }
            | Self::Immediate { user_data, .. } => *user_data,
        }
    }
}

#[derive(Deserialize)]
struct Config {
    address: String,
    protocol: Protocol,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum EngineConfigFile {
    Normalized {
        listeners: Vec<Config>,
        routing: routing::PlanConfig,
    },
    Legacy(Vec<Config>),
}

#[derive(Deserialize)]
struct Protocol {
    #[serde(rename = "type")]
    kind: String,
    user_ids: Vec<String>,
    #[serde(default)]
    sniffing: bool,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum AdminRequest {
    Ping,
    VmessStatus,
    ReplaceVmessUsers {
        site: usize,
        users: Vec<VmessNormalizedUser>,
    },
    TakeVmessTraffic {
        site: usize,
    },
    RestoreVmessTraffic {
        site: usize,
        traffic: Vec<VmessTrafficRecord>,
    },
    UpdateVmessPolicy {
        site: usize,
        speed_bytes_per_second: u64,
        device_limit: usize,
        rules: Vec<String>,
    },
    SsStatus,
    ReplaceSsUsers {
        site: usize,
        users: Vec<ss::NormalizedUser>,
    },
    TakeSsTraffic {
        site: usize,
    },
    RestoreSsTraffic {
        site: usize,
        traffic: Vec<ss::TrafficRecord>,
    },
    UpdateSsPolicy {
        site: usize,
        speed_bytes_per_second: u64,
        device_limit: usize,
        rules: Vec<String>,
    },
}

struct AdminCommand {
    request: AdminRequest,
    response: SyncSender<Result<serde_json::Value, String>>,
}

struct AdminControl {
    receiver: Receiver<AdminCommand>,
    eventfd: OwnedFd,
    event_value: Box<u64>,
}

struct ListenerState {
    socket: TcpListener,
    credentials: Credentials,
    users: Vec<UserRuntime>,
    live_users: Vec<usize>,
    free_users: Vec<usize>,
    pending_traffic: HashMap<u64, (u64, u64)>,
    speed_bytes_per_second: u64,
    device_limit: usize,
    rules: Option<RegexSet>,
    device_rejects: u64,
    rule_rejects: u64,
    sniffing: bool,
}

#[derive(Deserialize)]
struct VmessNormalizedUser {
    uid: u64,
    id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct VmessTrafficRecord {
    uid: u64,
    upload: u64,
    download: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VmessUserSlotState {
    Live,
    Retired,
    Free,
}

#[derive(Clone, Copy)]
struct Features {
    traffic: bool,
    limiter: bool,
    device: bool,
    rule: bool,
}

impl Features {
    fn parse(value: &str) -> io::Result<Self> {
        let features = match value {
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
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--features must be none, traffic, traffic-limiter, traffic-limiter-device, or full",
                ));
            }
        };
        Ok(features)
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

    fn requires_paced_io(&self) -> bool {
        self.rate > 0.0 && self.rate < MULTISHOT_SAFE_RATE
    }

    fn update_rate(&mut self, bytes_per_second: u64) {
        *self = Self::new(bytes_per_second);
    }
}

fn compile_rules(rules: &[String]) -> io::Result<Option<RegexSet>> {
    if rules.len() > 4096 || rules.iter().any(|rule| rule.len() > 8192) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VMess rule set exceeds the bounded size",
        ));
    }
    if rules.is_empty() {
        return Ok(None);
    }
    RegexSet::new(rules)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn vmess_user_runtime(uid: u64, id: Uuid, speed_bytes_per_second: u64) -> UserRuntime {
    UserRuntime {
        uid,
        id,
        upload: 0,
        download: 0,
        active: 0,
        limiter: TokenBucket::new(speed_bytes_per_second),
        device_ips: HashMap::new(),
        state: VmessUserSlotState::Live,
    }
}

impl ListenerState {
    fn new(
        socket: TcpListener,
        user_ids: Vec<String>,
        speed_bytes_per_second: u64,
        device_limit: usize,
        sniffing: bool,
    ) -> io::Result<Self> {
        let mut state = Self {
            socket,
            credentials: Credentials::new(&[])?,
            users: Vec::new(),
            live_users: Vec::new(),
            free_users: Vec::new(),
            pending_traffic: HashMap::new(),
            speed_bytes_per_second,
            device_limit,
            rules: None,
            device_rejects: 0,
            rule_rejects: 0,
            sniffing,
        };
        state.replace_users(
            user_ids
                .into_iter()
                .enumerate()
                .map(|(index, id)| VmessNormalizedUser {
                    uid: index as u64 + 1,
                    id,
                })
                .collect(),
        )?;
        Ok(state)
    }

    fn update_policy(
        &mut self,
        speed_bytes_per_second: u64,
        device_limit: usize,
        rules: Vec<String>,
    ) -> io::Result<()> {
        let compiled = compile_rules(&rules)?;
        self.speed_bytes_per_second = speed_bytes_per_second;
        self.device_limit = device_limit;
        self.rules = compiled;
        for user in &mut self.users {
            if user.state != VmessUserSlotState::Free {
                user.limiter.update_rate(speed_bytes_per_second);
            }
        }
        Ok(())
    }

    fn allocate_user(&mut self, uid: u64, id: Uuid) -> usize {
        let user = vmess_user_runtime(uid, id, self.speed_bytes_per_second);
        if let Some(index) = self.free_users.pop() {
            self.users[index] = user;
            index
        } else {
            let index = self.users.len();
            self.users.push(user);
            index
        }
    }

    fn replace_users(&mut self, users: Vec<VmessNormalizedUser>) -> io::Result<(usize, usize)> {
        let mut normalized = Vec::with_capacity(users.len());
        let mut seen_uids = HashSet::with_capacity(users.len());
        let mut seen_ids = HashSet::with_capacity(users.len());
        for user in users {
            let id = Uuid::parse_str(&user.id)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            if !seen_uids.insert(user.uid) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VMess update has a duplicate UID",
                ));
            }
            if !seen_ids.insert(id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VMess update has duplicate credentials",
                ));
            }
            normalized.push((user.uid, id));
        }

        let old_live = mem::take(&mut self.live_users);
        let old_by_uid: HashMap<u64, usize> = old_live
            .iter()
            .map(|&index| (self.users[index].uid, index))
            .collect();
        let mut reused = HashSet::with_capacity(normalized.len());
        let mut new_live = Vec::with_capacity(normalized.len());
        for (uid, id) in normalized {
            if let Some(&index) = old_by_uid.get(&uid) {
                if self.users[index].id == id {
                    reused.insert(index);
                    new_live.push(index);
                    continue;
                }
            }
            new_live.push(self.allocate_user(uid, id));
        }
        for index in old_live {
            if !reused.contains(&index) {
                self.users[index].state = VmessUserSlotState::Retired;
            }
        }
        self.live_users = new_live;
        let indexed_credentials: Vec<_> = self
            .live_users
            .iter()
            .map(|&index| (index, self.users[index].id))
            .collect();
        self.credentials.replace(&indexed_credentials);
        self.prune_retired();
        Ok((self.live_users.len(), self.retired_users()))
    }

    fn retired_users(&self) -> usize {
        self.users
            .iter()
            .filter(|user| user.state == VmessUserSlotState::Retired)
            .count()
    }

    fn take_traffic(&mut self) -> Vec<VmessTrafficRecord> {
        let mut totals = BTreeMap::<u64, (u64, u64)>::new();
        for (uid, traffic) in self.pending_traffic.drain() {
            totals.insert(uid, traffic);
        }
        for user in &mut self.users {
            if user.state == VmessUserSlotState::Free {
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
            .map(|(uid, (upload, download))| VmessTrafficRecord {
                uid,
                upload,
                download,
            })
            .collect()
    }

    fn restore_traffic(&mut self, traffic: Vec<VmessTrafficRecord>) {
        for record in traffic {
            let total = self.pending_traffic.entry(record.uid).or_default();
            total.0 = total.0.saturating_add(record.upload);
            total.1 = total.1.saturating_add(record.download);
        }
    }

    fn prune_retired(&mut self) {
        for (index, user) in self.users.iter_mut().enumerate() {
            if user.state != VmessUserSlotState::Retired
                || user.active != 0
                || user.upload != 0
                || user.download != 0
            {
                continue;
            }
            user.uid = 0;
            user.id = Uuid::nil();
            user.device_ips = HashMap::new();
            user.state = VmessUserSlotState::Free;
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

struct UserRuntime {
    uid: u64,
    id: Uuid,
    upload: u64,
    download: u64,
    active: u32,
    limiter: TokenBucket,
    device_ips: HashMap<IpAddr, u32>,
    state: VmessUserSlotState,
}

struct DownloadBufferRing {
    entries: *mut types::BufRingEntry,
    buffers: Vec<Box<[u8; DOWNLOAD_BUFFER_SIZE]>>,
    tail: u16,
    mask: u16,
}

impl DownloadBufferRing {
    fn new(ring: &IoUring) -> io::Result<Self> {
        let ring_bytes = DOWNLOAD_BUFFER_COUNT as usize * mem::size_of::<types::BufRingEntry>();
        let mut allocation = ptr::null_mut();
        let result = unsafe { libc::posix_memalign(&mut allocation, 4096, ring_bytes) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        unsafe { ptr::write_bytes(allocation, 0, ring_bytes) };
        let entries = allocation.cast::<types::BufRingEntry>();
        unsafe {
            ring.submitter().register_buf_ring_with_flags(
                entries as u64,
                DOWNLOAD_BUFFER_COUNT,
                DOWNLOAD_BUFFER_GROUP,
                0,
            )?;
        }
        let buffers = (0..DOWNLOAD_BUFFER_COUNT)
            .map(|_| Box::new([0; DOWNLOAD_BUFFER_SIZE]))
            .collect();
        let mut provided = Self {
            entries,
            buffers,
            tail: 0,
            mask: DOWNLOAD_BUFFER_COUNT - 1,
        };
        for id in 0..DOWNLOAD_BUFFER_COUNT {
            provided.add_unpublished(id);
        }
        provided.publish();
        Ok(provided)
    }

    fn compat() -> Self {
        Self {
            entries: ptr::null_mut(),
            buffers: Vec::new(),
            tail: 0,
            mask: 0,
        }
    }

    fn add_unpublished(&mut self, id: u16) {
        let index = self.tail & self.mask;
        let entry = unsafe { &mut *self.entries.add(index as usize) };
        entry.set_addr(unsafe {
            self.buffers[id as usize]
                .as_mut_ptr()
                .add(DOWNLOAD_HEADROOM) as u64
        });
        entry.set_len(DOWNLOAD_PAYLOAD_SIZE as u32);
        entry.set_bid(id);
        self.tail = self.tail.wrapping_add(1);
    }

    fn publish(&self) {
        fence(Ordering::Release);
        unsafe {
            ptr::write_volatile(
                types::BufRingEntry::tail(self.entries) as *mut u16,
                self.tail,
            )
        };
    }

    fn release(&mut self, id: u16) {
        if self.entries.is_null() {
            debug_assert!(false, "compat backend returned a download buffer ID");
            return;
        }
        self.add_unpublished(id);
        self.publish();
    }

    fn bytes(&self, id: u16) -> &[u8; DOWNLOAD_BUFFER_SIZE] {
        &self.buffers[id as usize]
    }

    fn bytes_mut(&mut self, id: u16) -> &mut [u8; DOWNLOAD_BUFFER_SIZE] {
        &mut self.buffers[id as usize]
    }
}

struct UploadBufferRing {
    entries: *mut types::BufRingEntry,
    buffers: Vec<Box<[u8; UPLOAD_BUFFER_SIZE]>>,
    tail: u16,
    mask: u16,
}

impl UploadBufferRing {
    fn new(ring: &IoUring) -> io::Result<Self> {
        let ring_bytes = UPLOAD_BUFFER_COUNT as usize * mem::size_of::<types::BufRingEntry>();
        let mut allocation = ptr::null_mut();
        let result = unsafe { libc::posix_memalign(&mut allocation, 4096, ring_bytes) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        unsafe { ptr::write_bytes(allocation, 0, ring_bytes) };
        let entries = allocation.cast::<types::BufRingEntry>();
        unsafe {
            ring.submitter().register_buf_ring_with_flags(
                entries as u64,
                UPLOAD_BUFFER_COUNT,
                UPLOAD_BUFFER_GROUP,
                0,
            )?;
        }
        let buffers = (0..UPLOAD_BUFFER_COUNT)
            .map(|_| Box::new([0; UPLOAD_BUFFER_SIZE]))
            .collect();
        let mut provided = Self {
            entries,
            buffers,
            tail: 0,
            mask: UPLOAD_BUFFER_COUNT - 1,
        };
        for id in 0..UPLOAD_BUFFER_COUNT {
            provided.add_unpublished(id);
        }
        provided.publish();
        Ok(provided)
    }

    fn compat() -> Self {
        Self {
            entries: ptr::null_mut(),
            buffers: Vec::new(),
            tail: 0,
            mask: 0,
        }
    }

    fn add_unpublished(&mut self, id: u16) {
        let index = self.tail & self.mask;
        let entry = unsafe { &mut *self.entries.add(index as usize) };
        entry.set_addr(self.buffers[id as usize].as_mut_ptr() as u64);
        entry.set_len(UPLOAD_BUFFER_SIZE as u32);
        entry.set_bid(id);
        self.tail = self.tail.wrapping_add(1);
    }

    fn publish(&self) {
        fence(Ordering::Release);
        unsafe {
            ptr::write_volatile(
                types::BufRingEntry::tail(self.entries) as *mut u16,
                self.tail,
            )
        };
    }

    fn release(&mut self, id: u16) {
        if self.entries.is_null() {
            debug_assert!(false, "compat backend returned an upload buffer ID");
            return;
        }
        self.add_unpublished(id);
        self.publish();
    }

    fn bytes(&self, id: u16) -> &[u8; UPLOAD_BUFFER_SIZE] {
        &self.buffers[id as usize]
    }

    fn bytes_mut(&mut self, id: u16) -> &mut [u8; UPLOAD_BUFFER_SIZE] {
        &mut self.buffers[id as usize]
    }
}

#[derive(Default)]
struct EpollInterest {
    read: Option<u64>,
    write: Option<u64>,
}

struct EpollReactor {
    descriptor: OwnedFd,
    interests: HashMap<RawFd, EpollInterest>,
    tags: HashMap<u64, (RawFd, bool)>,
}

impl EpollReactor {
    fn new() -> io::Result<Self> {
        let descriptor = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            descriptor: unsafe { OwnedFd::from_raw_fd(descriptor) },
            interests: HashMap::new(),
            tags: HashMap::new(),
        })
    }

    fn update_registration(&self, descriptor: RawFd, add: bool) -> io::Result<()> {
        let interest = self
            .interests
            .get(&descriptor)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "epoll interest disappeared"))?;
        let mut events = (libc::EPOLLONESHOT | libc::EPOLLERR | libc::EPOLLHUP) as u32;
        if interest.read.is_some() {
            events |= (libc::EPOLLIN | libc::EPOLLRDHUP) as u32;
        }
        if interest.write.is_some() {
            events |= libc::EPOLLOUT as u32;
        }
        let mut event = libc::epoll_event {
            events,
            u64: descriptor as u64,
        };
        let operation = if add {
            libc::EPOLL_CTL_ADD
        } else {
            libc::EPOLL_CTL_MOD
        };
        let result = unsafe {
            libc::epoll_ctl(
                self.descriptor.as_raw_fd(),
                operation,
                descriptor,
                &mut event,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn add(&mut self, descriptor: RawFd, events: i16, user_data: u64) -> io::Result<()> {
        let read = events & libc::POLLIN != 0;
        let write = events & libc::POLLOUT != 0;
        if read == write {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "epoll request must contain exactly one readiness direction",
            ));
        }
        if self.tags.contains_key(&user_data) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "epoll user_data is already armed",
            ));
        }
        let add = !self.interests.contains_key(&descriptor);
        let interest = self.interests.entry(descriptor).or_default();
        let slot = if read {
            &mut interest.read
        } else {
            &mut interest.write
        };
        if slot.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "epoll descriptor direction is already armed",
            ));
        }
        *slot = Some(user_data);
        self.tags.insert(user_data, (descriptor, read));
        if let Err(error) = self.update_registration(descriptor, add) {
            self.tags.remove(&user_data);
            if let Some(interest) = self.interests.get_mut(&descriptor) {
                if read {
                    interest.read = None;
                } else {
                    interest.write = None;
                }
                if interest.read.is_none() && interest.write.is_none() {
                    self.interests.remove(&descriptor);
                }
            }
            return Err(error);
        }
        Ok(())
    }

    fn cancel(&mut self, target: u64) -> io::Result<bool> {
        let Some((descriptor, read)) = self.tags.remove(&target) else {
            return Ok(false);
        };
        let Some(interest) = self.interests.get_mut(&descriptor) else {
            return Ok(false);
        };
        if read {
            interest.read = None;
        } else {
            interest.write = None;
        }
        if interest.read.is_none() && interest.write.is_none() {
            self.interests.remove(&descriptor);
            unsafe {
                libc::epoll_ctl(
                    self.descriptor.as_raw_fd(),
                    libc::EPOLL_CTL_DEL,
                    descriptor,
                    ptr::null_mut(),
                );
            }
        } else {
            self.update_registration(descriptor, false)?;
        }
        Ok(true)
    }

    fn wait(
        &mut self,
        deadline: Option<Instant>,
        completions: &mut VecDeque<(u64, i32, u32)>,
    ) -> io::Result<()> {
        let timeout = deadline.map_or(-1, |deadline| {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                0
            } else {
                remaining.as_millis().clamp(1, i32::MAX as u128) as i32
            }
        });
        let mut events: [libc::epoll_event; 256] = unsafe { mem::zeroed() };
        let count = loop {
            let result = unsafe {
                libc::epoll_wait(
                    self.descriptor.as_raw_fd(),
                    events.as_mut_ptr(),
                    events.len() as libc::c_int,
                    timeout,
                )
            };
            if result >= 0 {
                break result as usize;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        };
        for event in &events[..count] {
            let descriptor = event.u64 as RawFd;
            let flags = event.events;
            let terminal = flags & (libc::EPOLLERR | libc::EPOLLHUP) as u32 != 0;
            let readable = terminal || flags & (libc::EPOLLIN | libc::EPOLLRDHUP) as u32 != 0;
            let writable = terminal || flags & libc::EPOLLOUT as u32 != 0;
            let Some(interest) = self.interests.get_mut(&descriptor) else {
                continue;
            };
            let read = readable.then(|| interest.read.take()).flatten();
            let write = writable.then(|| interest.write.take()).flatten();
            let empty = interest.read.is_none() && interest.write.is_none();
            for user_data in [read, write].into_iter().flatten() {
                self.tags.remove(&user_data);
                completions.push_back((user_data, flags as i32, 0));
            }
            if empty {
                self.interests.remove(&descriptor);
                unsafe {
                    libc::epoll_ctl(
                        self.descriptor.as_raw_fd(),
                        libc::EPOLL_CTL_DEL,
                        descriptor,
                        ptr::null_mut(),
                    );
                }
            } else {
                self.update_registration(descriptor, false)?;
            }
        }
        Ok(())
    }
}

enum IoDriverKind {
    Uring(IoUring),
    Epoll(EpollReactor),
}

struct IoDriver {
    backend: IoBackend,
    kind: IoDriverKind,
    ready: VecDeque<(u64, i32, u32)>,
}

impl IoDriver {
    fn uring(ring: IoUring, backend: IoBackend) -> Self {
        Self {
            backend,
            kind: IoDriverKind::Uring(ring),
            ready: VecDeque::new(),
        }
    }

    fn epoll() -> io::Result<Self> {
        Ok(Self {
            backend: IoBackend::Epoll,
            kind: IoDriverKind::Epoll(EpollReactor::new()?),
            ready: VecDeque::new(),
        })
    }

    fn push(&mut self, entry: IoEntry) -> io::Result<()> {
        match (&mut self.kind, entry) {
            (IoDriverKind::Uring(ring), IoEntry::Uring(entry)) => loop {
                if unsafe { ring.submission().push(&entry) }.is_ok() {
                    return Ok(());
                }
                ring.submit()?;
            },
            (
                IoDriverKind::Uring(ring),
                IoEntry::Poll {
                    descriptor,
                    events,
                    user_data,
                },
            ) => {
                let entry = opcode::PollAdd::new(types::Fd(descriptor), events as _)
                    .build()
                    .user_data(user_data);
                loop {
                    if unsafe { ring.submission().push(&entry) }.is_ok() {
                        return Ok(());
                    }
                    ring.submit()?;
                }
            }
            (IoDriverKind::Uring(ring), IoEntry::CancelPoll { target, user_data }) => {
                let entry = opcode::PollRemove::new(target).build().user_data(user_data);
                loop {
                    if unsafe { ring.submission().push(&entry) }.is_ok() {
                        return Ok(());
                    }
                    ring.submit()?;
                }
            }
            (
                IoDriverKind::Epoll(reactor),
                IoEntry::Poll {
                    descriptor,
                    events,
                    user_data,
                },
            ) => reactor.add(descriptor, events, user_data),
            (IoDriverKind::Epoll(reactor), IoEntry::CancelPoll { target, user_data }) => {
                let result = if reactor.cancel(target)? {
                    0
                } else {
                    -libc::ENOENT
                };
                self.ready.push_back((user_data, result, 0));
                Ok(())
            }
            (_, IoEntry::Immediate { result, user_data }) => {
                self.ready.push_back((user_data, result, 0));
                Ok(())
            }
            (IoDriverKind::Epoll(_), IoEntry::Uring(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "advanced io_uring request reached epoll backend",
            )),
        }
    }

    fn submit(&mut self) -> io::Result<()> {
        if let IoDriverKind::Uring(ring) = &mut self.kind {
            ring.submit()?;
        }
        Ok(())
    }

    fn wait(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        if !self.ready.is_empty() {
            return Ok(());
        }
        match &mut self.kind {
            IoDriverKind::Uring(ring) if self.backend.fixed_files() => {
                if let Some(deadline) = deadline {
                    let wait = deadline
                        .saturating_duration_since(Instant::now())
                        .max(Duration::from_nanos(1));
                    let timespec = types::Timespec::from(wait);
                    let arguments = types::SubmitArgs::new().timespec(&timespec);
                    if let Err(error) = ring.submitter().submit_with_args(1, &arguments) {
                        if error.raw_os_error() != Some(libc::ETIME) {
                            return Err(error);
                        }
                    }
                } else {
                    ring.submit_and_wait(1)?;
                }
                Ok(())
            }
            IoDriverKind::Uring(ring) => {
                ring.submit()?;
                loop {
                    if !ring.completion().is_empty() {
                        return Ok(());
                    }
                    let timeout = deadline.map_or(-1, |deadline| {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            0
                        } else {
                            remaining.as_millis().clamp(1, i32::MAX as u128) as i32
                        }
                    });
                    let mut descriptor = libc::pollfd {
                        fd: ring.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
                    if result >= 0 {
                        return Ok(());
                    }
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
            IoDriverKind::Epoll(reactor) => reactor.wait(deadline, &mut self.ready),
        }
    }

    fn drain_completions(&mut self, completions: &mut Vec<(u64, i32, u32)>) {
        completions.extend(self.ready.drain(..));
        if let IoDriverKind::Uring(ring) = &mut self.kind {
            completions.extend(ring.completion().map(|completion| {
                (
                    completion.user_data(),
                    completion.result(),
                    completion.flags(),
                )
            }));
        }
    }

    fn register_file(&mut self, slot: u32, descriptor: RawFd) -> io::Result<()> {
        match &mut self.kind {
            IoDriverKind::Uring(ring) => ring
                .submitter()
                .register_files_update(slot, &[descriptor])
                .map(|_| ()),
            IoDriverKind::Epoll(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fixed file registration reached epoll backend",
            )),
        }
    }
}

fn advanced_io_backend() -> io::Result<(IoDriver, IoBackend, UploadBufferRing, DownloadBufferRing)>
{
    let ring = IoUring::builder()
        .setup_single_issuer()
        .setup_defer_taskrun()
        .build(RING_ENTRIES)?;
    ring.submitter().register_files_sparse(FIXED_FILE_SLOTS)?;
    let upload = UploadBufferRing::new(&ring)?;
    let download = DownloadBufferRing::new(&ring)?;
    Ok((
        IoDriver::uring(ring, IoBackend::UringAdvanced),
        IoBackend::UringAdvanced,
        upload,
        download,
    ))
}

fn compat_io_backend() -> io::Result<(IoDriver, IoBackend, UploadBufferRing, DownloadBufferRing)> {
    Ok((
        IoDriver::uring(IoUring::new(RING_ENTRIES)?, IoBackend::UringCompat),
        IoBackend::UringCompat,
        UploadBufferRing::compat(),
        DownloadBufferRing::compat(),
    ))
}

fn epoll_io_backend() -> io::Result<(IoDriver, IoBackend, UploadBufferRing, DownloadBufferRing)> {
    Ok((
        IoDriver::epoll()?,
        IoBackend::Epoll,
        UploadBufferRing::compat(),
        DownloadBufferRing::compat(),
    ))
}

fn raise_nofile_soft_limit() -> io::Result<()> {
    let required = libc::rlim_t::from(FIXED_FILE_SLOTS).saturating_add(64);
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if limit.rlim_cur >= required {
        return Ok(());
    }
    limit.rlim_cur = required.min(limit.rlim_max);
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn io_backend(
    requested: &str,
) -> io::Result<(
    IoDriver,
    IoBackend,
    UploadBufferRing,
    DownloadBufferRing,
    String,
)> {
    if requested != "uring-compat" {
        if let Err(error) = raise_nofile_soft_limit() {
            eprintln!("FastEngine could not raise RLIMIT_NOFILE for advanced io_uring: {error}");
        }
    }
    match requested {
        "auto" => match advanced_io_backend() {
            Ok((ring, backend, upload, download)) => Ok((
                ring,
                backend,
                upload,
                download,
                "advanced io_uring capability probe passed".to_owned(),
            )),
            Err(advanced_error) => {
                eprintln!(
                    "FastEngine advanced io_uring probe failed ({advanced_error}); selecting compatibility backend"
                );
                match compat_io_backend() {
                    Ok((driver, backend, upload, download)) => Ok((
                        driver,
                        backend,
                        upload,
                        download,
                        format!(
                            "advanced probe failed: {advanced_error}; readiness compatibility probe passed"
                        ),
                    )),
                    Err(compat_error) => epoll_io_backend().map(
                        |(driver, backend, upload, download)| {
                            (
                                driver,
                                backend,
                                upload,
                                download,
                                format!(
                                    "advanced probe failed: {advanced_error}; compatibility probe failed: {compat_error}; epoll probe passed"
                                ),
                            )
                        },
                    ),
                }
            }
        },
        "uring-advanced" => advanced_io_backend().map(|(ring, backend, upload, download)| {
            (
                ring,
                backend,
                upload,
                download,
                "advanced backend forced by diagnostic override".to_owned(),
            )
        }),
        "uring-compat" => compat_io_backend().map(|(ring, backend, upload, download)| {
            (
                ring,
                backend,
                upload,
                download,
                "compatibility backend forced by diagnostic override".to_owned(),
            )
        }),
        "epoll" => epoll_io_backend().map(|(driver, backend, upload, download)| {
            (
                driver,
                backend,
                upload,
                download,
                "epoll backend forced by diagnostic override".to_owned(),
            )
        }),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--io-backend must be auto, uring-advanced, uring-compat, or epoll",
        )),
    }
}

struct Connection {
    _client: OwnedFd,
    target: Option<OwnedFd>,
    client_slot: u32,
    target_slot: u32,
    fixed_files: bool,
    listener: usize,
    user: Option<usize>,
    peer_ip: IpAddr,
    target_endpoint: Option<SocketAddr>,
    target_address: Option<Box<RawSocketAddress>>,
    pending_target: Option<ResolvedTarget>,
    tcp_target: Option<ResolvedTarget>,
    sniff: SniffState,
    sniff_buffer: Vec<u8>,
    target_udp: bool,
    xudp: bool,
    xudp_session_id: u16,
    xudp_target: Option<ResolvedTarget>,
    route_protocols: u8,
    rule_checked: bool,
    session: Option<Session>,
    client_input: Box<[u8; CLIENT_INPUT_SIZE]>,
    client_start: usize,
    client_end: usize,
    upload_buffer: Option<u16>,
    upload_buffer_start: usize,
    upload_buffer_end: usize,
    upload_queue: VecDeque<(u16, usize)>,
    client_multishot_armed: bool,
    upload_start: usize,
    upload_length: usize,
    upload_offset: usize,
    upload_resume: usize,
    upload_from_sniff: bool,
    upload_budget: usize,
    download_buffer: Option<u16>,
    download_queue: VecDeque<(u16, usize)>,
    target_multishot_armed: bool,
    download_local: Option<Box<[u8; DOWNLOAD_BUFFER_SIZE]>>,
    download_local_active: bool,
    download_eof_frame: bool,
    client_output_start: usize,
    client_output_length: usize,
    client_output_offset: usize,
    download_plaintext_length: usize,
    download_budget: usize,
    upload_ready_at: Option<Instant>,
    upload_scheduled_at: Option<Instant>,
    download_ready_at: Option<Instant>,
    download_scheduled_at: Option<Instant>,
    device_admitted: bool,
    connected: bool,
    client_one_shot: bool,
    target_one_shot: bool,
    client_read_eof: bool,
    target_read_eof: bool,
    target_write_shutdown: bool,
    client_write_shutdown: bool,
    inflight: usize,
    close_cancels_queued: bool,
    closing: bool,
    failed: bool,
    generation: u64,
    timeout: TcpTimeoutState,
}

macro_rules! queue_connection {
    ($state:expr, $pending:expr, $entry:expr) => {{
        let entry = $entry;
        ($state).inflight += 1;
        ($pending).push(entry);
    }};
}

fn tag(identifier: usize, operation: u8) -> u64 {
    ((identifier as u64) << 8) | operation as u64
}

fn decode_tag(value: u64) -> (usize, u8) {
    ((value >> 8) as usize, value as u8)
}

fn notify_eventfd(eventfd: RawFd) -> io::Result<()> {
    let value = 1u64;
    let result = unsafe {
        libc::write(
            eventfd,
            (&value as *const u64).cast(),
            mem::size_of::<u64>(),
        )
    };
    if result == mem::size_of::<u64>() as isize {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(())
    } else {
        Err(error)
    }
}

fn write_admin_response(
    stream: &mut UnixStream,
    response: Result<serde_json::Value, String>,
) -> io::Result<()> {
    let value = match response {
        Ok(result) => serde_json::json!({"ok": true, "result": result}),
        Err(error) => serde_json::json!({"ok": false, "error": error}),
    };
    serde_json::to_writer(&mut *stream, &value)?;
    stream.write_all(b"\n")
}

fn handle_admin_stream(
    mut stream: UnixStream,
    sender: &mpsc::Sender<AdminCommand>,
    eventfd: RawFd,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut line = String::new();
    let count = BufReader::new(&mut stream)
        .take(ADMIN_MAX_LINE + 1)
        .read_line(&mut line)?;
    if count == 0 || count as u64 > ADMIN_MAX_LINE {
        return write_admin_response(
            &mut stream,
            Err("admin request is empty or too large".into()),
        );
    }
    let request = match serde_json::from_str::<AdminRequest>(line.trim()) {
        Ok(request) => request,
        Err(error) => return write_admin_response(&mut stream, Err(error.to_string())),
    };
    let (response_sender, response_receiver) = mpsc::sync_channel(1);
    sender
        .send(AdminCommand {
            request,
            response: response_sender,
        })
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "admin engine stopped"))?;
    notify_eventfd(eventfd)?;
    let response = response_receiver
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "admin engine timed out"))?;
    write_admin_response(&mut stream, response)
}

fn start_admin(path: &str) -> io::Result<AdminControl> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => match UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "admin socket already has a listener",
                ));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                fs::remove_file(path)?;
            }
            Err(error) => return Err(error),
        },
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "admin path exists and is not a socket",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    // Keep the eventfd blocking. A nonblocking eventfd completes an io_uring
    // read with EAGAIN whenever the control queue is empty, which turns the
    // supposedly dormant control path into a busy completion/rearm loop.
    let descriptor = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let eventfd = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let notifier_descriptor = unsafe { libc::dup(eventfd.as_raw_fd()) };
    if notifier_descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let notifier = unsafe { OwnedFd::from_raw_fd(notifier_descriptor) };
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("oldxr-fastengine-admin".to_owned())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else {
                    break;
                };
                let _ = handle_admin_stream(stream, &sender, notifier.as_raw_fd());
            }
        })?;
    Ok(AdminControl {
        receiver,
        eventfd,
        event_value: Box::new(0),
    })
}

fn admin_event_entry(control: &mut AdminControl, poll_only: bool) -> IoEntry {
    let entry = if poll_only {
        IoEntry::poll(control.eventfd.as_raw_fd(), libc::POLLIN)
    } else {
        IoEntry::uring(
            opcode::Read::new(
                types::Fd(control.eventfd.as_raw_fd()),
                (&mut *control.event_value as *mut u64).cast(),
                mem::size_of::<u64>() as u32,
            )
            .build(),
        )
    };
    entry.user_data(tag(0, OP_ADMIN))
}

fn drain_admin_event(control: &mut AdminControl) -> io::Result<()> {
    let result = unsafe {
        libc::read(
            control.eventfd.as_raw_fd(),
            (&mut *control.event_value as *mut u64).cast(),
            mem::size_of::<u64>(),
        )
    };
    if result == mem::size_of::<u64>() as isize {
        Ok(())
    } else if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short eventfd read",
        ))
    }
}

fn vmess_site_mut(listeners: &mut [ListenerState], site: usize) -> io::Result<&mut ListenerState> {
    let index = site.checked_sub(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "VMess site must be one-based")
    })?;
    listeners
        .get_mut(index)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "VMess site was not found"))
}

fn process_admin_command(
    command: AdminCommand,
    ss_engine: &mut ss::Engine,
    listeners: &mut [ListenerState],
) -> Result<(), mpsc::SendError<Result<serde_json::Value, String>>> {
    let response = match command.request {
        AdminRequest::Ping => Ok(serde_json::json!({"pong": true})),
        AdminRequest::VmessStatus => {
            let live_users: usize = listeners.iter().map(|site| site.live_users.len()).sum();
            let retired_users: usize = listeners.iter().map(ListenerState::retired_users).sum();
            let active_connections: u64 = listeners
                .iter()
                .flat_map(|site| &site.users)
                .map(|user| u64::from(user.active))
                .sum();
            let (upload, download) =
                listeners
                    .iter()
                    .fold((0u64, 0u64), |(upload, download), site| {
                        let (site_upload, site_download) = site.traffic_totals();
                        (
                            upload.saturating_add(site_upload),
                            download.saturating_add(site_download),
                        )
                    });
            let rule_rejects: u64 = listeners.iter().map(|site| site.rule_rejects).sum();
            let device_rejects: u64 = listeners.iter().map(|site| site.device_rejects).sum();
            Ok(serde_json::json!({
                "live_users": live_users,
                "retired_users": retired_users,
                "runtime_users": live_users + retired_users,
                "active_connections": active_connections,
                "upload": upload,
                "download": download,
                "device_rejects": device_rejects,
                "rule_rejects": rule_rejects,
                "upload_buffer_fallbacks": VMESS_UPLOAD_BUFFER_FALLBACKS.load(Ordering::Relaxed),
                "download_buffer_fallbacks": VMESS_DOWNLOAD_BUFFER_FALLBACKS.load(Ordering::Relaxed),
            }))
        }
        AdminRequest::ReplaceVmessUsers { site, users } => vmess_site_mut(listeners, site)
            .and_then(|state| state.replace_users(users))
            .map(|(live_users, retired_users)| {
                serde_json::json!({
                    "live_users": live_users,
                    "retired_users": retired_users,
                    "runtime_users": live_users + retired_users,
                })
            })
            .map_err(|error| error.to_string()),
        AdminRequest::TakeVmessTraffic { site } => vmess_site_mut(listeners, site)
            .and_then(|state| serde_json::to_value(state.take_traffic()).map_err(io::Error::other))
            .map_err(|error| error.to_string()),
        AdminRequest::RestoreVmessTraffic { site, traffic } => vmess_site_mut(listeners, site)
            .map(|state| {
                state.restore_traffic(traffic);
                serde_json::json!({"restored": true})
            })
            .map_err(|error| error.to_string()),
        AdminRequest::UpdateVmessPolicy {
            site,
            speed_bytes_per_second,
            device_limit,
            rules,
        } => vmess_site_mut(listeners, site)
            .and_then(|state| state.update_policy(speed_bytes_per_second, device_limit, rules))
            .map(|()| serde_json::json!({"updated": true}))
            .map_err(|error| error.to_string()),
        AdminRequest::SsStatus => {
            let status = ss_engine.status();
            Ok(serde_json::json!({
                "live_users": status.live_users,
                "retired_users": status.retired_users,
                "runtime_users": status.runtime_users,
                "open": status.open,
                "inflight": status.inflight,
                "upload": status.upload,
                "download": status.download,
                "replay_rejects": status.replay_rejects,
                "device_rejects": status.device_rejects,
                "rule_rejects": status.rule_rejects,
                "udp_input_drops": status.udp_input_drops,
                "udp_queue_drops": status.udp_queue_drops,
                "udp_listener_errors": status.udp_listener_errors,
                "udp_upload_errors": status.udp_upload_errors,
                "udp_receive_errors": status.udp_receive_errors,
                "udp_response_errors": status.udp_response_errors,
            }))
        }
        AdminRequest::ReplaceSsUsers { site, users } => ss_engine
            .replace_users(site, users)
            .map(|(live_users, retired_users)| {
                serde_json::json!({
                    "live_users": live_users,
                    "retired_users": retired_users,
                    "runtime_users": live_users + retired_users,
                })
            })
            .map_err(|error| error.to_string()),
        AdminRequest::TakeSsTraffic { site } => ss_engine
            .take_traffic(site)
            .and_then(|traffic| serde_json::to_value(traffic).map_err(io::Error::other))
            .map_err(|error| error.to_string()),
        AdminRequest::RestoreSsTraffic { site, traffic } => ss_engine
            .restore_traffic(site, traffic)
            .map(|()| serde_json::json!({"restored": true}))
            .map_err(|error| error.to_string()),
        AdminRequest::UpdateSsPolicy {
            site,
            speed_bytes_per_second,
            device_limit,
            rules,
        } => ss_engine
            .update_policy(site, speed_bytes_per_second, device_limit, rules)
            .map(|()| serde_json::json!({"updated": true}))
            .map_err(|error| error.to_string()),
    };
    command.response.send(response)
}

fn set_nodelay(descriptor: RawFd) -> io::Result<()> {
    let enabled: libc::c_int = 1;
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

fn tcp_socket(address: SocketAddr) -> io::Result<OwnedFd> {
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
    set_nodelay(descriptor.as_raw_fd())?;
    Ok(descriptor)
}

fn udp_socket(address: SocketAddr) -> io::Result<OwnedFd> {
    let descriptor = unsafe {
        libc::socket(
            socket_domain(address),
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

fn accept_entry(listener: usize, descriptor: RawFd, fixed_files: bool) -> IoEntry {
    let entry = if fixed_files {
        IoEntry::uring(
            opcode::Accept::new(types::Fd(descriptor), ptr::null_mut(), ptr::null_mut())
                .flags(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC)
                .build(),
        )
    } else {
        IoEntry::poll(descriptor, libc::POLLIN)
    };
    entry.user_data(tag(listener, OP_ACCEPT))
}

fn arm_accepts(
    listeners: &[ListenerState],
    accept_armed: &mut [bool],
    accept_armed_count: &mut usize,
    accept_cursor: &mut usize,
    active_connections: usize,
    fixed_files: bool,
    pending: &mut Vec<IoEntry>,
) {
    if listeners.is_empty() {
        return;
    }
    let capacity = MAX_CONNECTIONS.saturating_sub(1);
    if *accept_armed_count >= listeners.len()
        || active_connections + *accept_armed_count >= capacity
    {
        return;
    }
    for _ in 0..listeners.len() {
        if active_connections + *accept_armed_count >= capacity {
            break;
        }
        let listener = *accept_cursor;
        *accept_cursor = (*accept_cursor + 1) % listeners.len();
        if accept_armed[listener] {
            continue;
        }
        accept_armed[listener] = true;
        *accept_armed_count += 1;
        pending.push(accept_entry(
            listener,
            listeners[listener].socket.as_raw_fd(),
            fixed_files,
        ));
    }
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

fn timer_is_current(connections: &[Option<Connection>], entry: (Instant, usize, u64, u8)) -> bool {
    let (deadline, identifier, generation, direction) = entry;
    let Some(state) = connections.get(identifier).and_then(Option::as_ref) else {
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

fn next_deadline(
    timers: &mut BinaryHeap<Reverse<(Instant, usize, u64, u8)>>,
    connections: &[Option<Connection>],
) -> Option<Instant> {
    loop {
        let entry = timers.peek().map(|entry| entry.0)?;
        if timer_is_current(connections, entry) {
            return Some(entry.0);
        }
        timers.pop();
    }
}

fn expire_tcp_connections(
    now: Instant,
    connections: &mut [Option<Connection>],
    timeouts: TcpTimeouts,
) {
    for state in connections.iter_mut().flatten() {
        if !state.closing && state.timeout.expired(now, timeouts) {
            begin_close(state);
        }
    }
}

fn resume_due(
    now: Instant,
    timers: &mut BinaryHeap<Reverse<(Instant, usize, u64, u8)>>,
    connections: &mut [Option<Connection>],
    upload_buffers: &UploadBufferRing,
    download_buffers: &DownloadBufferRing,
    pending: &mut Vec<IoEntry>,
) {
    loop {
        let Some(Reverse(entry @ (deadline, _, _, _))) = timers.peek().copied() else {
            return;
        };
        if deadline > now {
            return;
        }
        timers.pop();
        if !timer_is_current(connections, entry) {
            continue;
        }
        let (_, identifier, generation, direction) = entry;
        let Some(state) = connections.get_mut(identifier).and_then(Option::as_mut) else {
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
                    queue_connection!(
                        state,
                        pending,
                        send_target_entry(identifier, state, upload_buffers)
                    );
                }
            }
            TIMER_DOWNLOAD => {
                state.download_ready_at = None;
                state.download_scheduled_at = None;
                if state.client_output_length != 0 {
                    queue_connection!(
                        state,
                        pending,
                        send_client_entry(identifier, state, download_buffers)
                    );
                }
            }
            _ => {}
        }
    }
}

fn recv_client_entry(identifier: usize, state: &mut Connection) -> io::Result<IoEntry> {
    if state.client_start > 0 {
        state
            .client_input
            .copy_within(state.client_start..state.client_end, 0);
        state.client_end -= state.client_start;
        state.client_start = 0;
    }
    if state.client_end == state.client_input.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VMess receive buffer exhausted",
        ));
    }
    let remaining = state.client_input.len() - state.client_end;
    state.client_multishot_armed = true;
    let buffer = unsafe { state.client_input.as_mut_ptr().add(state.client_end) };
    let entry = if state.fixed_files {
        IoEntry::uring(
            opcode::Recv::new(types::Fixed(state.client_slot), buffer, remaining as u32)
                .ioprio(1)
                .build(),
        )
    } else {
        IoEntry::poll(state._client.as_raw_fd(), libc::POLLIN)
    };
    Ok(entry.user_data(tag(identifier, OP_RECV_CLIENT)))
}

fn recv_client_multi_entry(identifier: usize, state: &Connection) -> IoEntry {
    IoEntry::uring(
        opcode::RecvMulti::new(types::Fixed(state.client_slot), UPLOAD_BUFFER_GROUP).build(),
    )
    .user_data(tag(identifier, OP_RECV_CLIENT))
}

fn connect_target_entry(identifier: usize, state: &Connection) -> io::Result<IoEntry> {
    let address = state.target_address.as_ref().expect("target address");
    let entry = if state.fixed_files {
        IoEntry::uring(
            opcode::Connect::new(
                types::Fixed(state.target_slot),
                address.as_ptr(),
                address.len(),
            )
            .build(),
        )
    } else {
        let descriptor = state.target.as_ref().expect("target socket").as_raw_fd();
        let result = unsafe { libc::connect(descriptor, address.as_ptr(), address.len()) };
        if result == 0 {
            IoEntry::immediate(0)
        } else {
            let error = io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::EINPROGRESS) | Some(libc::EALREADY) | Some(libc::EINTR)
            ) {
                return Err(error);
            }
            IoEntry::poll(descriptor, libc::POLLOUT)
        }
    };
    Ok(entry.user_data(tag(identifier, OP_CONNECT_TARGET)))
}

fn ensure_target_connect(
    identifier: usize,
    state: &mut Connection,
    site: &mut ListenerState,
    features: Features,
    router: &routing::Router,
    driver: &mut IoDriver,
    pending: &mut Vec<IoEntry>,
) -> io::Result<()> {
    if state.target.is_some() || state.target_address.is_none() {
        return Ok(());
    }
    if !state.rule_checked {
        let target = if state.target_udp {
            state.xudp_target.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing VMess UDP target")
            })?
        } else {
            state.tcp_target.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing VMess TCP target")
            })?
        };
        let network = if state.target_udp { "udp" } else { "tcp" };
        let destination = format!("{network}:{}:{}", target.host, target.address.port());
        if features.rule
            && site
                .rules
                .as_ref()
                .is_some_and(|rules| rules.is_match(&destination))
        {
            site.rule_rejects = site.rule_rejects.saturating_add(1);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VMess rule rejected target",
            ));
        }
        let routed = router.route_target(
            if state.target_udp {
                routing::NETWORK_UDP
            } else {
                routing::NETWORK_TCP
            },
            target,
            state.sniff.protocols() | state.route_protocols,
        )?;
        state.target_endpoint = Some(routed.address);
        state.target_address = Some(Box::new(RawSocketAddress::new(routed.address)));
        if state.target_udp {
            state.xudp_target = Some(routed);
        } else {
            state.tcp_target = Some(routed);
        }
        state.rule_checked = true;
    }
    let address = state
        .target_endpoint
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing target endpoint"))?;
    let target_socket = if state.target_udp {
        udp_socket(address)?
    } else {
        tcp_socket(address)?
    };
    if state.fixed_files {
        driver.register_file(state.target_slot, target_socket.as_raw_fd())?;
    }
    state.target = Some(target_socket);
    queue_connection!(state, pending, connect_target_entry(identifier, state)?);
    Ok(())
}

fn set_vmess_tcp_target(state: &mut Connection, decision: SniffDecision) -> io::Result<bool> {
    let Some(original) = state.pending_target.as_ref() else {
        return Ok(false);
    };
    let target = match decision {
        SniffDecision::NeedMore => return Ok(false),
        SniffDecision::Original => original.clone(),
        SniffDecision::Override(host) => ResolvedTarget::resolve(&host, original.address.port())?,
    };
    state.pending_target = None;
    state.target_endpoint = Some(target.address);
    state.target_address = Some(Box::new(RawSocketAddress::new(target.address)));
    state.tcp_target = Some(target);
    state.rule_checked = false;
    Ok(true)
}

fn send_target_entry(identifier: usize, state: &Connection, uploads: &UploadBufferRing) -> IoEntry {
    let remaining = state.upload_length - state.upload_offset;
    let source = if state.upload_from_sniff {
        state.sniff_buffer.as_ptr()
    } else {
        match state.upload_buffer {
            Some(buffer_id) => uploads.bytes(buffer_id).as_ptr(),
            None => state.client_input.as_ptr(),
        }
    };
    let source = unsafe { source.add(state.upload_start + state.upload_offset) };
    let entry = if state.fixed_files {
        IoEntry::uring(
            opcode::Send::new(types::Fixed(state.target_slot), source, remaining as u32)
                .ioprio(1)
                .build(),
        )
    } else {
        IoEntry::poll(
            state.target.as_ref().expect("target socket").as_raw_fd(),
            libc::POLLOUT,
        )
    };
    entry.user_data(tag(identifier, OP_SEND_TARGET))
}

fn recv_target_entry(identifier: usize, state: &mut Connection) -> IoEntry {
    state.target_multishot_armed = true;
    IoEntry::uring(
        opcode::RecvMulti::new(types::Fixed(state.target_slot), DOWNLOAD_BUFFER_GROUP).build(),
    )
    .user_data(tag(identifier, OP_RECV_TARGET))
}

fn recv_target_paced_entry(identifier: usize, state: &mut Connection) -> IoEntry {
    state.target_multishot_armed = true;
    let buffer = state
        .download_local
        .as_mut()
        .expect("paced download buffer");
    let buffer = unsafe { buffer.as_mut_ptr().add(DOWNLOAD_HEADROOM) };
    let entry = if state.fixed_files {
        IoEntry::uring(
            opcode::Recv::new(
                types::Fixed(state.target_slot),
                buffer,
                DOWNLOAD_PAYLOAD_SIZE as u32,
            )
            .ioprio(1)
            .build(),
        )
    } else {
        IoEntry::poll(
            state.target.as_ref().expect("target socket").as_raw_fd(),
            libc::POLLIN,
        )
    };
    entry.user_data(tag(identifier, OP_RECV_TARGET))
}

fn cancel_entry(
    identifier: usize,
    target_operation: u8,
    cancel_operation: u8,
    fixed_files: bool,
) -> IoEntry {
    let entry = if fixed_files {
        IoEntry::uring(opcode::AsyncCancel::new(tag(identifier, target_operation)).build())
    } else {
        IoEntry::cancel_poll(tag(identifier, target_operation))
    };
    entry.user_data(tag(identifier, cancel_operation))
}

fn send_client_entry(
    identifier: usize,
    state: &Connection,
    downloads: &DownloadBufferRing,
) -> IoEntry {
    let buffer: &[u8] = if state.download_local_active {
        state
            .download_local
            .as_deref()
            .expect("paced download buffer")
    } else {
        downloads.bytes(state.download_buffer.expect("download buffer"))
    };
    let remaining = state.client_output_length - state.client_output_offset;
    let buffer = unsafe {
        buffer
            .as_ptr()
            .add(state.client_output_start + state.client_output_offset)
    };
    let entry = if state.fixed_files {
        IoEntry::uring(
            opcode::Send::new(types::Fixed(state.client_slot), buffer, remaining as u32)
                .ioprio(1)
                .build(),
        )
    } else {
        IoEntry::poll(state._client.as_raw_fd(), libc::POLLOUT)
    };
    entry.user_data(tag(identifier, OP_SEND_CLIENT))
}

fn negative_errno() -> i32 {
    -io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn syscall_result(result: isize) -> i32 {
    if result < 0 {
        negative_errno()
    } else {
        result as i32
    }
}

fn accept_ready(descriptor: RawFd) -> i32 {
    let result = unsafe {
        libc::accept4(
            descriptor,
            ptr::null_mut(),
            ptr::null_mut(),
            libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        )
    };
    if result < 0 {
        negative_errno()
    } else {
        result
    }
}

fn connect_ready(descriptor: RawFd) -> i32 {
    let mut error = 0;
    let mut length = mem::size_of_val(&error) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut error as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result < 0 {
        negative_errno()
    } else if error == 0 {
        0
    } else {
        -error
    }
}

fn compat_vmess_result(
    operation: u8,
    state: &mut Connection,
    uploads: &UploadBufferRing,
    downloads: &DownloadBufferRing,
) -> i32 {
    match operation {
        OP_RECV_CLIENT => {
            let remaining = state.client_input.len() - state.client_end;
            syscall_result(unsafe {
                libc::recv(
                    state._client.as_raw_fd(),
                    state.client_input.as_mut_ptr().add(state.client_end).cast(),
                    remaining,
                    0,
                )
            })
        }
        OP_CONNECT_TARGET => {
            connect_ready(state.target.as_ref().expect("target socket").as_raw_fd())
        }
        OP_SEND_TARGET => {
            let remaining = state.upload_length - state.upload_offset;
            let source = if state.upload_from_sniff {
                state.sniff_buffer.as_ptr()
            } else {
                match state.upload_buffer {
                    Some(buffer_id) => uploads.bytes(buffer_id).as_ptr(),
                    None => state.client_input.as_ptr(),
                }
            };
            syscall_result(unsafe {
                libc::send(
                    state.target.as_ref().expect("target socket").as_raw_fd(),
                    source.add(state.upload_start + state.upload_offset).cast(),
                    remaining,
                    libc::MSG_NOSIGNAL,
                )
            })
        }
        OP_RECV_TARGET => {
            let buffer = state
                .download_local
                .as_mut()
                .expect("compat download buffer");
            syscall_result(unsafe {
                libc::recv(
                    state.target.as_ref().expect("target socket").as_raw_fd(),
                    buffer.as_mut_ptr().add(DOWNLOAD_HEADROOM).cast(),
                    DOWNLOAD_PAYLOAD_SIZE,
                    0,
                )
            })
        }
        OP_SEND_CLIENT => {
            let buffer: &[u8] = if state.download_local_active {
                state
                    .download_local
                    .as_deref()
                    .expect("compat download buffer")
            } else {
                downloads.bytes(state.download_buffer.expect("download buffer"))
            };
            syscall_result(unsafe {
                libc::send(
                    state._client.as_raw_fd(),
                    buffer
                        .as_ptr()
                        .add(state.client_output_start + state.client_output_offset)
                        .cast(),
                    state.client_output_length - state.client_output_offset,
                    libc::MSG_NOSIGNAL,
                )
            })
        }
        _ => 0,
    }
}

enum XudpFrame {
    Data {
        session_id: u16,
        target: Option<ResolvedTarget>,
        payload_start: usize,
        payload_length: usize,
    },
    End,
}

fn decode_xudp_frame(input: &[u8]) -> io::Result<XudpFrame> {
    if input.len() < 6 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short XUDP metadata",
        ));
    }
    let metadata_length = u16::from_be_bytes(input[..2].try_into().unwrap()) as usize;
    if metadata_length < 4 || 2 + metadata_length > input.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid XUDP metadata length",
        ));
    }
    let session_id = u16::from_be_bytes(input[2..4].try_into().unwrap());
    let status = input[4];
    let option = input[5];
    if option & 0x02 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "XUDP peer reported an error",
        ));
    }
    if status == 3 {
        return Ok(XudpFrame::End);
    }
    if !matches!(status, 1 | 2 | 4) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid XUDP session status",
        ));
    }
    let metadata_end = 2 + metadata_length;
    let mut cursor = 6;
    let target = if metadata_length > 4 {
        if cursor + 4 > metadata_end || input[cursor] != 2 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "XUDP requires a UDP destination",
            ));
        }
        cursor += 1;
        let port = u16::from_be_bytes(input[cursor..cursor + 2].try_into().unwrap());
        cursor += 2;
        let address_type = *input.get(cursor).ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "short XUDP destination")
        })?;
        cursor += 1;
        let target = match address_type {
            1 => {
                if cursor + 4 > metadata_end {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short XUDP IPv4 destination",
                    ));
                }
                let address = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(
                        input[cursor],
                        input[cursor + 1],
                        input[cursor + 2],
                        input[cursor + 3],
                    )),
                    port,
                );
                cursor += 4;
                ResolvedTarget::from_ip(address)
            }
            2 => {
                let length = *input.get(cursor).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "short XUDP domain")
                })? as usize;
                cursor += 1;
                if cursor + length > metadata_end {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short XUDP domain",
                    ));
                }
                let host = std::str::from_utf8(&input[cursor..cursor + length]).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid XUDP domain")
                })?;
                cursor += length;
                ResolvedTarget::resolve(host, port)?
            }
            3 => {
                if cursor + 16 > metadata_end {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short XUDP IPv6 destination",
                    ));
                }
                let ip = std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&input[cursor..cursor + 16]).unwrap(),
                );
                cursor += 16;
                ResolvedTarget::from_ip(SocketAddr::new(IpAddr::V6(ip), port))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported XUDP destination type",
                ));
            }
        };
        if cursor != metadata_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid XUDP destination length",
            ));
        }
        Some(target)
    } else {
        None
    };
    if option & 0x01 == 0 || status == 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XUDP frame has no payload",
        ));
    }
    if metadata_end + 2 > input.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short XUDP payload length",
        ));
    }
    let payload_length =
        u16::from_be_bytes(input[metadata_end..metadata_end + 2].try_into().unwrap()) as usize;
    let payload_start = metadata_end + 2;
    if payload_length == 0 || payload_start + payload_length != input.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid XUDP payload length",
        ));
    }
    Ok(XudpFrame::Data {
        session_id,
        target,
        payload_start,
        payload_length,
    })
}

fn prepend_xudp_response(
    output: &mut [u8],
    payload_start: usize,
    payload_length: usize,
    session_id: u16,
    target: &ResolvedTarget,
) -> io::Result<(usize, usize)> {
    let address_length = match target.address {
        SocketAddr::V4(_) => 1 + 4,
        SocketAddr::V6(_) => 1 + 16,
    };
    let metadata_length = 4 + 1 + 2 + address_length;
    let prefix_length = 2 + metadata_length + 2;
    let start = payload_start.checked_sub(prefix_length).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing XUDP response headroom",
        )
    })?;
    output[start..start + 2].copy_from_slice(&(metadata_length as u16).to_be_bytes());
    output[start + 2..start + 4].copy_from_slice(&session_id.to_be_bytes());
    output[start + 4] = 2; // Keep
    output[start + 5] = 1; // Data
    output[start + 6] = 2; // UDP
    output[start + 7..start + 9].copy_from_slice(&target.address.port().to_be_bytes());
    let address_start = start + 9;
    let address_end = match target.address {
        SocketAddr::V4(address) => {
            output[address_start] = 1;
            output[address_start + 1..address_start + 5].copy_from_slice(&address.ip().octets());
            address_start + 5
        }
        SocketAddr::V6(address) => {
            output[address_start] = 3;
            output[address_start + 1..address_start + 17].copy_from_slice(&address.ip().octets());
            address_start + 17
        }
    };
    output[address_end..payload_start].copy_from_slice(&(payload_length as u16).to_be_bytes());
    Ok((start, prefix_length + payload_length))
}

fn finish_download_encode(
    state: &mut Connection,
    output: &mut [u8],
    payload_length: usize,
    padding_random: &mut PaddingRandom,
) -> io::Result<(usize, usize)> {
    let (payload_start, framed_length) = if state.xudp {
        prepend_xudp_response(
            output,
            DOWNLOAD_HEADROOM,
            payload_length,
            state.xudp_session_id,
            state
                .xudp_target
                .as_ref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing XUDP target"))?,
        )?
    } else {
        (DOWNLOAD_HEADROOM, payload_length)
    };
    state
        .session
        .as_mut()
        .expect("VMess session")
        .finish_fixed_encode(output, payload_start, framed_length, padding_random)
}

fn next_upload_entry(
    identifier: usize,
    state: &mut Connection,
    uploads: &mut UploadBufferRing,
    user: &mut UserRuntime,
    features: Features,
) -> io::Result<Option<IoEntry>> {
    if state.upload_length != 0 {
        if state.connected && state.upload_ready_at.is_none() {
            return Ok(Some(send_target_entry(identifier, state, uploads)));
        }
        return Ok(None);
    }
    loop {
        if state.upload_buffer.is_none() && state.client_start == state.client_end {
            state.client_start = 0;
            state.client_end = 0;
            if let Some((buffer_id, length)) = state.upload_queue.pop_front() {
                state.upload_buffer = Some(buffer_id);
                state.upload_buffer_start = 0;
                state.upload_buffer_end = length;
            } else {
                if state.client_read_eof {
                    return Ok(None);
                }
                if state.client_one_shot {
                    return Ok(Some(recv_client_entry(identifier, state)?));
                }
                if state.client_multishot_armed {
                    return Ok(None);
                }
                state.client_multishot_armed = true;
                return Ok(Some(recv_client_multi_entry(identifier, state)));
            }
        }
        let result = match state.upload_buffer {
            Some(buffer_id) => state.session.as_mut().expect("VMess session").decode(
                &mut uploads.bytes_mut(buffer_id)[..],
                state.upload_buffer_start,
                state.upload_buffer_end,
            )?,
            None => state.session.as_mut().expect("VMess session").decode(
                &mut state.client_input[..],
                state.client_start,
                state.client_end,
            )?,
        };
        match result {
            DecodeResult::NeedMore { consumed } => {
                if let Some(buffer_id) = state.upload_buffer.take() {
                    let remaining = state.upload_buffer_end - consumed;
                    if remaining > state.client_input.len() {
                        uploads.release(buffer_id);
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "VMess fragmented frame exceeded bound",
                        ));
                    }
                    state.client_input[..remaining].copy_from_slice(
                        &uploads.bytes(buffer_id)[consumed..state.upload_buffer_end],
                    );
                    state.client_start = 0;
                    state.client_end = remaining;
                    state.upload_buffer_start = 0;
                    state.upload_buffer_end = 0;
                    uploads.release(buffer_id);
                } else {
                    state.client_start = consumed;
                    if state.client_start > 0 {
                        state
                            .client_input
                            .copy_within(state.client_start..state.client_end, 0);
                        state.client_end -= state.client_start;
                        state.client_start = 0;
                    }
                }
                if let Some((buffer_id, length)) = state.upload_queue.pop_front() {
                    if state.client_end + length > state.client_input.len() {
                        uploads.release(buffer_id);
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "VMess fragmented frame exceeded local bound",
                        ));
                    }
                    state.client_input[state.client_end..state.client_end + length]
                        .copy_from_slice(&uploads.bytes(buffer_id)[..length]);
                    state.client_end += length;
                    uploads.release(buffer_id);
                    continue;
                }
                if state.client_one_shot {
                    return Ok(Some(recv_client_entry(identifier, state)?));
                }
                if state.client_multishot_armed {
                    return Ok(None);
                }
                state.client_multishot_armed = true;
                return Ok(Some(recv_client_multi_entry(identifier, state)));
            }
            DecodeResult::Eof => {
                if let Some(buffer_id) = state.upload_buffer.take() {
                    uploads.release(buffer_id);
                }
                state.client_start = state.client_end;
                state.upload_buffer_start = 0;
                state.upload_buffer_end = 0;
                state.client_read_eof = true;
                if !state.upload_queue.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "VMess data received after termination frame",
                    ));
                }
                return Ok(None);
            }
            DecodeResult::Plain {
                start,
                length,
                resume,
            } => {
                let (start, length) = if state.xudp {
                    let plaintext = match state.upload_buffer {
                        Some(buffer_id) => &uploads.bytes(buffer_id)[start..start + length],
                        None => &state.client_input[start..start + length],
                    };
                    match decode_xudp_frame(plaintext)? {
                        XudpFrame::End => {
                            if let Some(buffer_id) = state.upload_buffer {
                                state.upload_buffer_start = resume;
                                if state.upload_buffer_start == state.upload_buffer_end {
                                    state.upload_buffer = None;
                                    state.upload_buffer_start = 0;
                                    state.upload_buffer_end = 0;
                                    uploads.release(buffer_id);
                                }
                            } else {
                                state.client_start = resume;
                            }
                            state.client_read_eof = true;
                            if !state.upload_queue.is_empty()
                                || state.upload_buffer.is_some()
                                || state.client_start != state.client_end
                            {
                                return Err(io::Error::new(
                                    io::ErrorKind::Unsupported,
                                    "multiple XUDP sessions on one VMess connection are unsupported",
                                ));
                            }
                            return Ok(None);
                        }
                        XudpFrame::Data {
                            session_id,
                            target,
                            payload_start,
                            payload_length,
                        } => {
                            state.route_protocols |= crate::sniff::udp_protocols(
                                &plaintext[payload_start..payload_start + payload_length],
                            );
                            let target =
                                target
                                    .or_else(|| state.xudp_target.clone())
                                    .ok_or_else(|| {
                                        io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "XUDP session has no destination",
                                        )
                                    })?;
                            if state
                                .xudp_target
                                .as_ref()
                                .is_some_and(|current| current.address != target.address)
                            {
                                return Err(io::Error::new(
                                    io::ErrorKind::Unsupported,
                                    "XUDP destination change is not yet supported",
                                ));
                            }
                            state.xudp_session_id = session_id;
                            state.target_endpoint = Some(target.address);
                            if state.target_address.is_none() {
                                state.target_address =
                                    Some(Box::new(RawSocketAddress::new(target.address)));
                            }
                            state.xudp_target = Some(target);
                            (start + payload_start, payload_length)
                        }
                    }
                } else {
                    (start, length)
                };
                if !state.xudp && state.pending_target.is_some() {
                    if state.sniff_buffer.len().saturating_add(length) > SNIFF_BUFFER_MAX {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "VMess sniff buffer exceeded bound",
                        ));
                    }
                    match state.upload_buffer {
                        Some(buffer_id) => state
                            .sniff_buffer
                            .extend_from_slice(&uploads.bytes(buffer_id)[start..start + length]),
                        None => state
                            .sniff_buffer
                            .extend_from_slice(&state.client_input[start..start + length]),
                    }
                    if let Some(buffer_id) = state.upload_buffer {
                        state.upload_buffer_start = resume;
                        if state.upload_buffer_start == state.upload_buffer_end {
                            state.upload_buffer = None;
                            state.upload_buffer_start = 0;
                            state.upload_buffer_end = 0;
                            uploads.release(buffer_id);
                        }
                    } else {
                        state.client_start = resume;
                    }
                    let decision = state.sniff.inspect(&state.sniff_buffer);
                    if decision == SniffDecision::NeedMore {
                        continue;
                    }
                    set_vmess_tcp_target(state, decision)?;
                    let length = state.sniff_buffer.len();
                    let wait =
                        reserve_budget(user, &mut state.upload_budget, length, features.limiter);
                    extend_deadline(&mut state.upload_ready_at, wait);
                    state.upload_start = 0;
                    state.upload_length = length;
                    state.upload_offset = 0;
                    state.upload_resume = 0;
                    state.upload_from_sniff = true;
                    if state.connected && state.upload_ready_at.is_none() {
                        return Ok(Some(send_target_entry(identifier, state, uploads)));
                    }
                    return Ok(None);
                }
                let wait = reserve_budget(user, &mut state.upload_budget, length, features.limiter);
                extend_deadline(&mut state.upload_ready_at, wait);
                state.upload_start = start;
                state.upload_length = length;
                state.upload_offset = 0;
                state.upload_resume = resume;
                if state.connected && state.upload_ready_at.is_none() {
                    return Ok(Some(send_target_entry(identifier, state, uploads)));
                }
                return Ok(None);
            }
        }
    }
}

fn prepare_download_entry(
    identifier: usize,
    state: &mut Connection,
    downloads: &mut DownloadBufferRing,
    user: &mut UserRuntime,
    features: Features,
    received: (u16, usize),
    padding_random: &mut PaddingRandom,
) -> io::Result<Option<IoEntry>> {
    let (buffer_id, length) = received;
    let wait = reserve_budget(user, &mut state.download_budget, length, features.limiter);
    extend_deadline(&mut state.download_ready_at, wait);
    let encoded = finish_download_encode(
        state,
        &mut downloads.bytes_mut(buffer_id)[..],
        length,
        padding_random,
    );
    let (start, encoded_length) = match encoded {
        Ok(value) => value,
        Err(error) => {
            downloads.release(buffer_id);
            return Err(error);
        }
    };
    state.download_buffer = Some(buffer_id);
    state.download_local_active = false;
    state.download_eof_frame = false;
    state.client_output_start = start;
    state.client_output_length = encoded_length;
    state.client_output_offset = 0;
    state.download_plaintext_length = length;
    if state.download_ready_at.is_none() {
        Ok(Some(send_client_entry(identifier, state, downloads)))
    } else {
        Ok(None)
    }
}

fn next_download_entry(
    identifier: usize,
    state: &mut Connection,
    downloads: &mut DownloadBufferRing,
    user: &mut UserRuntime,
    features: Features,
    padding_random: &mut PaddingRandom,
) -> io::Result<Option<IoEntry>> {
    let Some((buffer_id, length)) = state.download_queue.pop_front() else {
        if state.target_read_eof || state.target_multishot_armed {
            return Ok(None);
        }
        if state.target_one_shot {
            return Ok(Some(recv_target_paced_entry(identifier, state)));
        }
        return Ok(Some(recv_target_entry(identifier, state)));
    };
    prepare_download_entry(
        identifier,
        state,
        downloads,
        user,
        features,
        (buffer_id, length),
        padding_random,
    )
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
    if state.client_read_eof
        && state.connected
        && state.upload_length == 0
        && state.upload_buffer.is_none()
        && state.upload_queue.is_empty()
        && state.client_start == state.client_end
        && !state.target_write_shutdown
    {
        if state.target_udp {
            // VMess UDP has no target-side byte-stream half close. Stop
            // accepting response datagrams and finish the VMess stream after
            // all already queued datagrams have been encoded.
            state.target_write_shutdown = true;
            state.target_read_eof = true;
        } else if let Some(target) = state.target.as_ref() {
            shutdown_write(target.as_raw_fd());
            state.target_write_shutdown = true;
        }
    }
}

fn finish_download_half(state: &mut Connection) {
    if state.target_read_eof
        && state.client_output_length == 0
        && !state.download_local_active
        && state.download_buffer.is_none()
        && state.download_queue.is_empty()
        && !state.client_write_shutdown
    {
        shutdown_write(state._client.as_raw_fd());
        state.client_write_shutdown = true;
    }
}

fn finish_graceful_close(state: &mut Connection) {
    if state.target_write_shutdown
        && state.client_write_shutdown
        && state.upload_length == 0
        && state.client_output_length == 0
    {
        begin_close(state);
    }
}

fn download_eof_entry(
    identifier: usize,
    state: &mut Connection,
    downloads: &DownloadBufferRing,
    padding_random: &mut PaddingRandom,
) -> io::Result<IoEntry> {
    if state.download_local.is_none() {
        state.download_local = Some(Box::new([0; DOWNLOAD_BUFFER_SIZE]));
    }
    let (start, length) = state
        .session
        .as_mut()
        .expect("VMess session")
        .finish_fixed_encode(
            &mut state.download_local.as_mut().expect("VMess EOF buffer")[..],
            DOWNLOAD_HEADROOM,
            0,
            padding_random,
        )?;
    state.download_local_active = true;
    state.download_eof_frame = true;
    state.client_output_start = start;
    state.client_output_length = length;
    state.client_output_offset = 0;
    state.download_plaintext_length = 0;
    Ok(send_client_entry(identifier, state, downloads))
}

fn udp_eof_entry_if_ready(
    identifier: usize,
    state: &mut Connection,
    downloads: &DownloadBufferRing,
    padding_random: &mut PaddingRandom,
) -> io::Result<Option<IoEntry>> {
    if state.target_udp
        && state.target_read_eof
        && state.download_queue.is_empty()
        && state.client_output_length == 0
        && state.download_buffer.is_none()
        && !state.download_local_active
        && !state.client_write_shutdown
    {
        download_eof_entry(identifier, state, downloads, padding_random).map(Some)
    } else {
        Ok(None)
    }
}

fn finish_upload_direction(
    identifier: usize,
    state: &mut Connection,
    downloads: &DownloadBufferRing,
    padding_random: &mut PaddingRandom,
    pending: &mut Vec<IoEntry>,
) {
    finish_upload_half(state);
    match udp_eof_entry_if_ready(identifier, state, downloads, padding_random) {
        Ok(Some(entry)) => queue_connection!(state, pending, entry),
        Ok(None) => {}
        Err(error) => fail_io(state, error),
    }
}

fn begin_close(state: &mut Connection) {
    if !state.closing {
        state.closing = true;
        VMESS_CLOSE_PENDING.store(true, Ordering::Relaxed);
        shutdown(state._client.as_raw_fd());
        if let Some(target) = state.target.as_ref() {
            shutdown(target.as_raw_fd());
        }
    }
}

fn fail(state: &mut Connection, error: impl std::fmt::Display) {
    if !state.failed {
        connection_error(ErrorScope::FastVmess, error);
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

fn complete_request(state: &mut Connection, operation: u8, completion_flags: u32) {
    let continues =
        matches!(operation, OP_RECV_CLIENT | OP_RECV_TARGET) && cqueue::more(completion_flags);
    if !continues {
        state.inflight = state.inflight.saturating_sub(1);
    }
}

fn complete_while_closing(
    state: &mut Connection,
    operation: u8,
    completion: (i32, u32),
    listeners: &mut [ListenerState],
    upload_buffers: &mut UploadBufferRing,
    download_buffers: &mut DownloadBufferRing,
    features: Features,
) {
    let (result, completion_flags) = completion;
    if result <= 0 {
        return;
    }
    match operation {
        OP_RECV_CLIENT => {
            if let Some(buffer_id) = cqueue::buffer_select(completion_flags) {
                upload_buffers.release(buffer_id);
            }
        }
        OP_RECV_TARGET => {
            if let Some(buffer_id) = cqueue::buffer_select(completion_flags) {
                download_buffers.release(buffer_id);
            }
        }
        OP_SEND_TARGET => {
            let count = result as usize;
            state.upload_offset = (state.upload_offset + count).min(state.upload_length);
            if features.traffic {
                if let Some(user) = state.user {
                    listeners[state.listener].users[user].upload += count as u64;
                }
            }
        }
        OP_SEND_CLIENT => {
            let credited = complete_record_write(
                &mut state.client_output_offset,
                state.client_output_length,
                &mut state.download_plaintext_length,
                result as usize,
            );
            if credited != 0 && features.traffic {
                if let Some(user) = state.user {
                    listeners[state.listener].users[user].download += credited;
                }
            }
        }
        _ => {}
    }
}

fn retire_connection(
    identifier: usize,
    connections: &mut [Option<Connection>],
    free_connections: &mut Vec<usize>,
    listeners: &mut [ListenerState],
    upload_buffers: &mut UploadBufferRing,
    download_buffers: &mut DownloadBufferRing,
    driver: &mut IoDriver,
) -> io::Result<()> {
    let Some(mut state) = connections[identifier].take() else {
        return Ok(());
    };
    debug_assert_eq!(state.inflight, 0);
    if let Some(buffer_id) = state.upload_buffer.take() {
        upload_buffers.release(buffer_id);
    }
    for (buffer_id, _) in state.upload_queue.drain(..) {
        upload_buffers.release(buffer_id);
    }
    if let Some(buffer_id) = state.download_buffer.take() {
        download_buffers.release(buffer_id);
    }
    for (buffer_id, _) in state.download_queue.drain(..) {
        download_buffers.release(buffer_id);
    }
    if let Some(user_index) = state.user {
        let user = &mut listeners[state.listener].users[user_index];
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
        listeners[state.listener].prune_retired();
    }
    if state.fixed_files {
        driver.register_file(state.client_slot, -1)?;
        driver.register_file(state.target_slot, -1)?;
    }
    free_connections.push(identifier);
    Ok(())
}

fn argument(name: &str, default: &str) -> String {
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == name {
            return arguments.next().unwrap_or_else(|| default.to_owned());
        }
    }
    default.to_owned()
}

fn numeric_argument(name: &str, default: usize) -> io::Result<usize> {
    argument(name, &default.to_string())
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn boolean_list_argument(name: &str, count: usize) -> io::Result<Vec<bool>> {
    let value = argument(name, "");
    if value.trim().is_empty() {
        return Ok(vec![false; count]);
    }
    let values = value
        .split(',')
        .map(|value| match value.trim() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid boolean {other:?} in {name}"),
            )),
        })
        .collect::<io::Result<Vec<_>>>()?;
    if values.len() != count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} contains {} entries, want {count}", values.len()),
        ));
    }
    Ok(values)
}

fn has_argument(name: &str) -> bool {
    env::args().skip(1).any(|argument| argument == name)
}

fn ignore_supervisor_signals() -> io::Result<()> {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let previous = unsafe { libc::signal(signal, libc::SIG_IGN) };
        if previous == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn ss_listen_addresses(
    listen_address: &str,
    explicit_ports: &str,
    listen_base: usize,
    site_count: usize,
) -> io::Result<Vec<String>> {
    let ip: IpAddr = listen_address.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Shadowsocks listen address {listen_address:?}: {error}"),
        )
    })?;
    let ports: Vec<u16> = if explicit_ports.trim().is_empty() {
        (1..=site_count)
            .map(|site| {
                u16::try_from(listen_base.saturating_add(site)).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Shadowsocks listen port exceeds 65535",
                    )
                })
            })
            .collect::<io::Result<_>>()?
    } else {
        explicit_ports
            .split(',')
            .map(|value| {
                let value = value.trim();
                let port: u16 = value.parse().map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid Shadowsocks listen port {value:?}: {error}"),
                    )
                })?;
                if port == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Shadowsocks listen port must not be zero",
                    ));
                }
                Ok(port)
            })
            .collect::<io::Result<_>>()?
    };
    Ok(ports
        .into_iter()
        .map(|port| SocketAddr::new(ip, port).to_string())
        .collect())
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

fn config_path() -> io::Result<String> {
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--config" || argument == "-config" {
            return arguments
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing config path"));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: oldxr-phase7-fastvmess-uring --config FILE",
    ))
}

fn main() -> io::Result<()> {
    if has_argument("--probe-io-backend") {
        let requested = env::var("OLDXR_FASTENGINE_IO_BACKEND")
            .unwrap_or_else(|_| argument("--io-backend", "auto"));
        let (_ring, backend, _upload, _download, reason) = io_backend(&requested)?;
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "engine": "FastEngine",
                "io_backend": backend.name(),
                "reason": reason,
                "requested": requested,
                "target_arch": env::consts::ARCH,
                "target_env": if cfg!(target_env = "musl") { "musl" } else { "gnu" },
            }))?
        );
        return Ok(());
    }
    if has_argument("--supervised") {
        // systemd's default KillMode sends SIGTERM to every process in the
        // service cgroup. Keep the data engine alive while its Go supervisor
        // drains final traffic, then let CommandContext terminate it.
        ignore_supervisor_signals()?;
    }
    let feature_name = argument("--features", "none");
    let debug_status_path = argument("--debug-status-path", "");
    let admin_socket_path = argument("--admin-socket", "");
    let mut debug_status_at = Instant::now();
    let mut debug_open = usize::MAX;
    let features = Features::parse(&feature_name)?;
    let speed_mbps = numeric_argument("--speed-mbps", 1000)? as u64;
    let speed_bytes_per_second = speed_mbps.saturating_mul(1_000_000) / 8;
    let device_limit = numeric_argument("--device-limit", 5)?;
    let tcp_timeouts = TcpTimeouts::from_seconds(
        numeric_argument("--handshake-seconds", 4)?,
        numeric_argument("--conn-idle-seconds", 10)?,
        numeric_argument("--uplink-only-seconds", 0)?,
        numeric_argument("--downlink-only-seconds", 0)?,
    );
    let (configs, router) = match serde_json::from_slice(&fs::read(config_path()?)?)? {
        EngineConfigFile::Normalized { listeners, routing } => {
            (listeners, Arc::new(routing::Router::compile(routing)?))
        }
        EngineConfigFile::Legacy(listeners) => (listeners, Arc::new(routing::Router::direct())),
    };
    let mut listeners = Vec::with_capacity(configs.len());
    for config in configs {
        if config.protocol.kind != "vmess" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only VMess configs are supported",
            ));
        }
        let socket = TcpListener::bind(&config.address)?;
        socket.set_nonblocking(true)?;
        listeners.push(ListenerState::new(
            socket,
            config.protocol.user_ids,
            speed_bytes_per_second,
            device_limit,
            config.protocol.sniffing,
        )?);
    }

    let requested_io_backend = env::var("OLDXR_FASTENGINE_IO_BACKEND")
        .unwrap_or_else(|_| argument("--io-backend", "auto"));
    let (mut driver, io_backend, mut upload_buffers, mut download_buffers, io_backend_reason) =
        io_backend(&requested_io_backend)?;
    eprintln!(
        "FastEngine I/O backend: {} ({io_backend_reason})",
        io_backend.name()
    );
    let ss_addresses = ss_listen_addresses(
        &argument("--ss-listen-address", "127.0.0.1"),
        &argument("--ss-ports", ""),
        numeric_argument("--ss-listen-base", 22000)?,
        numeric_argument("--ss-sites", 10)?,
    )?;
    let ss_sniffing = boolean_list_argument("--ss-sniffing", ss_addresses.len())?;
    let mut ss_engine = ss::Engine::new_with_addresses(
        &ss_addresses,
        &ss_sniffing,
        numeric_argument("--ss-users", 1000)?,
        numeric_argument("--ss-revision", 0)?,
        &feature_name,
        speed_mbps,
        "",
        device_limit,
        true,
        VMESS_FIXED_FILE_SLOTS,
        Duration::from_secs(numeric_argument("--ss-udp-idle-seconds", 120)? as u64),
        tcp_timeouts,
        io_backend.fixed_files(),
        Arc::clone(&router),
    )?;
    let mut admin_control = if admin_socket_path.is_empty() {
        None
    } else {
        Some(start_admin(&admin_socket_path)?)
    };
    let mut padding_random = PaddingRandom::new();
    let mut connections: Vec<Option<Connection>> = Vec::with_capacity(MAX_CONNECTIONS + 1);
    connections.push(None);
    let mut timers = BinaryHeap::new();
    let mut next_generation = 1u64;
    let mut free_connections = Vec::with_capacity(MAX_CONNECTIONS);
    let mut accept_armed = vec![false; listeners.len()];
    let mut accept_armed_count = 0;
    let mut accept_cursor = 0;
    let mut active_connections = 0;
    let mut next_policy_sweep = Instant::now() + Duration::from_secs(1);
    let mut pending = Vec::with_capacity(RING_ENTRIES as usize);
    let mut completions = Vec::with_capacity(RING_ENTRIES as usize);
    arm_accepts(
        &listeners,
        &mut accept_armed,
        &mut accept_armed_count,
        &mut accept_cursor,
        active_connections,
        io_backend.fixed_files(),
        &mut pending,
    );
    ss_engine.arm(&mut pending);
    if let Some(control) = admin_control.as_mut() {
        pending.push(admin_event_entry(control, !io_backend.fixed_files()));
    }
    for entry in pending.drain(..) {
        driver.push(entry)?;
    }
    driver.submit()?;

    loop {
        let now = Instant::now();
        if (active_connections != 0 || ss_engine.has_tcp_connections()) && now >= next_policy_sweep
        {
            expire_tcp_connections(now, &mut connections, tcp_timeouts);
            ss_engine.expire_tcp(now);
            next_policy_sweep = now + Duration::from_secs(1);
        }
        resume_due(
            now,
            &mut timers,
            &mut connections,
            &upload_buffers,
            &download_buffers,
            &mut pending,
        );
        ss_engine.resume_due(now, &mut pending);
        for entry in pending.drain(..) {
            driver.push(entry)?;
        }
        let policy_deadline = (active_connections != 0 || ss_engine.has_tcp_connections())
            .then_some(next_policy_sweep);
        let deadline = [
            next_deadline(&mut timers, &connections),
            ss_engine.next_deadline(),
            policy_deadline,
        ]
        .into_iter()
        .flatten()
        .min();
        driver.wait(deadline)?;
        completions.clear();
        driver.drain_completions(&mut completions);
        pending.clear();

        for (user_data, mut result, completion_flags) in completions.drain(..) {
            if ss::owns(user_data) {
                ss_engine.handle_completion(&mut driver, user_data, result, &mut pending)?;
                continue;
            }
            let (identifier, operation) = decode_tag(user_data);
            if operation == OP_ADMIN {
                let control = admin_control.as_mut().expect("admin control event");
                if result < 0 && -result != libc::EAGAIN {
                    return Err(io::Error::from_raw_os_error(-result));
                }
                if !io_backend.fixed_files() && result >= 0 {
                    drain_admin_event(control)?;
                }
                while let Ok(command) = control.receiver.try_recv() {
                    let _ = process_admin_command(command, &mut ss_engine, &mut listeners);
                }
                pending.push(admin_event_entry(control, !io_backend.fixed_files()));
                continue;
            }
            if operation == OP_ACCEPT {
                accept_armed[identifier] = false;
                accept_armed_count = accept_armed_count.saturating_sub(1);
                if !io_backend.fixed_files() && result >= 0 {
                    result = accept_ready(listeners[identifier].socket.as_raw_fd());
                }
                if result < 0 {
                    arm_accepts(
                        &listeners,
                        &mut accept_armed,
                        &mut accept_armed_count,
                        &mut accept_cursor,
                        active_connections,
                        io_backend.fixed_files(),
                        &mut pending,
                    );
                    continue;
                }
                let client = unsafe { OwnedFd::from_raw_fd(result) };
                if active_connections >= MAX_CONNECTIONS.saturating_sub(1) {
                    arm_accepts(
                        &listeners,
                        &mut accept_armed,
                        &mut accept_armed_count,
                        &mut accept_cursor,
                        active_connections,
                        io_backend.fixed_files(),
                        &mut pending,
                    );
                    continue;
                }
                if set_nodelay(client.as_raw_fd()).is_err() {
                    arm_accepts(
                        &listeners,
                        &mut accept_armed,
                        &mut accept_armed_count,
                        &mut accept_cursor,
                        active_connections,
                        io_backend.fixed_files(),
                        &mut pending,
                    );
                    continue;
                }
                let peer_ip =
                    peer_ip(client.as_raw_fd()).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                let generation = next_generation;
                next_generation = next_generation.wrapping_add(1).max(1);
                let connection_id = free_connections.pop().unwrap_or(connections.len());
                let client_slot = (connection_id * 2) as u32;
                let target_slot = client_slot + 1;
                if io_backend.fixed_files() {
                    driver.register_file(client_slot, client.as_raw_fd())?;
                }
                let mut state = Connection {
                    _client: client,
                    target: None,
                    client_slot,
                    target_slot,
                    fixed_files: io_backend.fixed_files(),
                    listener: identifier,
                    user: None,
                    peer_ip,
                    target_endpoint: None,
                    target_address: None,
                    pending_target: None,
                    tcp_target: None,
                    sniff: SniffState::with_bittorrent(
                        listeners[identifier].sniffing,
                        router.needs_bittorrent(),
                    ),
                    sniff_buffer: Vec::new(),
                    target_udp: false,
                    xudp: false,
                    xudp_session_id: 0,
                    xudp_target: None,
                    route_protocols: 0,
                    rule_checked: false,
                    session: None,
                    client_input: Box::new([0; CLIENT_INPUT_SIZE]),
                    client_start: 0,
                    client_end: 0,
                    upload_buffer: None,
                    upload_buffer_start: 0,
                    upload_buffer_end: 0,
                    upload_queue: VecDeque::new(),
                    client_multishot_armed: false,
                    upload_start: 0,
                    upload_length: 0,
                    upload_offset: 0,
                    upload_resume: 0,
                    upload_from_sniff: false,
                    upload_budget: 0,
                    download_buffer: None,
                    download_queue: VecDeque::new(),
                    target_multishot_armed: false,
                    client_output_start: 0,
                    client_output_length: 0,
                    client_output_offset: 0,
                    download_plaintext_length: 0,
                    download_budget: 0,
                    download_local: None,
                    download_local_active: false,
                    download_eof_frame: false,
                    upload_ready_at: None,
                    upload_scheduled_at: None,
                    download_ready_at: None,
                    download_scheduled_at: None,
                    device_admitted: false,
                    connected: false,
                    client_one_shot: false,
                    target_one_shot: false,
                    client_read_eof: false,
                    target_read_eof: false,
                    target_write_shutdown: false,
                    client_write_shutdown: false,
                    inflight: 0,
                    close_cancels_queued: false,
                    closing: false,
                    failed: false,
                    generation,
                    timeout: TcpTimeoutState::new(Instant::now()),
                };
                let receive = recv_client_entry(connection_id, &mut state)?;
                queue_connection!(&mut state, pending, receive);
                if connection_id == connections.len() {
                    connections.push(Some(state));
                } else {
                    connections[connection_id] = Some(state);
                }
                active_connections += 1;
                arm_accepts(
                    &listeners,
                    &mut accept_armed,
                    &mut accept_armed_count,
                    &mut accept_cursor,
                    active_connections,
                    io_backend.fixed_files(),
                    &mut pending,
                );
                continue;
            }

            let Some(state) = connections.get_mut(identifier).and_then(Option::as_mut) else {
                continue;
            };
            if !io_backend.fixed_files() && result >= 0 {
                result = compat_vmess_result(operation, state, &upload_buffers, &download_buffers);
            }
            complete_request(state, operation, completion_flags);
            if operation == OP_RECV_CLIENT && !cqueue::more(completion_flags) {
                state.client_multishot_armed = false;
            }
            if operation == OP_RECV_TARGET && !cqueue::more(completion_flags) {
                state.target_multishot_armed = false;
            }
            if state.closing {
                complete_while_closing(
                    state,
                    operation,
                    (result, completion_flags),
                    &mut listeners,
                    &mut upload_buffers,
                    &mut download_buffers,
                    features,
                );
                continue;
            }
            if !io_backend.fixed_files() && result == -libc::EAGAIN {
                let retry = match operation {
                    OP_RECV_CLIENT => Some(recv_client_entry(identifier, state)?),
                    OP_SEND_TARGET => Some(send_target_entry(identifier, state, &upload_buffers)),
                    OP_RECV_TARGET => Some(recv_target_paced_entry(identifier, state)),
                    OP_SEND_CLIENT => Some(send_client_entry(identifier, state, &download_buffers)),
                    _ => None,
                };
                if let Some(entry) = retry {
                    queue_connection!(state, pending, entry);
                    continue;
                }
            }
            if result < 0 {
                if result == -libc::ENOBUFS {
                    match operation {
                        OP_RECV_CLIENT if state.session.is_some() => {
                            // A provided-buffer shortage terminates this multishot receive.
                            // Fall back to the connection-local one-shot buffer instead of
                            // closing the connection or immediately retrying the empty shared
                            // ring. Existing queued plaintext drains first.
                            state.client_one_shot = true;
                            state.client_multishot_armed = false;
                            VMESS_UPLOAD_BUFFER_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                            if state.upload_length == 0 {
                                let user = state.user.expect("authenticated user");
                                let site = state.listener;
                                match next_upload_entry(
                                    identifier,
                                    state,
                                    &mut upload_buffers,
                                    &mut listeners[site].users[user],
                                    features,
                                ) {
                                    Ok(Some(entry)) => queue_connection!(state, pending, entry),
                                    Ok(None) => {}
                                    Err(error) => fail_io(state, error),
                                }
                            }
                            continue;
                        }
                        OP_RECV_TARGET => {
                            // Use bounded per-connection storage under shared-ring pressure.
                            // This preserves socket backpressure and avoids an ENOBUFS retry
                            // loop while the outstanding encrypted write is completing.
                            state.target_one_shot = true;
                            state.target_multishot_armed = false;
                            VMESS_DOWNLOAD_BUFFER_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                            if state.download_local.is_none() {
                                state.download_local = Some(Box::new([0; DOWNLOAD_BUFFER_SIZE]));
                            }
                            if state.client_output_length == 0 {
                                let user = state.user.expect("authenticated user");
                                let site = state.listener;
                                match next_download_entry(
                                    identifier,
                                    state,
                                    &mut download_buffers,
                                    &mut listeners[site].users[user],
                                    features,
                                    &mut padding_random,
                                ) {
                                    Ok(Some(entry)) => queue_connection!(state, pending, entry),
                                    Ok(None) => {}
                                    Err(error) => fail_io(state, error),
                                }
                            }
                            continue;
                        }
                        _ => {}
                    }
                }
                fail_io(state, io::Error::from_raw_os_error(-result));
                continue;
            }

            match operation {
                OP_RECV_CLIENT => {
                    if result == 0 {
                        if let Some(buffer_id) = cqueue::buffer_select(completion_flags) {
                            upload_buffers.release(buffer_id);
                        }
                        state.client_multishot_armed = false;
                        if state.session.is_none() {
                            begin_close(state);
                        } else {
                            if state.pending_target.is_some() {
                                if let Err(error) =
                                    set_vmess_tcp_target(state, SniffDecision::Original)
                                {
                                    fail_io(state, error);
                                    continue;
                                }
                                let site = state.listener;
                                if let Err(error) = ensure_target_connect(
                                    identifier,
                                    state,
                                    &mut listeners[site],
                                    features,
                                    &router,
                                    &mut driver,
                                    &mut pending,
                                ) {
                                    fail_io(state, error);
                                    continue;
                                }
                            }
                            state.client_read_eof = true;
                            finish_upload_direction(
                                identifier,
                                state,
                                &download_buffers,
                                &mut padding_random,
                                &mut pending,
                            );
                            finish_graceful_close(state);
                        }
                        continue;
                    }
                    state.timeout.note_activity();
                    if state.session.is_none() {
                        state.client_end += result as usize;
                        match listeners[state.listener]
                            .credentials
                            .parse_handshake(&mut state.client_input[..], state.client_end)
                        {
                            Ok(None) => match recv_client_entry(identifier, state) {
                                Ok(entry) => queue_connection!(state, pending, entry),
                                Err(error) => fail(state, error),
                            },
                            Ok(Some(Handshake {
                                consumed,
                                target,
                                command,
                                session,
                                user_index,
                            })) => {
                                let site = &mut listeners[state.listener];
                                let target_udp = command != VmessCommand::Tcp;
                                let xudp = command == VmessCommand::Mux;
                                if let Some(target) = target {
                                    if target_udp {
                                        state.target_endpoint = Some(target.address);
                                        state.target_address =
                                            Some(Box::new(RawSocketAddress::new(target.address)));
                                        state.xudp_target = Some(target);
                                    } else if site.sniffing || router.needs_bittorrent() {
                                        state.pending_target = Some(target);
                                    } else {
                                        state.target_endpoint = Some(target.address);
                                        state.target_address =
                                            Some(Box::new(RawSocketAddress::new(target.address)));
                                        state.tcp_target = Some(target);
                                    }
                                }
                                if features.device {
                                    let devices = &mut site.users[user_index].device_ips;
                                    if site.device_limit != 0
                                        && !devices.contains_key(&state.peer_ip)
                                        && devices.len() >= site.device_limit
                                    {
                                        site.device_rejects = site.device_rejects.saturating_add(1);
                                        fail(state, "VMess device limit rejected");
                                        continue;
                                    }
                                    *devices.entry(state.peer_ip).or_default() += 1;
                                    state.device_admitted = true;
                                }
                                site.users[user_index].active += 1;
                                state.user = Some(user_index);
                                state.client_start = consumed;
                                state.session = Some(session);
                                state.timeout.authenticated(Instant::now());
                                state.target_udp = target_udp;
                                state.xudp = xudp;
                                let one_shot = !state.fixed_files
                                    || features.limiter
                                        && site.users[user_index].limiter.requires_paced_io();
                                state.client_one_shot = one_shot;
                                state.target_one_shot = one_shot;
                                if state.target_one_shot {
                                    state.download_local =
                                        Some(Box::new([0; DOWNLOAD_BUFFER_SIZE]));
                                }
                                match next_upload_entry(
                                    identifier,
                                    state,
                                    &mut upload_buffers,
                                    &mut site.users[user_index],
                                    features,
                                ) {
                                    Ok(Some(entry)) => queue_connection!(state, pending, entry),
                                    Ok(None) => {}
                                    Err(error) => {
                                        fail_io(state, error);
                                        continue;
                                    }
                                }
                                if let Err(error) = ensure_target_connect(
                                    identifier,
                                    state,
                                    site,
                                    features,
                                    &router,
                                    &mut driver,
                                    &mut pending,
                                ) {
                                    fail_io(state, error);
                                }
                            }
                            Err(error) => fail_io(state, error),
                        }
                    } else {
                        if state.client_read_eof {
                            if let Some(buffer_id) = cqueue::buffer_select(completion_flags) {
                                upload_buffers.release(buffer_id);
                            }
                            fail(state, "VMess data received after termination frame");
                            continue;
                        }
                        if state.client_one_shot {
                            state.client_end += result as usize;
                        } else {
                            let Some(buffer_id) = cqueue::buffer_select(completion_flags) else {
                                fail(state, "multishot client receive has no buffer");
                                continue;
                            };
                            if !cqueue::more(completion_flags) {
                                state.client_multishot_armed = false;
                            }
                            // Keep the common one-ready-buffer path out of VecDeque. A hot
                            // connection can still receive several CQEs before its previous
                            // target send completes, so overflow retains buffer IDs in order.
                            if state.upload_length == 0
                                && state.upload_buffer.is_none()
                                && state.client_start == state.client_end
                                && state.upload_queue.is_empty()
                            {
                                state.client_start = 0;
                                state.client_end = 0;
                                state.upload_buffer = Some(buffer_id);
                                state.upload_buffer_start = 0;
                                state.upload_buffer_end = result as usize;
                            } else {
                                state.upload_queue.push_back((buffer_id, result as usize));
                            }
                        }
                        if state.upload_length == 0 {
                            let user = state.user.expect("authenticated user");
                            let site = state.listener;
                            match next_upload_entry(
                                identifier,
                                state,
                                &mut upload_buffers,
                                &mut listeners[site].users[user],
                                features,
                            ) {
                                Ok(Some(entry)) => queue_connection!(state, pending, entry),
                                Ok(None) => {}
                                Err(error) => fail_io(state, error),
                            }
                        }
                        if !state.closing {
                            let site = state.listener;
                            if let Err(error) = ensure_target_connect(
                                identifier,
                                state,
                                &mut listeners[site],
                                features,
                                &router,
                                &mut driver,
                                &mut pending,
                            ) {
                                fail_io(state, error);
                            }
                        }
                        if !state.closing {
                            finish_upload_direction(
                                identifier,
                                state,
                                &download_buffers,
                                &mut padding_random,
                                &mut pending,
                            );
                            finish_graceful_close(state);
                            schedule_waits(&mut timers, identifier, state);
                        }
                    }
                }
                OP_CONNECT_TARGET => {
                    state.connected = true;
                    if state.target_one_shot {
                        queue_connection!(
                            state,
                            pending,
                            recv_target_paced_entry(identifier, state)
                        );
                    } else {
                        queue_connection!(state, pending, recv_target_entry(identifier, state));
                    }
                    let user = state.user.expect("authenticated user");
                    let site = state.listener;
                    match next_upload_entry(
                        identifier,
                        state,
                        &mut upload_buffers,
                        &mut listeners[site].users[user],
                        features,
                    ) {
                        Ok(Some(entry)) => queue_connection!(state, pending, entry),
                        Ok(None) => {}
                        Err(error) => fail_io(state, error),
                    }
                    if !state.closing {
                        finish_upload_direction(
                            identifier,
                            state,
                            &download_buffers,
                            &mut padding_random,
                            &mut pending,
                        );
                        finish_graceful_close(state);
                        schedule_waits(&mut timers, identifier, state);
                    }
                }
                OP_SEND_TARGET => {
                    if result == 0 {
                        fail(state, "target write zero");
                        continue;
                    }
                    let remaining = state.upload_length - state.upload_offset;
                    if state.target_udp && result as usize != remaining {
                        fail(state, "partial VMess UDP datagram write");
                        continue;
                    }
                    state.upload_offset += result as usize;
                    if features.traffic {
                        let user = state.user.expect("authenticated user");
                        listeners[state.listener].users[user].upload += result as u64;
                    }
                    if state.upload_offset < state.upload_length {
                        queue_connection!(
                            state,
                            pending,
                            send_target_entry(identifier, state, &upload_buffers)
                        );
                    } else {
                        if state.upload_from_sniff {
                            state.upload_from_sniff = false;
                            state.sniff_buffer.clear();
                        } else if let Some(buffer_id) = state.upload_buffer {
                            state.upload_buffer_start = state.upload_resume;
                            if state.upload_buffer_start == state.upload_buffer_end {
                                state.upload_buffer = None;
                                state.upload_buffer_start = 0;
                                state.upload_buffer_end = 0;
                                upload_buffers.release(buffer_id);
                            }
                        } else {
                            state.client_start = state.upload_resume;
                        }
                        state.upload_length = 0;
                        state.upload_offset = 0;
                        let user = state.user.expect("authenticated user");
                        let site = state.listener;
                        match next_upload_entry(
                            identifier,
                            state,
                            &mut upload_buffers,
                            &mut listeners[site].users[user],
                            features,
                        ) {
                            Ok(Some(entry)) => queue_connection!(state, pending, entry),
                            Ok(None) => {}
                            Err(error) => fail_io(state, error),
                        }
                        if !state.closing {
                            finish_upload_direction(
                                identifier,
                                state,
                                &download_buffers,
                                &mut padding_random,
                                &mut pending,
                            );
                            finish_graceful_close(state);
                            schedule_waits(&mut timers, identifier, state);
                        }
                    }
                }
                OP_RECV_TARGET => {
                    if state.target_udp && state.target_read_eof {
                        if let Some(buffer_id) = cqueue::buffer_select(completion_flags) {
                            download_buffers.release(buffer_id);
                        }
                        continue;
                    }
                    if result == 0 {
                        if let Some(buffer_id) = cqueue::buffer_select(completion_flags) {
                            download_buffers.release(buffer_id);
                        }
                        state.target_multishot_armed = false;
                        state.target_read_eof = true;
                        if state.client_output_length == 0 && state.download_queue.is_empty() {
                            match download_eof_entry(
                                identifier,
                                state,
                                &download_buffers,
                                &mut padding_random,
                            ) {
                                Ok(entry) => queue_connection!(state, pending, entry),
                                Err(error) => fail_io(state, error),
                            }
                        }
                        continue;
                    }
                    state.timeout.note_activity();
                    if !state.target_one_shot {
                        let Some(buffer_id) = cqueue::buffer_select(completion_flags) else {
                            fail(state, "multishot target receive has no buffer");
                            continue;
                        };
                        if !cqueue::more(completion_flags) {
                            state.target_multishot_armed = false;
                        }
                        if state.client_output_length == 0 && state.download_queue.is_empty() {
                            let user = state.user.expect("authenticated user");
                            let site = state.listener;
                            match prepare_download_entry(
                                identifier,
                                state,
                                &mut download_buffers,
                                &mut listeners[site].users[user],
                                features,
                                (buffer_id, result as usize),
                                &mut padding_random,
                            ) {
                                Ok(Some(entry)) => queue_connection!(state, pending, entry),
                                Ok(None) => schedule_waits(&mut timers, identifier, state),
                                Err(error) => fail_io(state, error),
                            }
                        } else {
                            state.download_queue.push_back((buffer_id, result as usize));
                        }
                        continue;
                    }
                    let buffer_id = {
                        if state.download_local_active {
                            fail(state, "paced target receive exceeded bounded queue");
                            continue;
                        }
                        None
                    };
                    let user = state.user.expect("authenticated user");
                    let wait = reserve_budget(
                        &mut listeners[state.listener].users[user],
                        &mut state.download_budget,
                        result as usize,
                        features.limiter,
                    );
                    extend_deadline(&mut state.download_ready_at, wait);
                    let encoded = if let Some(buffer_id) = buffer_id {
                        finish_download_encode(
                            state,
                            &mut download_buffers.bytes_mut(buffer_id)[..],
                            result as usize,
                            &mut padding_random,
                        )
                    } else {
                        let mut local = state.download_local.take().expect("paced download buffer");
                        let result = finish_download_encode(
                            state,
                            &mut local[..],
                            result as usize,
                            &mut padding_random,
                        );
                        state.download_local = Some(local);
                        result
                    };
                    match encoded {
                        Ok((start, length)) => {
                            state.download_buffer = buffer_id;
                            state.download_local_active = state.target_one_shot;
                            state.download_eof_frame = false;
                            state.client_output_start = start;
                            state.client_output_length = length;
                            state.client_output_offset = 0;
                            state.download_plaintext_length = result as usize;
                            if state.download_ready_at.is_none() {
                                queue_connection!(
                                    state,
                                    pending,
                                    send_client_entry(identifier, state, &download_buffers)
                                );
                            } else {
                                schedule_waits(&mut timers, identifier, state);
                            }
                        }
                        Err(error) => {
                            if let Some(buffer_id) = buffer_id {
                                download_buffers.release(buffer_id);
                            }
                            fail(state, error);
                        }
                    }
                }
                OP_SEND_CLIENT => {
                    if result == 0 {
                        fail(state, "client write zero");
                        continue;
                    }
                    let credited = complete_record_write(
                        &mut state.client_output_offset,
                        state.client_output_length,
                        &mut state.download_plaintext_length,
                        result as usize,
                    );
                    if state.client_output_offset < state.client_output_length {
                        queue_connection!(
                            state,
                            pending,
                            send_client_entry(identifier, state, &download_buffers)
                        );
                    } else {
                        let completed_eof = state.download_eof_frame;
                        if let Some(buffer_id) = state.download_buffer.take() {
                            download_buffers.release(buffer_id);
                        }
                        state.download_local_active = false;
                        state.download_eof_frame = false;
                        if credited != 0 && features.traffic {
                            let user = state.user.expect("authenticated user");
                            listeners[state.listener].users[user].download += credited;
                        }
                        state.client_output_start = 0;
                        state.client_output_length = 0;
                        state.client_output_offset = 0;
                        if completed_eof {
                            finish_download_half(state);
                            finish_graceful_close(state);
                        } else {
                            let user = state.user.expect("authenticated user");
                            let site = state.listener;
                            match next_download_entry(
                                identifier,
                                state,
                                &mut download_buffers,
                                &mut listeners[site].users[user],
                                features,
                                &mut padding_random,
                            ) {
                                Ok(Some(entry)) => queue_connection!(state, pending, entry),
                                Ok(None) => {
                                    if state.target_read_eof {
                                        match download_eof_entry(
                                            identifier,
                                            state,
                                            &download_buffers,
                                            &mut padding_random,
                                        ) {
                                            Ok(entry) => {
                                                queue_connection!(state, pending, entry)
                                            }
                                            Err(error) => fail_io(state, error),
                                        }
                                    }
                                }
                                Err(error) => fail_io(state, error),
                            }
                        }
                    }
                }
                _ => fail(state, "unknown completion"),
            }
            if !state.closing && state.session.is_some() {
                if state.target_write_shutdown
                    && state.timeout.upload_closed(Instant::now(), tcp_timeouts)
                {
                    begin_close(state);
                }
                if !state.closing
                    && state.client_write_shutdown
                    && state.timeout.download_closed(Instant::now(), tcp_timeouts)
                {
                    begin_close(state);
                }
            }
        }

        if VMESS_CLOSE_PENDING.load(Ordering::Relaxed) {
            pending.retain(|entry| {
                let user_data = entry.get_user_data();
                if ss::owns(user_data) {
                    return true;
                }
                let (identifier, operation) = decode_tag(user_data);
                if matches!(operation, OP_ACCEPT | OP_ADMIN) {
                    return true;
                }
                let Some(state) = connections.get_mut(identifier).and_then(Option::as_mut) else {
                    return false;
                };
                if !state.closing {
                    return true;
                }
                state.inflight = state.inflight.saturating_sub(1);
                false
            });

            for (identifier, state) in connections.iter_mut().enumerate().skip(1) {
                let Some(state) = state.as_mut() else {
                    continue;
                };
                if !state.closing || state.inflight == 0 || state.close_cancels_queued {
                    continue;
                }
                state.close_cancels_queued = true;
                if state.client_multishot_armed {
                    queue_connection!(
                        state,
                        pending,
                        cancel_entry(
                            identifier,
                            OP_RECV_CLIENT,
                            OP_CANCEL_CLIENT_RECV,
                            state.fixed_files,
                        )
                    );
                }
                if state.target_multishot_armed {
                    queue_connection!(
                        state,
                        pending,
                        cancel_entry(
                            identifier,
                            OP_RECV_TARGET,
                            OP_CANCEL_TARGET_RECV,
                            state.fixed_files,
                        )
                    );
                }
            }

            let retired: Vec<_> = connections
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
                retire_connection(
                    identifier,
                    &mut connections,
                    &mut free_connections,
                    &mut listeners,
                    &mut upload_buffers,
                    &mut download_buffers,
                    &mut driver,
                )?;
                active_connections = active_connections.saturating_sub(1);
            }
            VMESS_CLOSE_PENDING.store(
                connections.iter().flatten().any(|state| state.closing),
                Ordering::Relaxed,
            );
        }
        ss_engine.finish_batch(&mut driver, &mut pending)?;
        arm_accepts(
            &listeners,
            &mut accept_armed,
            &mut accept_armed_count,
            &mut accept_cursor,
            active_connections,
            io_backend.fixed_files(),
            &mut pending,
        );

        if !debug_status_path.is_empty() {
            let total_open = active_connections + ss_engine.open_connections();
            if debug_status_at.elapsed() >= Duration::from_secs(1)
                || (debug_open != 0 && total_open == 0)
            {
                let mut vmess_open = 0;
                let mut vmess_closing = 0;
                let mut vmess_inflight = 0;
                let mut vmess_active_users = 0;
                let mut vmess_live_users = 0;
                let mut vmess_retired_users = 0;
                let mut vmess_upload = 0u64;
                let mut vmess_download = 0u64;
                for state in connections.iter().flatten() {
                    vmess_open += 1;
                    vmess_closing += usize::from(state.closing);
                    vmess_inflight += state.inflight;
                }
                for user in listeners.iter().flat_map(|listener| &listener.users) {
                    vmess_active_users += usize::from(user.active != 0);
                }
                for listener in &listeners {
                    vmess_live_users += listener.live_users.len();
                    vmess_retired_users += listener.retired_users();
                    let (site_upload, site_download) = listener.traffic_totals();
                    vmess_upload = vmess_upload.saturating_add(site_upload);
                    vmess_download = vmess_download.saturating_add(site_download);
                }
                let ss_status = ss_engine.status();
                let status = serde_json::json!({
                    "engine": "FastEngine",
                    "io_backend": io_backend.name(),
                    "io_backend_reason": io_backend_reason,
                    "vmess": {
                        "live_users": vmess_live_users,
                        "retired_users": vmess_retired_users,
                        "runtime_users": vmess_live_users + vmess_retired_users,
                        "slots": connections.len().saturating_sub(1),
                        "free": free_connections.len(),
                        "open": vmess_open,
                        "closing": vmess_closing,
                        "inflight": vmess_inflight,
                        "active_users": vmess_active_users,
                        "upload": vmess_upload,
                        "download": vmess_download,
                        "device_rejects": listeners.iter().map(|site| site.device_rejects).sum::<u64>(),
                        "rule_rejects": listeners.iter().map(|site| site.rule_rejects).sum::<u64>(),
                        "upload_buffer_fallbacks": VMESS_UPLOAD_BUFFER_FALLBACKS.load(Ordering::Relaxed),
                        "download_buffer_fallbacks": VMESS_DOWNLOAD_BUFFER_FALLBACKS.load(Ordering::Relaxed),
                    },
                    "shadowsocks": {
                        "live_users": ss_status.live_users,
                        "retired_users": ss_status.retired_users,
                        "runtime_users": ss_status.runtime_users,
                        "slots": ss_status.slots,
                        "free": ss_status.free,
                        "open": ss_status.open,
                        "closing": ss_status.closing,
                        "inflight": ss_status.inflight,
                        "active_users": ss_status.active_users,
                        "upload": ss_status.upload,
                        "download": ss_status.download,
                        "replay_rejects": ss_status.replay_rejects,
                        "device_rejects": ss_status.device_rejects,
                        "rule_rejects": ss_status.rule_rejects,
                        "udp_input_drops": ss_status.udp_input_drops,
                        "udp_queue_drops": ss_status.udp_queue_drops,
                        "udp_listener_errors": ss_status.udp_listener_errors,
                        "udp_upload_errors": ss_status.udp_upload_errors,
                        "udp_receive_errors": ss_status.udp_receive_errors,
                        "udp_response_errors": ss_status.udp_response_errors,
                    }
                });
                fs::write(&debug_status_path, serde_json::to_vec(&status)?)?;
                debug_status_at = Instant::now();
            }
            debug_open = total_open;
        }

        for entry in pending.drain(..) {
            driver.push(entry)?;
        }
        // The next wait submits queued io_uring requests or arms epoll
        // interests before blocking, avoiding an extra syscall per batch.
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;

    #[test]
    fn epoll_reactor_preserves_duplex_interests_and_cancellation() {
        let (mut client, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let descriptor = client.as_raw_fd();
        let mut reactor = EpollReactor::new().unwrap();
        let mut completions = VecDeque::new();

        reactor.add(descriptor, libc::POLLIN, 101).unwrap();
        reactor.add(descriptor, libc::POLLOUT, 102).unwrap();
        reactor
            .wait(
                Some(Instant::now() + Duration::from_secs(1)),
                &mut completions,
            )
            .unwrap();
        assert!(completions.iter().any(|completion| completion.0 == 102));
        assert!(!completions.iter().any(|completion| completion.0 == 101));
        completions.clear();

        std::io::Write::write_all(&mut peer, b"x").unwrap();
        reactor
            .wait(
                Some(Instant::now() + Duration::from_secs(1)),
                &mut completions,
            )
            .unwrap();
        assert!(completions.iter().any(|completion| completion.0 == 101));
        let mut byte = [0u8; 1];
        std::io::Read::read_exact(&mut client, &mut byte).unwrap();

        reactor.add(descriptor, libc::POLLIN, 103).unwrap();
        assert!(reactor.cancel(103).unwrap());
        assert!(!reactor.cancel(103).unwrap());
    }

    #[test]
    fn epoll_reactor_rolls_back_failed_registration() {
        let mut reactor = EpollReactor::new().unwrap();
        assert!(reactor.add(-1, libc::POLLIN, 201).is_err());
        assert!(reactor.interests.is_empty());
        assert!(reactor.tags.is_empty());
    }

    fn normalized(uid: u64, id: &str) -> VmessNormalizedUser {
        VmessNormalizedUser {
            uid,
            id: id.to_owned(),
        }
    }

    fn listener() -> ListenerState {
        ListenerState::new(
            TcpListener::bind("127.0.0.1:0").unwrap(),
            vec![
                "00000001-0001-4000-8000-000100000001".into(),
                "00000002-0001-4000-8000-000100000002".into(),
            ],
            1_000_000,
            5,
            false,
        )
        .unwrap()
    }

    #[test]
    fn vmess_unchanged_user_reuses_slot_and_changed_id_retires() {
        let mut site = listener();
        let unchanged = site.live_users[0];
        let changed = site.live_users[1];
        site.users[changed].active = 1;
        site.users[changed].upload = 42;

        let result = site
            .replace_users(vec![
                normalized(1, "00000001-0001-4000-8000-000100000001"),
                normalized(2, "00000002-0001-4000-8000-000100000099"),
            ])
            .unwrap();
        assert_eq!(result, (2, 1));
        assert_eq!(site.live_users[0], unchanged);
        assert_ne!(site.live_users[1], changed);
        assert_eq!(site.users[changed].state, VmessUserSlotState::Retired);
        assert_eq!(
            site.take_traffic(),
            vec![VmessTrafficRecord {
                uid: 2,
                upload: 42,
                download: 0,
            }]
        );
        site.users[changed].active = 0;
        site.prune_retired();
        assert_eq!(site.users[changed].state, VmessUserSlotState::Free);
    }

    #[test]
    fn vmess_retiring_user_preserves_late_and_restored_traffic() {
        let mut site = listener();
        let removed = site.live_users[0];
        site.users[removed].active = 1;
        site.replace_users(Vec::new()).unwrap();
        site.users[removed].upload = 123;
        site.users[removed].download = 456;
        let traffic = site.take_traffic();
        assert_eq!(
            traffic,
            vec![VmessTrafficRecord {
                uid: 1,
                upload: 123,
                download: 456,
            }]
        );
        assert_eq!(site.users[removed].state, VmessUserSlotState::Retired);
        site.restore_traffic(traffic.clone());
        assert_eq!(site.take_traffic(), traffic);
        site.users[removed].active = 0;
        site.prune_retired();
        assert_eq!(site.users[removed].state, VmessUserSlotState::Free);
    }

    #[test]
    fn vmess_invalid_update_is_transactional() {
        let mut site = listener();
        let original = site.live_users.clone();
        assert!(site
            .replace_users(vec![
                normalized(1, "00000001-0001-4000-8000-000100000001"),
                normalized(1, "00000002-0001-4000-8000-000100000002"),
            ])
            .is_err());
        assert_eq!(site.live_users, original);
        assert!(site
            .replace_users(vec![
                normalized(1, "00000001-0001-4000-8000-000100000001"),
                normalized(2, "00000001-0001-4000-8000-000100000001"),
            ])
            .is_err());
        assert_eq!(site.live_users, original);
        assert!(site.replace_users(vec![normalized(1, "invalid")]).is_err());
        assert_eq!(site.live_users, original);
    }

    #[test]
    fn explicit_ss_ports_preserve_panel_listener_order() {
        let addresses = ss_listen_addresses("127.0.0.1", "31001, 32007,33003", 22000, 10)
            .expect("explicit listener addresses");
        assert_eq!(
            addresses,
            vec!["127.0.0.1:31001", "127.0.0.1:32007", "127.0.0.1:33003"]
        );
    }

    #[test]
    fn default_ss_ports_remain_compatible_with_existing_harness() {
        let addresses =
            ss_listen_addresses("::1", "", 22000, 2).expect("default listener addresses");
        assert_eq!(addresses, vec!["[::1]:22001", "[::1]:22002"]);
    }

    #[test]
    fn invalid_ss_ports_fail_closed() {
        assert!(ss_listen_addresses("127.0.0.1", "31001,0", 22000, 10).is_err());
        assert!(ss_listen_addresses("127.0.0.1", "31001,not-a-port", 22000, 10).is_err());
        assert!(ss_listen_addresses("not-an-ip", "31001", 22000, 10).is_err());
    }

    #[test]
    fn vmess_policy_update_is_transactional_and_updates_runtime() {
        let mut site = listener();
        site.update_policy(2_000_000, 7, vec![r"^tcp:127\.0\.0\.1:19090$".into()])
            .expect("valid VMess policy");
        assert_eq!(site.speed_bytes_per_second, 2_000_000);
        assert_eq!(site.device_limit, 7);
        assert!(site
            .rules
            .as_ref()
            .expect("rules")
            .is_match("tcp:127.0.0.1:19090"));
        assert_eq!(site.users[site.live_users[0]].limiter.rate, 2_000_000.0);

        let previous_rate = site.speed_bytes_per_second;
        let previous_limit = site.device_limit;
        assert!(site.update_policy(3_000_000, 9, vec!["[".into()]).is_err());
        assert_eq!(site.speed_bytes_per_second, previous_rate);
        assert_eq!(site.device_limit, previous_limit);
    }

    #[test]
    fn vmess_only_engine_can_disable_ss_listeners() {
        assert!(ss_listen_addresses("127.0.0.1", "", 22000, 0)
            .expect("empty listener set")
            .is_empty());
    }

    #[test]
    fn xudp_new_and_keep_frames_preserve_datagram_boundaries() {
        let mut new_frame = vec![
            0, 12, // metadata length
            0x12, 0x34, // session ID
            1, 1, // New + Data
            2, // UDP
            0x4a, 0x93, // port 19091
            1,    // IPv4
            127, 0, 0, 1, 0, 4, // payload length
        ];
        new_frame.extend_from_slice(b"ping");
        match decode_xudp_frame(&new_frame).expect("new XUDP frame") {
            XudpFrame::Data {
                session_id,
                target,
                payload_start,
                payload_length,
            } => {
                assert_eq!(session_id, 0x1234);
                assert_eq!(
                    target,
                    Some(ResolvedTarget::from_ip("127.0.0.1:19091".parse().unwrap()))
                );
                assert_eq!(
                    &new_frame[payload_start..payload_start + payload_length],
                    b"ping"
                );
            }
            XudpFrame::End => panic!("expected data frame"),
        }

        let mut keep_frame = vec![0, 4, 0x12, 0x34, 2, 1, 0, 4];
        keep_frame.extend_from_slice(b"pong");
        match decode_xudp_frame(&keep_frame).expect("keep XUDP frame") {
            XudpFrame::Data {
                session_id,
                target,
                payload_start,
                payload_length,
            } => {
                assert_eq!(session_id, 0x1234);
                assert_eq!(target, None);
                assert_eq!(
                    &keep_frame[payload_start..payload_start + payload_length],
                    b"pong"
                );
            }
            XudpFrame::End => panic!("expected data frame"),
        }
    }

    #[test]
    fn xudp_end_and_response_metadata_are_wire_compatible() {
        assert!(matches!(
            decode_xudp_frame(&[0, 4, 0, 7, 3, 0]).expect("end XUDP frame"),
            XudpFrame::End
        ));

        let target = ResolvedTarget::from_ip("192.0.2.10:5353".parse().unwrap());
        let mut output = [0u8; 64];
        output[32..36].copy_from_slice(b"data");
        let (start, length) =
            prepend_xudp_response(&mut output, 32, 4, 9, &target).expect("XUDP response");
        assert_eq!(start, 16);
        assert_eq!(length, 20);
        assert_eq!(
            &output[start..32],
            &[0, 12, 0, 9, 2, 1, 2, 0x14, 0xe9, 1, 192, 0, 2, 10, 0, 4]
        );
        assert_eq!(&output[32..36], b"data");
    }

    #[test]
    fn xudp_ipv6_metadata_is_wire_compatible() {
        let address = "2001:db8::7".parse::<std::net::Ipv6Addr>().unwrap();
        let mut frame = vec![
            0, 24, // metadata length
            0, 9, // session ID
            1, 1, // New + Data
            2, // UDP
            0x14, 0xe9, // port 5353
            3,    // IPv6
        ];
        frame.extend_from_slice(&address.octets());
        frame.extend_from_slice(&4u16.to_be_bytes());
        frame.extend_from_slice(b"data");
        match decode_xudp_frame(&frame).expect("IPv6 XUDP frame") {
            XudpFrame::Data { target, .. } => assert_eq!(
                target.expect("target").address,
                "[2001:db8::7]:5353".parse().unwrap()
            ),
            XudpFrame::End => panic!("expected data frame"),
        }

        let target = ResolvedTarget::from_ip("[2001:db8::7]:5353".parse().unwrap());
        let mut output = [0u8; 80];
        output[48..52].copy_from_slice(b"data");
        let (start, length) =
            prepend_xudp_response(&mut output, 48, 4, 9, &target).expect("IPv6 response");
        assert_eq!(start, 20);
        assert_eq!(length, 32);
        assert_eq!(&output[start..start + 2], &24u16.to_be_bytes());
        assert_eq!(output[start + 9], 3);
        assert_eq!(&output[start + 10..start + 26], &address.octets());
        assert_eq!(&output[48..52], b"data");
    }
}
