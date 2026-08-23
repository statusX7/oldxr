// VMess AEAD codec adapted from Shoes (MIT), commit 7a5a8ee3bd1c52bc15ec57e074e95e374d41f275.
// This lab prototype keeps the trusted wire/crypto construction while replacing the socket runtime.

use crate::netaddr::ResolvedTarget;
use aws_lc_rs::aead::{Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_128_GCM};
use aws_lc_rs::cipher::{
    DecryptingKey as CipherDecryptingKey, DecryptionContext, UnboundCipherKey, AES_128,
};
use aws_lc_rs::digest::{Context, SHA256};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::{aead::Nonce, aead::NonceSequence};
use digest::XofReader;
use md5::{Digest, Md5};
use shake::digest::{ExtendableOutput, Update};
use shake::Shake128;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant, SystemTime};
use uuid::Uuid;

const TAG_LEN: usize = 16;
const MAX_PADDING_LEN: usize = 64;
const PADDING_RANDOM_CACHE_SIZE: usize = 16 * 1024;
const MAX_ENCRYPTED_WRITE_DATA_SIZE: usize = 8192 + TAG_LEN;

pub struct VmessNonceSequence {
    count: u16,
    nonce: [u8; 12],
}

impl VmessNonceSequence {
    fn new(data: &[u8]) -> Self {
        let mut nonce = [0u8; 12];
        nonce[2..].copy_from_slice(&data[2..12]);
        Self { count: 0, nonce }
    }
}

impl NonceSequence for VmessNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let nonce = Nonce::assume_unique_for_key(self.nonce);
        self.count = self.count.wrapping_add(1);
        self.nonce[0] = (self.count >> 8) as u8;
        self.nonce[1] = self.count as u8;
        Ok(nonce)
    }
}

struct SingleUseNonce {
    nonce: [u8; 12],
    used: bool,
}

impl SingleUseNonce {
    fn new(data: &[u8]) -> Self {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(data);
        Self { nonce, used: false }
    }
}

impl NonceSequence for SingleUseNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        if self.used {
            return Err(Unspecified);
        }
        self.used = true;
        Nonce::try_assume_unique_for_key(&self.nonce)
    }
}

trait VmessHash: std::fmt::Debug {
    fn setup_new(&self) -> Box<dyn VmessHash>;
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> [u8; 32];
}

#[derive(Clone)]
struct Sha256Hash(Context);

impl std::fmt::Debug for Sha256Hash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Sha256Hash")
    }
}

impl VmessHash for Sha256Hash {
    fn setup_new(&self) -> Box<dyn VmessHash> {
        Box::new(self.clone())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        self.0.clone().finish().as_ref().try_into().unwrap()
    }
}

#[derive(Debug)]
struct RecursiveHash {
    inner: Box<dyn VmessHash>,
    outer: Box<dyn VmessHash>,
    default_inner: [u8; 64],
    default_outer: [u8; 64],
}

impl RecursiveHash {
    fn new(key: &[u8], hash: Box<dyn VmessHash>) -> Self {
        assert!(key.len() <= 64);
        let mut default_outer = [0x5c; 64];
        let mut default_inner = [0x36; 64];
        for (index, byte) in key.iter().enumerate() {
            default_outer[index] ^= byte;
            default_inner[index] ^= byte;
        }
        let mut inner = hash.setup_new();
        let outer = hash;
        inner.update(&default_inner);
        Self {
            inner,
            outer,
            default_inner,
            default_outer,
        }
    }
}

impl VmessHash for RecursiveHash {
    fn setup_new(&self) -> Box<dyn VmessHash> {
        Box::new(Self {
            inner: self.inner.setup_new(),
            outer: self.outer.setup_new(),
            default_inner: self.default_inner,
            default_outer: self.default_outer,
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        self.outer.update(&self.default_outer);
        self.outer.update(&self.inner.finalize());
        self.outer.finalize()
    }
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut current: Box<dyn VmessHash> = Box::new(RecursiveHash::new(
        b"VMess AEAD KDF",
        Box::new(Sha256Hash(Context::new(&SHA256))),
    ));
    for item in path {
        current = Box::new(RecursiveHash::new(item, current));
    }
    current.update(key);
    current.finalize()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    aws_lc_rs::digest::digest(&SHA256, data)
        .as_ref()
        .try_into()
        .unwrap()
}

fn md5(data: &[u8]) -> [u8; 16] {
    let mut context = Md5::new();
    Digest::update(&mut context, data);
    context.finalize().into()
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn fnv1a(data: &[u8]) -> u32 {
    data.iter().fold(0x811c_9dc5u32, |hash, byte| {
        (hash ^ *byte as u32).wrapping_mul(16_777_619)
    })
}

struct ServerUser {
    runtime_index: usize,
    identity: [u8; 16],
    instruction_key: [u8; 16],
    auth_key: CipherDecryptingKey,
}

struct SessionReplayFilter {
    entries: HashMap<[u8; 48], Instant>,
    cleanup_at: Instant,
    ttl: Duration,
    capacity: usize,
}

impl SessionReplayFilter {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            cleanup_at: Instant::now() + Duration::from_secs(30),
            ttl,
            capacity,
        }
    }

    fn check_and_add(&mut self, key: [u8; 48]) -> bool {
        self.check_and_add_at(key, Instant::now())
    }

    fn check_and_add_at(&mut self, key: [u8; 48], now: Instant) -> bool {
        if now >= self.cleanup_at || self.entries.len() >= self.capacity {
            self.entries.retain(|_, expires| *expires > now);
            self.cleanup_at = now + Duration::from_secs(30);
        }
        if self.entries.get(&key).is_some_and(|expires| *expires > now) {
            return true;
        }
        if self.entries.len() >= self.capacity {
            return true;
        }
        self.entries.insert(key, now + self.ttl);
        false
    }
}

struct ReplayFilter {
    current: HashSet<[u8; 16]>,
    previous: HashSet<[u8; 16]>,
    rotated_at: Instant,
}

impl ReplayFilter {
    fn check_and_add(&mut self, auth_id: [u8; 16]) -> bool {
        let elapsed = self.rotated_at.elapsed();
        if elapsed >= Duration::from_secs(120) {
            if elapsed >= Duration::from_secs(240) {
                self.previous.clear();
            } else {
                self.previous = std::mem::take(&mut self.current);
            }
            self.current.clear();
            self.rotated_at = Instant::now();
        }
        if self.current.contains(&auth_id) || self.previous.contains(&auth_id) {
            return true;
        }
        if self.current.len() >= 131_072 {
            return true;
        }
        self.current.insert(auth_id);
        false
    }
}

pub struct Credentials {
    users: Vec<ServerUser>,
    replay: ReplayFilter,
    session_replay: SessionReplayFilter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Tcp,
    Udp,
    Mux,
}

pub struct Handshake {
    pub consumed: usize,
    pub target: Option<ResolvedTarget>,
    pub command: Command,
    pub session: Session,
    pub user_index: usize,
}

fn parse_target(input: &[u8], cursor: &mut usize, port: u16) -> io::Result<ResolvedTarget> {
    let address_type = *input
        .get(*cursor)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short VMess destination"))?;
    *cursor += 1;
    match address_type {
        1 => {
            if *cursor + 4 > input.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short VMess IPv4 destination",
                ));
            }
            let ip = Ipv4Addr::new(
                input[*cursor],
                input[*cursor + 1],
                input[*cursor + 2],
                input[*cursor + 3],
            );
            *cursor += 4;
            Ok(ResolvedTarget::from_ip(SocketAddr::V4(SocketAddrV4::new(
                ip, port,
            ))))
        }
        2 => {
            let length = *input
                .get(*cursor)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short VMess domain"))?
                as usize;
            *cursor += 1;
            if *cursor + length > input.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short VMess domain",
                ));
            }
            let host = std::str::from_utf8(&input[*cursor..*cursor + length])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid VMess domain"))?;
            *cursor += length;
            ResolvedTarget::from_domain(host, port)
        }
        3 => {
            if *cursor + 16 > input.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short VMess IPv6 destination",
                ));
            }
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&input[*cursor..*cursor + 16]).unwrap());
            *cursor += 16;
            Ok(ResolvedTarget::from_ip(SocketAddr::V6(SocketAddrV6::new(
                ip, port, 0, 0,
            ))))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported VMess destination type",
        )),
    }
}

impl Credentials {
    pub fn new(user_ids: &[String]) -> io::Result<Self> {
        let mut users = Vec::with_capacity(user_ids.len());
        for (runtime_index, user_id) in user_ids.iter().enumerate() {
            let uuid = Uuid::parse_str(user_id)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            users.push(Self::build_user(runtime_index, uuid));
        }
        Ok(Self {
            users,
            replay: ReplayFilter {
                current: HashSet::new(),
                previous: HashSet::new(),
                rotated_at: Instant::now(),
            },
            session_replay: SessionReplayFilter::new(131_072, Duration::from_secs(180)),
        })
    }

    fn build_user(runtime_index: usize, uuid: Uuid) -> ServerUser {
        let mut key_material = Vec::with_capacity(52);
        key_material.extend_from_slice(uuid.as_bytes());
        key_material.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let instruction_key = md5(&key_material);
        let derived = kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
        let unbound = UnboundCipherKey::new(&AES_128, &derived[..16]).unwrap();
        ServerUser {
            runtime_index,
            identity: *uuid.as_bytes(),
            instruction_key,
            auth_key: CipherDecryptingKey::ecb(unbound).unwrap(),
        }
    }

    pub fn replace(&mut self, users: &[(usize, Uuid)]) {
        self.users = users
            .iter()
            .map(|&(runtime_index, uuid)| Self::build_user(runtime_index, uuid))
            .collect();
    }

    pub fn parse_handshake(
        &mut self,
        input: &mut [u8],
        available: usize,
    ) -> io::Result<Option<Handshake>> {
        const PREFIX_LEN: usize = 16 + 18 + 8;
        if available < PREFIX_LEN {
            return Ok(None);
        }
        let auth_id: [u8; 16] = input[..16].try_into().unwrap();
        let now = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
        let mut authenticated = None;
        for user in &self.users {
            let mut plaintext = auth_id;
            if user
                .auth_key
                .decrypt(&mut plaintext, DecryptionContext::None)
                .is_err()
            {
                continue;
            }
            if crc32(&plaintext[..12]) != u32::from_be_bytes(plaintext[12..].try_into().unwrap()) {
                continue;
            }
            let timestamp = u64::from_be_bytes(plaintext[..8].try_into().unwrap());
            if timestamp.abs_diff(now) <= 120 {
                authenticated = Some((user.runtime_index, user.identity, user.instruction_key));
                break;
            }
        }
        let (user_index, user_identity, instruction_key) = authenticated.ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "VMess AuthID rejected")
        })?;

        let nonce: [u8; 8] = input[34..42].try_into().unwrap();
        let mut encrypted_length: [u8; 18] = input[16..34].try_into().unwrap();
        let length_key = kdf(
            &instruction_key,
            &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
        );
        let length_nonce = kdf(
            &instruction_key,
            &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
        );
        let unbound = UnboundKey::new(&AES_128_GCM, &length_key[..16]).unwrap();
        OpeningKey::new(unbound, SingleUseNonce::new(&length_nonce[..12]))
            .open_in_place(Aad::from(&auth_id), &mut encrypted_length)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid VMess header length")
            })?;
        let header_len = u16::from_be_bytes(encrypted_length[..2].try_into().unwrap()) as usize;
        let consumed = PREFIX_LEN + header_len + TAG_LEN;
        if available < consumed {
            return Ok(None);
        }
        if self.replay.check_and_add(auth_id) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VMess AuthID replay rejected",
            ));
        }

        let header_key = kdf(
            &instruction_key,
            &[b"VMess Header AEAD Key", &auth_id, &nonce],
        );
        let header_nonce = kdf(
            &instruction_key,
            &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
        );
        let encrypted_header = &mut input[PREFIX_LEN..consumed];
        let unbound = UnboundKey::new(&AES_128_GCM, &header_key[..16]).unwrap();
        OpeningKey::new(unbound, SingleUseNonce::new(&header_nonce[..12]))
            .open_in_place(Aad::from(&auth_id), encrypted_header)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid VMess header"))?;
        let header = &encrypted_header[..header_len];
        if header.len() < 42 || header[0] != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid VMess request",
            ));
        }
        let command = match header[37] {
            1 => Command::Tcp,
            2 => Command::Udp,
            3 => Command::Mux,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported VMess command",
                ));
            }
        };
        let option = header[34];
        if option & 0x01 == 0 || option & 0x10 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported VMess option",
            ));
        }
        let masked = option & 0x04 != 0;
        let padded = option & 0x08 != 0;
        if padded && !masked {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid VMess padding",
            ));
        }
        if header[35] & 0x0f != 3 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "prototype supports AES-128-GCM only",
            ));
        }

        let margin = (header[35] >> 4) as usize;
        let mut cursor = 38usize;
        let target = if command == Command::Mux {
            None
        } else {
            if cursor + 3 > header.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short VMess destination",
                ));
            }
            let port = u16::from_be_bytes(header[cursor..cursor + 2].try_into().unwrap());
            cursor += 2;
            Some(parse_target(header, &mut cursor, port)?)
        };
        if cursor + margin + 4 > header.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short VMess header",
            ));
        }
        cursor += margin;
        let expected = u32::from_be_bytes(header[cursor..cursor + 4].try_into().unwrap());
        if fnv1a(&header[..cursor]) != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess header checksum",
            ));
        }

        let request_iv: [u8; 16] = header[1..17].try_into().unwrap();
        let request_key: [u8; 16] = header[17..33].try_into().unwrap();
        let mut session_id = [0u8; 48];
        session_id[..16].copy_from_slice(&user_identity);
        session_id[16..32].copy_from_slice(&request_key);
        session_id[32..].copy_from_slice(&request_iv);
        if self.session_replay.check_and_add(session_id) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VMess session replay rejected",
            ));
        }
        let response_auth = header[33];
        let response_iv: [u8; 16] = sha256(&request_iv)[..16].try_into().unwrap();
        let response_key: [u8; 16] = sha256(&request_key)[..16].try_into().unwrap();
        let opening = OpeningKey::new(
            UnboundKey::new(&AES_128_GCM, &request_key).unwrap(),
            VmessNonceSequence::new(&request_iv),
        );
        let sealing = SealingKey::new(
            UnboundKey::new(&AES_128_GCM, &response_key).unwrap(),
            VmessNonceSequence::new(&response_iv),
        );
        let read_mask = masked.then(|| {
            let mut hash = Shake128::default();
            hash.update(&request_iv);
            LengthMask::new(hash.finalize_xof(), padded)
        });
        let write_mask = masked.then(|| {
            let mut hash = Shake128::default();
            hash.update(&response_iv);
            LengthMask::new(hash.finalize_xof(), padded)
        });
        let response_prefix = build_response_prefix(response_auth, &response_key, &response_iv)?;

        Ok(Some(Handshake {
            consumed,
            target,
            command,
            session: Session {
                opening,
                sealing,
                read_mask,
                write_mask,
                pending_frame: None,
                response_prefix: Some(response_prefix),
            },
            user_index,
        }))
    }
}

struct LengthMask {
    reader: shake::Shake128Reader,
    mask: [u8; 2],
    padding: bool,
}

impl LengthMask {
    fn new(reader: shake::Shake128Reader, padding: bool) -> Self {
        Self {
            reader,
            mask: [0; 2],
            padding,
        }
    }

    fn next_u16(&mut self) -> u16 {
        self.reader.read(&mut self.mask);
        u16::from_be_bytes(self.mask)
    }

    fn next_values(&mut self) -> (usize, u16) {
        let padding = if self.padding {
            (self.next_u16() % MAX_PADDING_LEN as u16) as usize
        } else {
            0
        };
        (padding, self.next_u16())
    }
}

fn build_response_prefix(
    response_auth: u8,
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
) -> io::Result<Vec<u8>> {
    let mut output = vec![0u8; 2 + TAG_LEN + 4 + TAG_LEN];
    output[1] = 4;
    let key = kdf(response_key, &[b"AEAD Resp Header Len Key"]);
    let nonce = kdf(response_iv, &[b"AEAD Resp Header Len IV"]);
    let unbound = UnboundKey::new(&AES_128_GCM, &key[..16]).unwrap();
    let tag = SealingKey::new(unbound, SingleUseNonce::new(&nonce[..12]))
        .seal_in_place_separate_tag(Aad::empty(), &mut output[..2])
        .map_err(|_| io::Error::other("response length encryption"))?;
    output[2..2 + TAG_LEN].copy_from_slice(tag.as_ref());

    let offset = 2 + TAG_LEN;
    output[offset..offset + 4].copy_from_slice(&[response_auth, 0, 0, 0]);
    let key = kdf(response_key, &[b"AEAD Resp Header Key"]);
    let nonce = kdf(response_iv, &[b"AEAD Resp Header IV"]);
    let unbound = UnboundKey::new(&AES_128_GCM, &key[..16]).unwrap();
    let tag = SealingKey::new(unbound, SingleUseNonce::new(&nonce[..12]))
        .seal_in_place_separate_tag(Aad::empty(), &mut output[offset..offset + 4])
        .map_err(|_| io::Error::other("response header encryption"))?;
    output[offset + 4..].copy_from_slice(tag.as_ref());
    Ok(output)
}

pub enum DecodeResult {
    NeedMore {
        consumed: usize,
    },
    Plain {
        start: usize,
        length: usize,
        resume: usize,
    },
    Eof,
}

pub struct Session {
    opening: OpeningKey<VmessNonceSequence>,
    sealing: SealingKey<VmessNonceSequence>,
    read_mask: Option<LengthMask>,
    write_mask: Option<LengthMask>,
    pending_frame: Option<(usize, usize)>,
    response_prefix: Option<Vec<u8>>,
}

pub struct PaddingRandom {
    bytes: [u8; PADDING_RANDOM_CACHE_SIZE],
    used: usize,
}

impl PaddingRandom {
    pub fn new() -> Self {
        Self {
            bytes: [0; PADDING_RANDOM_CACHE_SIZE],
            used: PADDING_RANDOM_CACHE_SIZE,
        }
    }

    fn fill(&mut self, output: &mut [u8]) -> io::Result<()> {
        let mut written = 0;
        while written < output.len() {
            if self.used == self.bytes.len() {
                SystemRandom::new()
                    .fill(&mut self.bytes)
                    .map_err(|_| io::Error::other("VMess padding RNG"))?;
                self.used = 0;
            }
            let count = (output.len() - written).min(self.bytes.len() - self.used);
            output[written..written + count]
                .copy_from_slice(&self.bytes[self.used..self.used + count]);
            self.used += count;
            written += count;
        }
        Ok(())
    }
}

impl Session {
    pub fn decode(
        &mut self,
        input: &mut [u8],
        start: usize,
        end: usize,
    ) -> io::Result<DecodeResult> {
        let mut data_start = start;
        let (padding, data_len) = match self.pending_frame {
            Some(value) => value,
            None => {
                if end - start < 2 {
                    return Ok(DecodeResult::NeedMore { consumed: start });
                }
                let mut length = u16::from_be_bytes(input[start..start + 2].try_into().unwrap());
                let padding = match self.read_mask.as_mut() {
                    Some(mask) => {
                        let (padding, length_mask) = mask.next_values();
                        length ^= length_mask;
                        padding
                    }
                    None => 0,
                };
                let length = length as usize;
                if length < padding + TAG_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "VMess frame length",
                    ));
                }
                data_start += 2;
                self.pending_frame = Some((padding, length));
                (padding, length)
            }
        };
        if end - data_start < data_len {
            return Ok(DecodeResult::NeedMore {
                consumed: data_start,
            });
        }
        self.pending_frame = None;
        if data_len - padding == TAG_LEN {
            return Ok(DecodeResult::Eof);
        }
        let encrypted_end = data_start + data_len - padding;
        self.opening
            .open_in_place(Aad::empty(), &mut input[data_start..encrypted_end])
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "VMess payload authentication")
            })?;
        Ok(DecodeResult::Plain {
            start: data_start,
            length: data_len - padding - TAG_LEN,
            resume: data_start + data_len,
        })
    }

    pub fn finish_fixed_encode(
        &mut self,
        output: &mut [u8],
        payload_start: usize,
        data_len: usize,
        padding_random: &mut PaddingRandom,
    ) -> io::Result<(usize, usize)> {
        if data_len > MAX_ENCRYPTED_WRITE_DATA_SIZE - TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid VMess output payload length",
            ));
        }
        let length_start = payload_start.checked_sub(2).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing VMess frame headroom")
        })?;
        let send_start = if let Some(prefix) = self.response_prefix.take() {
            let start = length_start.checked_sub(prefix.len()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing VMess response headroom",
                )
            })?;
            output[start..length_start].copy_from_slice(&prefix);
            start
        } else {
            length_start
        };
        let (padding, length_mask) = match self.write_mask.as_mut() {
            Some(mask) => mask.next_values(),
            None => (0, 0),
        };
        if payload_start + data_len + TAG_LEN + padding > output.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess output buffer too small",
            ));
        }
        let masked_len = ((data_len + TAG_LEN + padding) as u16) ^ length_mask;
        output[length_start..payload_start].copy_from_slice(&masked_len.to_be_bytes());
        let tag = self
            .sealing
            .seal_in_place_separate_tag(
                Aad::empty(),
                &mut output[payload_start..payload_start + data_len],
            )
            .map_err(|_| io::Error::other("VMess payload encryption"))?;
        let mut end = payload_start + data_len;
        output[end..end + TAG_LEN].copy_from_slice(tag.as_ref());
        end += TAG_LEN;
        if padding > 0 {
            padding_random.fill(&mut output[end..end + padding])?;
            end += padding;
        }
        Ok((send_start, end - send_start))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_known_ieee_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn padding_random_cache_refills_across_boundaries() {
        let mut random = PaddingRandom::new();
        random.fill(&mut []).unwrap();
        assert_eq!(random.used, PADDING_RANDOM_CACHE_SIZE);

        random.fill(&mut [0; MAX_PADDING_LEN - 1]).unwrap();
        assert_eq!(random.used, MAX_PADDING_LEN - 1);

        let mut crossing = vec![0; PADDING_RANDOM_CACHE_SIZE];
        random.fill(&mut crossing).unwrap();
        assert_eq!(random.used, MAX_PADDING_LEN - 1);
    }

    #[test]
    fn replay_filter_rejects_duplicate() {
        let mut filter = ReplayFilter {
            current: HashSet::new(),
            previous: HashSet::new(),
            rotated_at: Instant::now(),
        };
        assert!(!filter.check_and_add([1; 16]));
        assert!(filter.check_and_add([1; 16]));
        assert!(!filter.check_and_add([2; 16]));
    }

    #[test]
    fn parses_domain_and_ipv6_targets() {
        let mut domain = vec![2, 9];
        domain.extend_from_slice(b"localhost");
        let mut cursor = 0;
        let target = parse_target(&domain, &mut cursor, 443).expect("domain target");
        assert_eq!(target.host, "localhost");
        assert_eq!(target.address, None);
        assert_eq!(target.port(), 443);
        assert_eq!(cursor, domain.len());

        let mut ipv6 = vec![3];
        ipv6.extend_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        let mut cursor = 0;
        let target = parse_target(&ipv6, &mut cursor, 8443).expect("IPv6 target");
        assert_eq!(target.address, Some("[2001:db8::7]:8443".parse().unwrap()));
        assert_eq!(target.host, "2001:db8::7");
        assert_eq!(cursor, ipv6.len());
    }

    #[test]
    fn session_replay_is_scoped_expires_and_fails_closed() {
        let ttl = Duration::from_secs(180);
        let started = Instant::now();
        let mut filter = SessionReplayFilter::new(2, ttl);
        let mut first = [0u8; 48];
        first[..16].fill(1);
        first[16..32].fill(2);
        first[32..].fill(3);
        assert!(!filter.check_and_add_at(first, started));
        assert!(filter.check_and_add_at(first, started + Duration::from_secs(1)));

        let mut other_user = first;
        other_user[..16].fill(4);
        assert!(!filter.check_and_add_at(other_user, started + Duration::from_secs(1)));

        let mut saturated = first;
        saturated[16..32].fill(5);
        assert!(filter.check_and_add_at(saturated, started + Duration::from_secs(1)));
        assert!(!filter.check_and_add_at(first, started + ttl + Duration::from_secs(1)));
    }
}
