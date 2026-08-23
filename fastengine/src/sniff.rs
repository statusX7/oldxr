const MAX_ATTEMPTS: u8 = 2;
const MAX_SNIFF_BYTES: usize = 32 * 1024;
pub const PROTOCOL_BITTORRENT: u8 = 1;

#[derive(Debug, Eq, PartialEq)]
pub enum Decision {
    NeedMore,
    Original,
    Override(String),
}

#[derive(Debug)]
pub struct State {
    enabled: bool,
    detect_bittorrent: bool,
    protocols: u8,
    attempts: u8,
    observed: usize,
}

impl State {
    #[cfg(test)]
    pub fn new(enabled: bool) -> Self {
        Self::with_bittorrent(enabled, false)
    }

    pub fn with_bittorrent(enabled: bool, detect_bittorrent: bool) -> Self {
        Self {
            enabled,
            detect_bittorrent,
            protocols: 0,
            attempts: 0,
            observed: 0,
        }
    }

    pub fn protocols(&self) -> u8 {
        self.protocols
    }

    pub fn inspect(&mut self, payload: &[u8]) -> Decision {
        if !self.enabled && !self.detect_bittorrent {
            return Decision::Original;
        }
        if payload.is_empty() || payload.len() == self.observed {
            return Decision::NeedMore;
        }
        self.observed = payload.len();
        self.attempts = self.attempts.saturating_add(1);
        let bittorrent = if self.detect_bittorrent {
            sniff_bittorrent(payload)
        } else {
            ProtocolProbe::NoMatch
        };
        if bittorrent == ProtocolProbe::Found {
            self.protocols |= PROTOCOL_BITTORRENT;
        }
        let host = if self.enabled {
            sniff_http_tls(payload)
        } else {
            Probe::NoMatch
        };
        match host {
            Probe::Found(host) => Decision::Override(host),
            Probe::NeedMore if self.attempts < MAX_ATTEMPTS && payload.len() < MAX_SNIFF_BYTES => {
                Decision::NeedMore
            }
            Probe::NeedMore | Probe::NoMatch => match bittorrent {
                ProtocolProbe::NeedMore if payload.len() < 20 => Decision::NeedMore,
                ProtocolProbe::Found | ProtocolProbe::NeedMore | ProtocolProbe::NoMatch => {
                    Decision::Original
                }
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProtocolProbe {
    Found,
    NeedMore,
    NoMatch,
}

fn sniff_bittorrent(input: &[u8]) -> ProtocolProbe {
    const HEADER: &[u8; 20] = b"\x13BitTorrent protocol";
    if input.len() < HEADER.len() {
        return if HEADER.starts_with(input) {
            ProtocolProbe::NeedMore
        } else {
            ProtocolProbe::NoMatch
        };
    }
    if input.starts_with(HEADER) {
        ProtocolProbe::Found
    } else {
        ProtocolProbe::NoMatch
    }
}

pub fn udp_protocols(input: &[u8]) -> u8 {
    if sniff_utp(input) {
        PROTOCOL_BITTORRENT
    } else {
        0
    }
}

fn sniff_utp(input: &[u8]) -> bool {
    const HEADER_LEN: usize = 20;
    if input.len() < HEADER_LEN || input[0] & 0x0f != 1 || input[0] >> 4 > 4 {
        return false;
    }
    let mut extension = input[1];
    let mut offset = HEADER_LEN;
    while extension != 0 {
        if extension != 1 || input.len().saturating_sub(offset) < 2 {
            return false;
        }
        extension = input[offset];
        let length = usize::from(input[offset + 1]);
        offset += 2;
        if input.len().saturating_sub(offset) < length {
            return false;
        }
        offset += length;
    }
    true
}

enum Probe {
    Found(String),
    NeedMore,
    NoMatch,
}

fn eq_ignore_ascii_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(&left, &right)| left.eq_ignore_ascii_case(&right))
}

fn trim_ascii(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(u8::is_ascii_whitespace) {
        input = &input[1..];
    }
    while input.last().is_some_and(u8::is_ascii_whitespace) {
        input = &input[..input.len() - 1];
    }
    input
}

fn normalized_http_host(input: &[u8]) -> Option<String> {
    let input = trim_ascii(input);
    if input.is_empty() {
        return None;
    }
    let value = std::str::from_utf8(input).ok()?;
    let host = if let Some(bracketed) = value.strip_prefix('[') {
        let end = bracketed.find(']')?;
        let host = &bracketed[..end];
        let suffix = &bracketed[end + 1..];
        if !suffix.is_empty()
            && (!suffix.starts_with(':')
                || (!suffix[1..].is_empty() && suffix[1..].parse::<i64>().is_err()))
        {
            return None;
        }
        host
    } else {
        match value.matches(':').count() {
            0 => value,
            1 => {
                let (host, port) = value.rsplit_once(':')?;
                if !port.is_empty() && port.parse::<i64>().is_err() {
                    return None;
                }
                host
            }
            _ => return None,
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(host.to_lowercase())
}

fn sniff_http(input: &[u8]) -> Probe {
    const METHODS: [&[u8]; 7] = [
        b"get", b"post", b"head", b"put", b"delete", b"options", b"connect",
    ];
    let method = METHODS.iter().find(|method| {
        input.len() >= method.len() && eq_ignore_ascii_case(&input[..method.len()], method)
    });
    if method.is_none() {
        return if input.len() < METHODS.iter().map(|method| method.len()).max().unwrap() {
            Probe::NeedMore
        } else {
            Probe::NoMatch
        };
    }

    let Some(first_newline) = input.iter().position(|&byte| byte == b'\n') else {
        return Probe::NeedMore;
    };
    let mut headers = &input[first_newline + 1..];
    while !headers.is_empty() {
        let (line, remaining, complete) = match headers.iter().position(|&byte| byte == b'\n') {
            Some(index) => (&headers[..index], &headers[index + 1..], true),
            None => (headers, &[][..], false),
        };
        let line = trim_ascii(line);
        if line.is_empty() {
            return Probe::NoMatch;
        }
        if let Some(separator) = line.iter().position(|&byte| byte == b':') {
            if eq_ignore_ascii_case(trim_ascii(&line[..separator]), b"host") {
                return normalized_http_host(&line[separator + 1..])
                    .map(Probe::Found)
                    .unwrap_or(Probe::NoMatch);
            }
        }
        if !complete {
            return Probe::NeedMore;
        }
        headers = remaining;
    }
    Probe::NeedMore
}

fn sniff_tls(input: &[u8]) -> Probe {
    if input.len() < 5 {
        return Probe::NeedMore;
    }
    if input[0] != 0x16 || input[1] != 3 {
        return Probe::NoMatch;
    }
    let record_length = u16::from_be_bytes([input[3], input[4]]) as usize;
    if input.len() < 5 + record_length {
        return Probe::NeedMore;
    }
    let mut data = &input[5..5 + record_length];
    if data.len() < 42 {
        return Probe::NeedMore;
    }
    let session_id_length = data[38] as usize;
    if session_id_length > 32 || data.len() < 39 + session_id_length {
        return Probe::NeedMore;
    }
    data = &data[39 + session_id_length..];
    if data.len() < 2 {
        return Probe::NeedMore;
    }
    let cipher_suites_length = u16::from_be_bytes([data[0], data[1]]) as usize;
    if !cipher_suites_length.is_multiple_of(2) || data.len() < 2 + cipher_suites_length {
        return Probe::NoMatch;
    }
    data = &data[2 + cipher_suites_length..];
    let Some((&compression_length, rest)) = data.split_first() else {
        return Probe::NeedMore;
    };
    if rest.len() < compression_length as usize {
        return Probe::NeedMore;
    }
    data = &rest[compression_length as usize..];
    if data.len() < 2 {
        return Probe::NoMatch;
    }
    let extensions_length = u16::from_be_bytes([data[0], data[1]]) as usize;
    data = &data[2..];
    if data.len() != extensions_length {
        return Probe::NoMatch;
    }
    while !data.is_empty() {
        if data.len() < 4 {
            return Probe::NoMatch;
        }
        let extension = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        data = &data[4..];
        if data.len() < length {
            return Probe::NoMatch;
        }
        if extension == 0 {
            let mut names = &data[..length];
            if names.len() < 2 {
                return Probe::NoMatch;
            }
            let names_length = u16::from_be_bytes([names[0], names[1]]) as usize;
            names = &names[2..];
            if names.len() != names_length {
                return Probe::NoMatch;
            }
            while !names.is_empty() {
                if names.len() < 3 {
                    return Probe::NoMatch;
                }
                let name_type = names[0];
                let name_length = u16::from_be_bytes([names[1], names[2]]) as usize;
                names = &names[3..];
                if names.len() < name_length {
                    return Probe::NoMatch;
                }
                if name_type == 0 {
                    let Ok(host) = std::str::from_utf8(&names[..name_length]) else {
                        return Probe::NoMatch;
                    };
                    if host.is_empty() || host.ends_with('.') {
                        return Probe::NoMatch;
                    }
                    return Probe::Found(host.to_owned());
                }
                names = &names[name_length..];
            }
        }
        data = &data[length..];
    }
    Probe::NoMatch
}

fn sniff_http_tls(input: &[u8]) -> Probe {
    let http = sniff_http(input);
    if matches!(http, Probe::Found(_)) {
        return http;
    }
    let tls = sniff_tls(input);
    if matches!(tls, Probe::Found(_)) {
        return tls;
    }
    if matches!(http, Probe::NeedMore) || matches!(tls, Probe::NeedMore) {
        Probe::NeedMore
    } else {
        Probe::NoMatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_state_keeps_original_destination() {
        assert_eq!(
            State::new(false).inspect(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            Decision::Original
        );
    }

    #[test]
    fn detects_fragmented_bittorrent_without_destination_sniffing() {
        let mut state = State::with_bittorrent(false, true);
        assert_eq!(state.inspect(b"\x13BitTor"), Decision::NeedMore);
        assert_eq!(
            state.inspect(b"\x13BitTorrent protocolpayload"),
            Decision::Original
        );
        assert_eq!(state.protocols(), PROTOCOL_BITTORRENT);
    }

    #[test]
    fn non_bittorrent_payload_does_not_set_protocol() {
        let mut state = State::with_bittorrent(false, true);
        assert_eq!(state.inspect(b"GET / HTTP/1.1\r\n"), Decision::Original);
        assert_eq!(state.protocols(), 0);
    }

    #[test]
    fn detects_valid_utp_header_without_accepting_truncation() {
        let mut header = [0u8; 20];
        header[0] = 0x11;
        assert_eq!(udp_protocols(&header), PROTOCOL_BITTORRENT);
        assert_eq!(udp_protocols(&header[..19]), 0);
        header[0] = 0x15;
        assert_eq!(udp_protocols(&header), 0);

        let mut extended = vec![0x11, 1];
        extended.resize(20, 0);
        extended.extend_from_slice(&[0, 2, 7, 8]);
        assert_eq!(udp_protocols(&extended), PROTOCOL_BITTORRENT);
    }

    #[test]
    fn extracts_http_host_without_port() {
        let mut state = State::new(true);
        assert_eq!(
            state.inspect(b"GET / HTTP/1.1\r\nHost: Example.COM:8443\r\n\r\n"),
            Decision::Override("example.com".into())
        );
    }

    #[test]
    fn preserves_historical_http_host_forms() {
        for (host, expected) in [
            ("Example.COM.", "example.com."),
            ("[::1]:8443", "::1"),
            ("fixture_name.invalid:-1", "fixture_name.invalid"),
        ] {
            let mut state = State::new(true);
            let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            assert_eq!(
                state.inspect(request.as_bytes()),
                Decision::Override(expected.into())
            );
        }
    }

    #[test]
    fn waits_once_for_fragmented_http_header() {
        let mut state = State::new(true);
        assert_eq!(state.inspect(b"GET / HTTP/1.1\r\nHo"), Decision::NeedMore);
        assert_eq!(
            state.inspect(b"GET / HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n"),
            Decision::Override("fixture.invalid".into())
        );
    }

    #[test]
    fn random_payload_keeps_original_destination() {
        let mut state = State::new(true);
        assert_eq!(state.inspect(&[0x7f; 4096]), Decision::Original);
    }

    #[test]
    fn extracts_tls_sni() {
        let host = b"TLS.fixture.invalid";
        let names_length = 1 + 2 + host.len();
        let server_name_length = 2 + names_length;
        let extension_length = 4 + server_name_length;
        let mut body = vec![0u8; 39];
        body[0] = 1;
        body[38] = 0;
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extension_length as u16).to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&(server_name_length as u16).to_be_bytes());
        body.extend_from_slice(&(names_length as u16).to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        body.extend_from_slice(host);
        let mut hello = vec![0u8; 5];
        hello[0] = 0x16;
        hello[1] = 3;
        hello[2] = 3;
        hello[3..5].copy_from_slice(&(body.len() as u16).to_be_bytes());
        hello.extend_from_slice(&body);

        let mut state = State::new(true);
        assert_eq!(
            state.inspect(&hello),
            Decision::Override("TLS.fixture.invalid".into())
        );
    }
}
