use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TcpTimeouts {
    handshake: Duration,
    connection_idle: Duration,
    uplink_only: Duration,
    downlink_only: Duration,
}

impl TcpTimeouts {
    pub(crate) fn from_seconds(
        handshake: usize,
        connection_idle: usize,
        uplink_only: usize,
        downlink_only: usize,
    ) -> Self {
        Self {
            handshake: Duration::from_secs(handshake as u64),
            connection_idle: Duration::from_secs(connection_idle as u64),
            uplink_only: Duration::from_secs(uplink_only as u64),
            downlink_only: Duration::from_secs(downlink_only as u64),
        }
    }

    fn duration(self, phase: TcpTimeoutPhase) -> Duration {
        match phase {
            TcpTimeoutPhase::Handshake => self.handshake,
            TcpTimeoutPhase::Bidirectional => self.connection_idle,
            TcpTimeoutPhase::UplinkOnly => self.uplink_only,
            TcpTimeoutPhase::DownlinkOnly => self.downlink_only,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpTimeoutPhase {
    Handshake,
    Bidirectional,
    UplinkOnly,
    DownlinkOnly,
}

pub(crate) struct TcpTimeoutState {
    phase: TcpTimeoutPhase,
    since: Instant,
    activity: bool,
}

impl TcpTimeoutState {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            phase: TcpTimeoutPhase::Handshake,
            since: now,
            activity: false,
        }
    }

    pub(crate) fn authenticated(&mut self, now: Instant) {
        self.phase = TcpTimeoutPhase::Bidirectional;
        self.since = now;
        self.activity = false;
    }

    // Keep the steady path to one boolean store. The coarse policy sweep
    // converts observed activity into a timestamp at most one second later.
    pub(crate) fn note_activity(&mut self) {
        if self.phase != TcpTimeoutPhase::Handshake {
            self.activity = true;
        }
    }

    // Upload is client -> target. Once it ends, only download remains.
    pub(crate) fn upload_closed(&mut self, now: Instant, timeouts: TcpTimeouts) -> bool {
        self.transition(now, TcpTimeoutPhase::DownlinkOnly, timeouts)
    }

    // Download is target -> client. Once it ends, only upload remains.
    pub(crate) fn download_closed(&mut self, now: Instant, timeouts: TcpTimeouts) -> bool {
        self.transition(now, TcpTimeoutPhase::UplinkOnly, timeouts)
    }

    fn transition(&mut self, now: Instant, phase: TcpTimeoutPhase, timeouts: TcpTimeouts) -> bool {
        if self.phase == TcpTimeoutPhase::Handshake {
            return false;
        }
        if self.phase != TcpTimeoutPhase::Bidirectional {
            return timeouts.duration(self.phase).is_zero();
        }
        self.phase = phase;
        self.since = now;
        self.activity = false;
        timeouts.duration(phase).is_zero()
    }

    pub(crate) fn expired(&mut self, now: Instant, timeouts: TcpTimeouts) -> bool {
        if self.phase != TcpTimeoutPhase::Handshake && self.activity {
            self.activity = false;
            self.since = now;
            return false;
        }
        let timeout = timeouts.duration(self.phase);
        timeout.is_zero() || now.saturating_duration_since(self.since) >= timeout
    }
}

#[cfg(test)]
mod tests {
    use super::{TcpTimeoutState, TcpTimeouts};
    use std::time::{Duration, Instant};

    fn policy() -> TcpTimeouts {
        TcpTimeouts::from_seconds(4, 10, 2, 3)
    }

    #[test]
    fn handshake_uses_absolute_deadline() {
        let start = Instant::now();
        let mut state = TcpTimeoutState::new(start);
        state.note_activity();
        assert!(!state.expired(start + Duration::from_secs(3), policy()));
        assert!(state.expired(start + Duration::from_secs(4), policy()));
    }

    #[test]
    fn authenticated_activity_refreshes_idle_window() {
        let start = Instant::now();
        let mut state = TcpTimeoutState::new(start);
        state.authenticated(start);
        state.note_activity();
        assert!(!state.expired(start + Duration::from_secs(9), policy()));
        assert!(!state.expired(start + Duration::from_secs(18), policy()));
        assert!(state.expired(start + Duration::from_secs(19), policy()));
    }

    #[test]
    fn half_close_selects_directional_timeout() {
        let start = Instant::now();
        let mut upload = TcpTimeoutState::new(start);
        upload.authenticated(start);
        assert!(!upload.upload_closed(start, policy()));
        assert!(!upload.expired(start + Duration::from_secs(2), policy()));
        assert!(upload.expired(start + Duration::from_secs(3), policy()));

        let mut download = TcpTimeoutState::new(start);
        download.authenticated(start);
        assert!(!download.download_closed(start, policy()));
        assert!(!download.expired(start + Duration::from_secs(1), policy()));
        assert!(download.expired(start + Duration::from_secs(2), policy()));
    }

    #[test]
    fn zero_direction_timeout_closes_immediately() {
        let start = Instant::now();
        let zero = TcpTimeouts::from_seconds(4, 10, 0, 0);
        let mut state = TcpTimeoutState::new(start);
        state.authenticated(start);
        assert!(state.upload_closed(start, zero));
    }
}
