use crate::netaddr::ResolvedTarget;
use serde::Deserialize;
use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;

pub const NETWORK_TCP: u8 = 1;
pub const NETWORK_UDP: u8 = 2;
pub const PROTOCOL_BITTORRENT: u8 = 1;

const MAX_OUTBOUNDS: usize = u16::MAX as usize;
const MAX_RULES: usize = 4096;
const MAX_PREFIXES_PER_RULE: usize = 65_536;
const MAX_PORT_RANGES_PER_RULE: usize = 65_536;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DomainStrategy {
    #[default]
    AsIs,
    IpOnDemand,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundAction {
    Direct,
    Blackhole,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundDomainStrategy {
    AsIs,
    UseIpv6,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OutboundConfig {
    pub tag: String,
    pub action: OutboundAction,
    pub domain_strategy: OutboundDomainStrategy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub struct PortRangeConfig {
    pub from: u16,
    pub to: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RuleConfig {
    pub outbound: u16,
    pub networks: u8,
    #[serde(default)]
    pub network_constraint: bool,
    #[serde(default)]
    pub ports: Vec<PortRangeConfig>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub protocols: u8,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PlanConfig {
    #[serde(default)]
    pub domain_strategy: DomainStrategy,
    pub default_outbound: u16,
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Prefix {
    V4 { network: u32, bits: u8 },
    V6 { network: u128, bits: u8 },
}

impl Prefix {
    fn parse(value: &str) -> io::Result<Self> {
        let (address, bits) = value.split_once('/').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("routing CIDR {value:?} has no prefix length"),
            )
        })?;
        let address = IpAddr::from_str(address).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid routing CIDR {value:?}: {error}"),
            )
        })?;
        let bits: u8 = bits.parse().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid routing CIDR {value:?}: {error}"),
            )
        })?;
        match address {
            IpAddr::V4(address) if bits <= 32 => {
                let mask = mask32(bits);
                Ok(Self::V4 {
                    network: u32::from(address) & mask,
                    bits,
                })
            }
            IpAddr::V6(address) if bits <= 128 => {
                let mask = mask128(bits);
                Ok(Self::V6 {
                    network: u128::from(address) & mask,
                    bits,
                })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("routing CIDR {value:?} has an invalid prefix length"),
            )),
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, bits }, IpAddr::V4(address)) => {
                u32::from(address) & mask32(bits) == network
            }
            (Self::V6 { network, bits }, IpAddr::V6(address)) => {
                u128::from(address) & mask128(bits) == network
            }
            _ => false,
        }
    }
}

const fn mask32(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    }
}

const fn mask128(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    }
}

#[derive(Clone, Debug)]
struct Rule {
    outbound: u16,
    networks: u8,
    ports: Vec<PortRangeConfig>,
    prefixes: Vec<Prefix>,
    protocols: u8,
}

impl Rule {
    fn matches(&self, input: RouteInput) -> bool {
        if self.networks & input.network == 0 {
            return false;
        }
        if !self.ports.is_empty()
            && !self
                .ports
                .iter()
                .any(|range| input.port >= range.from && input.port <= range.to)
        {
            return false;
        }
        if !self.prefixes.is_empty()
            && !input
                .addresses
                .iter()
                .any(|&address| self.prefixes.iter().any(|prefix| prefix.contains(address)))
        {
            return false;
        }
        if self.protocols != 0 && self.protocols & input.protocols == 0 {
            return false;
        }
        true
    }
}

#[derive(Clone, Copy)]
pub struct RouteInput<'a> {
    pub network: u8,
    pub port: u16,
    pub addresses: &'a [IpAddr],
    pub protocols: u8,
}

pub struct Router {
    domain_strategy: DomainStrategy,
    default_outbound: u16,
    outbounds: Vec<OutboundConfig>,
    rules: Vec<Rule>,
    needs_bittorrent: bool,
}

impl Router {
    pub fn direct() -> Self {
        Self {
            domain_strategy: DomainStrategy::AsIs,
            default_outbound: 0,
            outbounds: vec![OutboundConfig {
                tag: "__fastengine_direct".to_owned(),
                action: OutboundAction::Direct,
                domain_strategy: OutboundDomainStrategy::AsIs,
            }],
            rules: Vec::new(),
            needs_bittorrent: false,
        }
    }

    pub fn compile(config: PlanConfig) -> io::Result<Self> {
        if config.outbounds.is_empty() || config.outbounds.len() > MAX_OUTBOUNDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "routing plan has an invalid outbound count",
            ));
        }
        if usize::from(config.default_outbound) >= config.outbounds.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "routing plan default outbound is out of bounds",
            ));
        }
        let mut tags = HashSet::with_capacity(config.outbounds.len());
        for outbound in &config.outbounds {
            if outbound.tag.is_empty() || !tags.insert(outbound.tag.as_str()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "routing plan contains an empty or duplicate tag {:?}",
                        outbound.tag
                    ),
                ));
            }
        }
        if config.rules.len() > MAX_RULES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "routing plan has too many rules",
            ));
        }
        let mut rules = Vec::with_capacity(config.rules.len());
        let mut needs_bittorrent = false;
        for (index, rule) in config.rules.into_iter().enumerate() {
            if usize::from(rule.outbound) >= config.outbounds.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("routing rule {index} outbound is out of bounds"),
                ));
            }
            if rule.networks == 0 || rule.networks & !(NETWORK_TCP | NETWORK_UDP) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("routing rule {index} has invalid network bits"),
                ));
            }
            if rule.protocols & !PROTOCOL_BITTORRENT != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("routing rule {index} has invalid protocol bits"),
                ));
            }
            if rule.ports.len() > MAX_PORT_RANGES_PER_RULE
                || rule
                    .ports
                    .iter()
                    .any(|range| range.from == 0 || range.from > range.to)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("routing rule {index} has invalid port ranges"),
                ));
            }
            if rule.cidrs.len() > MAX_PREFIXES_PER_RULE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("routing rule {index} has too many CIDRs"),
                ));
            }
            let prefixes = rule
                .cidrs
                .iter()
                .map(|cidr| Prefix::parse(cidr))
                .collect::<io::Result<Vec<_>>>()?;
            if !rule.network_constraint
                && rule.ports.is_empty()
                && prefixes.is_empty()
                && rule.protocols == 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("routing rule {index} has no match condition"),
                ));
            }
            needs_bittorrent |= rule.protocols & PROTOCOL_BITTORRENT != 0;
            rules.push(Rule {
                outbound: rule.outbound,
                networks: rule.networks,
                ports: rule.ports,
                prefixes,
                protocols: rule.protocols,
            });
        }
        Ok(Self {
            domain_strategy: config.domain_strategy,
            default_outbound: config.default_outbound,
            outbounds: config.outbounds,
            rules,
            needs_bittorrent,
        })
    }

    pub fn pick(&self, input: RouteInput<'_>) -> &OutboundConfig {
        let outbound = self
            .rules
            .iter()
            .find(|rule| rule.matches(input))
            .map_or(self.default_outbound, |rule| rule.outbound);
        &self.outbounds[usize::from(outbound)]
    }

    pub fn needs_bittorrent(&self) -> bool {
        self.needs_bittorrent
    }

    pub fn route_target(
        &self,
        network: u8,
        target: &ResolvedTarget,
        protocols: u8,
    ) -> io::Result<ResolvedTarget> {
        let address = target.address.ip();
        let addresses = if self.domain_strategy == DomainStrategy::IpOnDemand
            || target.host.parse::<IpAddr>().is_ok()
        {
            std::slice::from_ref(&address)
        } else {
            &[]
        };
        let outbound = self.pick(RouteInput {
            network,
            port: target.address.port(),
            addresses,
            protocols,
        });
        if outbound.action == OutboundAction::Blackhole {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("routing outbound {:?} rejected target", outbound.tag),
            ));
        }
        match outbound.domain_strategy {
            OutboundDomainStrategy::AsIs => Ok(target.clone()),
            OutboundDomainStrategy::UseIpv6 => target.resolve_ipv6(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn plan() -> Router {
        Router::compile(PlanConfig {
            domain_strategy: DomainStrategy::IpOnDemand,
            default_outbound: 0,
            outbounds: vec![
                OutboundConfig {
                    tag: "IPv4_out".into(),
                    action: OutboundAction::Direct,
                    domain_strategy: OutboundDomainStrategy::AsIs,
                },
                OutboundConfig {
                    tag: "IPv6_out".into(),
                    action: OutboundAction::Direct,
                    domain_strategy: OutboundDomainStrategy::UseIpv6,
                },
                OutboundConfig {
                    tag: "block".into(),
                    action: OutboundAction::Blackhole,
                    domain_strategy: OutboundDomainStrategy::AsIs,
                },
            ],
            rules: vec![
                RuleConfig {
                    outbound: 2,
                    networks: NETWORK_TCP | NETWORK_UDP,
                    network_constraint: false,
                    ports: Vec::new(),
                    cidrs: vec!["10.0.0.0/8".into(), "fc00::/7".into()],
                    protocols: 0,
                },
                RuleConfig {
                    outbound: 2,
                    networks: NETWORK_TCP,
                    network_constraint: false,
                    ports: Vec::new(),
                    cidrs: Vec::new(),
                    protocols: PROTOCOL_BITTORRENT,
                },
                RuleConfig {
                    outbound: 2,
                    networks: NETWORK_TCP | NETWORK_UDP,
                    network_constraint: false,
                    ports: vec![PortRangeConfig { from: 22, to: 25 }],
                    cidrs: Vec::new(),
                    protocols: 0,
                },
            ],
        })
        .unwrap()
    }

    #[test]
    fn preserves_first_match_and_default_outbound() {
        let router = plan();
        let private = [IpAddr::V4(Ipv4Addr::new(10, 2, 3, 4))];
        assert_eq!(
            router
                .pick(RouteInput {
                    network: NETWORK_TCP,
                    port: 443,
                    addresses: &private,
                    protocols: 0,
                })
                .action,
            OutboundAction::Blackhole
        );
        let public = [IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];
        assert_eq!(
            router
                .pick(RouteInput {
                    network: NETWORK_TCP,
                    port: 443,
                    addresses: &public,
                    protocols: 0,
                })
                .tag,
            "IPv4_out"
        );
    }

    #[test]
    fn matches_bittorrent_ports_and_ipv6() {
        let router = plan();
        let public = [IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];
        for input in [
            RouteInput {
                network: NETWORK_TCP,
                port: 443,
                addresses: &public,
                protocols: PROTOCOL_BITTORRENT,
            },
            RouteInput {
                network: NETWORK_UDP,
                port: 22,
                addresses: &public,
                protocols: 0,
            },
        ] {
            assert_eq!(router.pick(input).action, OutboundAction::Blackhole);
        }
        let private = [IpAddr::V6(Ipv6Addr::from_str("fd00::1").unwrap())];
        assert_eq!(
            router
                .pick(RouteInput {
                    network: NETWORK_UDP,
                    port: 53,
                    addresses: &private,
                    protocols: 0,
                })
                .action,
            OutboundAction::Blackhole
        );
    }

    #[test]
    fn rejects_out_of_bounds_handles_and_invalid_cidrs() {
        let mut config = PlanConfig {
            domain_strategy: DomainStrategy::AsIs,
            default_outbound: 1,
            outbounds: vec![OutboundConfig {
                tag: "direct".into(),
                action: OutboundAction::Direct,
                domain_strategy: OutboundDomainStrategy::AsIs,
            }],
            rules: Vec::new(),
        };
        assert!(Router::compile(config.clone()).is_err());
        config.default_outbound = 0;
        config.rules.push(RuleConfig {
            outbound: 0,
            networks: NETWORK_TCP,
            network_constraint: false,
            ports: Vec::new(),
            cidrs: vec!["not-a-cidr".into()],
            protocols: 0,
        });
        assert!(Router::compile(config).is_err());
    }

    #[test]
    fn route_target_applies_blackhole_and_ipv6_strategy() {
        let router = plan();
        let private = ResolvedTarget::from_ip("10.2.3.4:443".parse().unwrap());
        assert_eq!(
            router
                .route_target(NETWORK_TCP, &private, 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let literal = ResolvedTarget::from_ip("192.0.2.1:443".parse().unwrap());
        assert_eq!(
            router.route_target(NETWORK_TCP, &literal, 0).unwrap(),
            literal
        );
    }
}
