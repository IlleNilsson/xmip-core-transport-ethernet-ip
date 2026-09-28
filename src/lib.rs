#![forbid(unsafe_code)]

//! Streams that are the data of an `EtherNet/IP` assembly. One assembly
//! instance's data attribute is one Stream: reading it is a
//! `Get_Attribute_Single`, writing it a `Set_Attribute_Single`, each one
//! explicit message in a `SendRRData` on a registered session.
//!
//! `EtherNet/IP` is CIP — the same objects `DeviceNet` and `ControlNet`
//! carry — encapsulated on TCP port 44818 for explicit messages and UDP
//! for implicit IO. What is here is the encapsulation and its common packet
//! format ([`encapsulation`]), the explicit message and reply ([`cip`]), a
//! scanner that speaks them, and [`Adapter`] — one session's worth of
//! adapter holding assemblies as byte vectors, for tests and the loopback.
//! The carrier is `xmip-core-transport-tcp`: the scanner connects and the
//! adapter listens through it.
//!
//! The origin URI names the adapter and the assembly:
//! `enip://host:44818/assembly/100`. A target is `enip://host:44818/100`
//! for another instance, or `host:port` for the configured one.

pub mod adapter;
pub mod cip;
pub mod encapsulation;
pub mod scanner;

use std::net::TcpListener;
use std::time::Duration;

pub use adapter::Adapter;
pub use cip::{Path, Reply, Request};
pub use encapsulation::Packet;
use net::{Target, ceiling};
pub use scanner::Scanner;
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::{Arrived, Configured, Directions, Pool, Transport};
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

use crate::encapsulation::RR_OVERHEAD;

/// The largest Stream one set carries: what the sixteen-bit encapsulation
/// length names, less the `SendRRData` items and the request's service and
/// path. One attribute is set in one message; the protocol has no segments.
pub const CEILING: usize = 65_535 - RR_OVERHEAD - cip::REQUEST_OVERHEAD;

/// The assembly instance a Location speaks about unless it names another.
const DEFAULT_INSTANCE: u8 = 100;

#[derive(Clone)]
pub struct EtherNetIpTransport {
    bind: String,
    instance: u8,
    timeout: Option<Duration>,
    /// The sessions a receive gets on and a send sets on, registered once
    /// per adapter and kept.
    sessions: Pool<Scanner>,
}

impl EtherNetIpTransport {
    /// Listen or connect at `bind`, about assembly instance 100.
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            instance: DEFAULT_INSTANCE,
            timeout: None,
            sessions: Pool::new(),
        }
    }

    /// Speak about assembly `instance` instead.
    #[must_use]
    pub const fn about(mut self, instance: u8) -> Self {
        self.instance = instance;
        self
    }

    /// Give up on a peer that stops mid-message.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Bind through the carrier and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        tcp::TcpTransport::new(self.bind.clone()).bind()
    }

    /// Accept one scanner on an already-bound listener.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Adapter> {
        Adapter::accept(listener, self.timeout)
    }

    /// Connect to `address` and register a session.
    ///
    /// # Errors
    /// As [`Scanner::connect`].
    pub fn connect(&self, address: &str) -> Result<Scanner> {
        Scanner::connect(address, self.timeout)
    }

    /// `enip://host:44818/<instance>` or `host:port` as the address and the
    /// instance to speak about.
    fn resolve(&self, target: &str) -> Result<(String, u8)> {
        let Some((authority, path)) =
            Target::under(&["enip"], target).map(|named| (named.authority(), named.path()))
        else {
            return Ok((target.to_string(), self.instance));
        };
        let instance = if path.is_empty() {
            self.instance
        } else {
            path.parse()
                .map_err(|_| protocol_error(format!("{path:?} is not an assembly instance")))?
        };
        Ok((authority.to_string(), instance))
    }
}

impl Transport for EtherNetIpTransport {
    fn name(&self) -> &'static str {
        "ethernet-ip"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// One get of the assembly, on the session kept for the adapter and
    /// registered on the first receive: its data as one Stream.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let bytes = self.sessions.exchange(
            self.bind.as_str(),
            || self.connect(&self.bind),
            |scanner| scanner.get(self.instance),
        )?;
        Ok(vec![Arrived::new(
            format!("enip://{}/assembly/{}", self.bind, self.instance),
            bytes,
        )])
    }

    /// One set of the assembly `target` names, on the session kept for its
    /// adapter and registered on the first send.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (address, instance) = self.resolve(target)?;
        self.sessions.exchange(
            address.as_str(),
            || self.connect(&address),
            |scanner| scanner.set(instance, bytes),
        )
    }
}

impl Configured for EtherNetIpTransport {
    /// The address is the adapter's host and port: where a Location connects
    /// as a scanner, or listens as an adapter.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "instance",
                kind: Kind::Integer {
                    minimum: 1,
                    maximum: 255,
                },
                presence: Presence::Default(Fixed::Integer(DEFAULT_INSTANCE as i64)),
                meaning: "The assembly instance whose data attribute is the Stream.",
                applies: Applies::Both,
            },
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a peer that stops mid-message is waited on; unbounded when \
                          left out.",
                applies: Applies::Both,
            },
        ],
    };

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let instance = u8::try_from(settings.integer("instance"))
            .map_err(|_| protocol_error("an assembly instance is at most 255"))?;
        let transport = Self::new(address).about(instance);
        Ok(match settings.optional_duration("timeout") {
            Some(timeout) => transport.timing_out_after(timeout),
            None => transport,
        })
    }
}

impl EtherNetIpTransport {
    /// Both ends on this machine: an ephemeral local port, the loopback
    /// timeout on either side of the session.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0").timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for EtherNetIpTransport {
    fn take_one(self, listener: &TcpListener) -> Result<Arrived> {
        let instance = self.instance;
        let mut adapter = self
            .accept_one(listener)?
            .with_assembly(instance, Vec::new());
        adapter.serve()?;
        let bytes = adapter
            .assembly(instance)
            .ok_or_else(|| protocol_error("the assembly went missing"))?
            .to_vec();
        Ok(Arrived::new(adapter.origin(instance), bytes))
    }
}

impl Loopback for EtherNetIpTransport {
    /// One attribute is set in one encapsulation packet, and the packet's
    /// length is sixteen bits.
    fn ceiling(&self) -> Option<usize> {
        Some(CEILING)
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        ceiling::within(payload.len(), CEILING, "one set carries")?;
        Self::new("127.0.0.1:0")
            .about(self.instance)
            .timing_out_after(self.timeout.unwrap_or(LOOPBACK_TIMEOUT))
            .send(address, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use transport::payload::edge_payloads;
    use xcore::settings::Given;

    /// The shapes a protocol breaks on, as the Playground lists them.
    fn payloads() -> Vec<(&'static str, Vec<u8>)> {
        let mut payloads = edge_payloads();
        payloads.extend([(
            "the brim",
            (0..CEILING)
                .map(|n| u8::try_from(n % 251).unwrap_or(0))
                .collect(),
        )]);
        payloads
    }

    #[test]
    fn ethernet_ip_declares_its_settings_and_reads_through_them() {
        assert_eq!(
            EtherNetIpTransport::SETTINGS.problems(),
            Vec::<String>::new()
        );
        let given = [
            ("instance".to_string(), Given::Integer(150)),
            ("timeout".to_string(), Given::Text("2s".to_string())),
        ];
        let built =
            EtherNetIpTransport::open("plc:44818", Applies::Send, &given).expect("configured");
        assert_eq!(built.instance, 150);
        assert_eq!(built.timeout, Some(Duration::from_secs(2)));
        let plain = EtherNetIpTransport::open("plc:44818", Applies::Receive, &[]).expect("plain");
        assert_eq!(plain.instance, DEFAULT_INSTANCE);
        let given = [("slot".to_string(), Given::Integer(1))];
        let Err(refused) = EtherNetIpTransport::open("plc:44818", Applies::Receive, &given) else {
            panic!("slot is not a setting");
        };
        assert!(refused.message.contains("\"slot\""), "{}", refused.message);
    }

    #[test]
    fn a_loopback_round_sets_an_assembly_on_a_registered_session() {
        let loopback = EtherNetIpTransport::loopback();
        let arrived = loopback.round(b"set attribute single").expect("round");
        assert_eq!(arrived.bytes, b"set attribute single");
        assert!(arrived.origin_uri.starts_with("enip://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/assembly/100"));
        assert_eq!(loopback.ceiling(), Some(CEILING));
        assert_eq!(CEILING, 65_511);
        assert!(loopback.refuses(b"x").is_none());
        assert_eq!(loopback.name(), "ethernet-ip");
        assert!(loopback.claims().is_none());
    }

    #[test]
    fn the_loopback_returns_the_edges_whole_and_refuses_over_the_brim() {
        let loopback = EtherNetIpTransport::loopback();
        for (name, bytes) in payloads() {
            let arrived = loopback
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
        let error = loopback
            .round(&vec![0; CEILING + 1])
            .expect_err("over the brim");
        assert!(error.message.starts_with("send failed:"), "{error}");
    }

    #[test]
    fn a_scanner_gets_and_sets_and_is_refused_what_the_adapter_lacks() {
        let adapter =
            EtherNetIpTransport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(2));
        let (listener, address) = adapter.bind().expect("bind");
        let serving = std::thread::spawn(move || {
            // Two sessions in turn: a Location's get and set on its one
            // kept session, then a scanner's own.
            let mut first = adapter
                .accept_one(&listener)
                .expect("accept")
                .with_assembly(100, vec![1, 2, 3]);
            first.serve().expect("serve");
            let set = first.assembly(100).map(<[u8]>::to_vec);
            let mut second = adapter
                .accept_one(&listener)
                .expect("accept again")
                .with_assembly(150, vec![0]);
            second.serve().expect("serve again");
            (set, second.assembly(150).map(<[u8]>::to_vec))
        });
        let near = EtherNetIpTransport::new(&address).timing_out_after(Duration::from_secs(2));
        let location = EtherNetIpTransport::new(&address).timing_out_after(Duration::from_secs(2));
        let arrived = location.receive().expect("get");
        location.send(&address, &[4, 5]).expect("set");
        assert_eq!(location.sessions.opened(), 1);
        // Its kept session closes with it.
        drop(location);
        assert_eq!(arrived[0].bytes, [1, 2, 3]);
        assert_eq!(
            arrived[0].origin_uri,
            format!("enip://{address}/assembly/100")
        );
        let mut scanner = near.connect(&address).expect("connect");
        assert_ne!(scanner.session(), 0);
        let error = scanner.get(7).expect_err("no assembly 7");
        assert!(error.message.contains("0x05"), "{error}");
        scanner.set(150, &[9, 9]).expect("set");
        scanner.unregister().expect("unregister");
        let (kept, apart) = serving.join().expect("thread");
        assert_eq!(kept, Some(vec![4, 5]));
        assert_eq!(apart, Some(vec![9, 9]));
    }

    #[test]
    fn a_thousand_receives_register_one_session() {
        const RECEIVES: usize = 1000;
        let adapter =
            EtherNetIpTransport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(5));
        let (listener, address) = adapter.bind().expect("bind");
        let serving = std::thread::spawn(move || {
            // One accept: every get arrives on the one session.
            let mut session = adapter
                .accept_one(&listener)
                .expect("accept")
                .with_assembly(100, vec![4, 2]);
            session.serve().expect("serve");
        });
        let near = EtherNetIpTransport::new(&address).timing_out_after(Duration::from_secs(5));
        let began = std::time::Instant::now();
        for _ in 0..RECEIVES {
            assert_eq!(near.receive().expect("get")[0].bytes, [4, 2]);
        }
        let took = began.elapsed();
        // Generous for a debug build under load: a millisecond a get.
        assert!(took < Duration::from_millis(RECEIVES as u64), "{took:?}");
        assert_eq!(near.sessions.opened(), 1);
        drop(near);
        serving.join().expect("served");
    }

    #[test]
    fn a_thousand_sends_register_one_session() {
        const SENDS: usize = 1000;
        let adapter =
            EtherNetIpTransport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(5));
        let (listener, address) = adapter.bind().expect("bind");
        let serving = std::thread::spawn(move || {
            // One accept: every set arrives on the one session.
            let mut session = adapter
                .accept_one(&listener)
                .expect("accept")
                .with_assembly(100, vec![0]);
            session.serve().expect("serve");
            session.assembly(100).map(<[u8]>::to_vec)
        });
        let near = EtherNetIpTransport::new(&address).timing_out_after(Duration::from_secs(5));
        let began = std::time::Instant::now();
        for n in 0..SENDS {
            near.send(&address, &[u8::try_from(n % 256).expect("a byte")])
                .expect("set");
        }
        let took = began.elapsed();
        // Generous for a debug build under load: a millisecond a set.
        assert!(took < Duration::from_millis(SENDS as u64), "{took:?}");
        assert_eq!(near.sessions.opened(), 1);
        drop(near);
        assert_eq!(serving.join().expect("served"), Some(vec![231]));
    }

    #[test]
    fn a_target_names_the_instance_and_what_is_not_enip_is_refused() {
        let near = EtherNetIpTransport::new("127.0.0.1:1");
        assert_eq!(
            near.resolve("enip://plc:44818/150").expect("resolved"),
            ("plc:44818".to_string(), 150)
        );
        assert_eq!(near.resolve("plc:44818").expect("bare").1, 100);
        assert!(near.resolve("enip://plc/many").is_err());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let far_end = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0u8; 64];
            let _ = std::io::Read::read(&mut stream, &mut request);
            stream.write_all(b"220 mail.example ESMTP\r\n").expect("w");
            std::thread::sleep(Duration::from_millis(200));
        });
        let error = EtherNetIpTransport::new("127.0.0.1:0")
            .timing_out_after(Duration::from_secs(2))
            .send(&address, b"x")
            .expect_err("refused");
        assert!(!error.retryable, "{error}");
        far_end.join().expect("thread");
    }
}
