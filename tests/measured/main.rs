//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): this transport held to how long Xmip takes — the millisecond rule
//! (`CONTRIBUTING.md`, *Rust is here for one reason*). A plain `cargo test`
//! leaves it out; the landing runs it after every other test of the module,
//! alone, one test at a time
//! (`cargo test --test measured --all-features -- --test-threads=1`), so
//! what is measured is Xmip's work and not its neighbors':
//!
//! - a thousand gets on one registered session take a millisecond each at
//!   most;
//! - a thousand sets on one registered session take a millisecond each at
//!   most.
//!
//! Each the millisecond beyond the round's wakes, round by round beside a
//! plain wake, the fastest of five (`xcore::latency::Rounds`).

use std::time::Duration;

use transport::Transport;
use xcore::latency::Rounds;
use xmip_core_transport_ethernet_ip::EtherNetIpTransport;

/// What a get or a set wakes where a plain wake wakes one: the adapter at
/// the request, and this end at its answer.
const WAKES: u32 = 2;

/// An adapter serving assembly 100 holding `bytes` until the near end
/// lets go, and its address.
fn adapter(bytes: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
    let adapter = EtherNetIpTransport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(5));
    let (listener, address) = adapter.bind().expect("bind");
    let serving = std::thread::spawn(move || {
        let mut session = adapter
            .accept_one(&listener)
            .expect("accept")
            .with_assembly(100, bytes);
        session.serve().expect("serve");
    });
    (address, serving)
}

#[test]
fn a_thousand_gets_take_a_millisecond_each_at_most() {
    const RECEIVES: usize = 1000;
    let (address, serving) = adapter(vec![4, 2]);
    let near = EtherNetIpTransport::new(&address).timing_out_after(Duration::from_secs(5));
    let mut rounds = Rounds::crossing(WAKES);
    for _ in 0..RECEIVES {
        let got = rounds
            .round(|| near.receive().expect("get").remove(0).taken())
            .expect("taken");
        assert_eq!(got.bytes, [4, 2]);
    }
    drop(near);
    serving.join().expect("served");
    rounds.hold("a get");
}

#[test]
fn a_thousand_sets_take_a_millisecond_each_at_most() {
    const SENDS: usize = 1000;
    let (address, serving) = adapter(vec![0]);
    let near = EtherNetIpTransport::new(&address).timing_out_after(Duration::from_secs(5));
    let mut rounds = Rounds::crossing(WAKES);
    for n in 0..SENDS {
        let byte = u8::try_from(n % 256).expect("a byte");
        rounds.round(|| near.send(&address, &[byte])).expect("set");
    }
    drop(near);
    serving.join().expect("served");
    rounds.hold("a set");
}
