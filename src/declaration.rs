//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// The assembly instance a Location speaks about unless it names another.
pub const DEFAULT_INSTANCE: u8 = 100;

/// Every setting a Location takes beyond its address, the adapter's host
/// and port: where a Location connects as a scanner, or listens as an
/// adapter.
pub const SETTINGS: &Settings = &Settings {
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
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long a peer that stops mid-message is waited on; unbounded when \
             left out.",
        ),
    ],
};

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["enip"];
