//! Library façade for `hush-daemon`.
//!
//! Exposes the public API surface used by:
//! - Integration tests in `crates/daemon/tests/`
//! - The `hushd` binary (`src/main.rs`) — via `use hush_daemon::{app, …}`
//!
//! WP3 adds the control-API server as `api` module.
//! WP9 adds the SQLite rollup writer as `rollup` module.
//! WP14 adds `inbound_tls` (DoT/DoQ) and `mdns` (passive mDNS insight).

pub mod api;
pub mod app;
pub mod dns;
pub mod inbound_tls;
pub mod lists;
pub mod mdns;
pub mod metrics;
pub mod odoh;
pub mod padding;
pub mod platform;
pub mod profiles;
pub mod rollup;
pub mod sentinel;
pub mod state_dir;
pub mod upstream;
