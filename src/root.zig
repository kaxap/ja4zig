//! ja4zig — Zig port of the FoxIO JA4+ Rust crate (`rust/ja4`).
//!
//! Modules are added incrementally. Phase 1 only exposes the helpers that the
//! unit tests in `tests/unit/` exercise.

pub const hash = @import("hash.zig");
pub const tshark = @import("tshark.zig");
pub const pcap = @import("pcap.zig");
pub const grease = @import("grease.zig");
pub const stream = @import("stream.zig");
pub const tcp = @import("tcp.zig");
pub const tls = @import("tls.zig");
pub const http = @import("http.zig");
pub const ssh = @import("ssh.zig");
pub const time = @import("time.zig");
pub const yaml = @import("yaml.zig");
pub const ja4x = @import("ja4x.zig");

test {
    _ = hash;
    _ = tshark;
    _ = pcap;
    _ = grease;
    _ = stream;
    _ = tcp;
    _ = tls;
    _ = http;
    _ = ssh;
    _ = time;
    _ = yaml;
    _ = ja4x;
}
