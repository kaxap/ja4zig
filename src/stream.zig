//! Central per-stream state and output assembly. Maps
//! `rust/ja4/src/stream.rs` onto Zig idioms — same field ordering on
//! emission so the snapshots diff byte-for-byte.

const std = @import("std");
const pcap = @import("pcap.zig");
const tcp = @import("tcp.zig");
const tls = @import("tls.zig");
const http = @import("http.zig");
const ssh = @import("ssh.zig");
const time = @import("time.zig");
const yaml = @import("yaml.zig");

pub const Sender = enum { client, server };
pub const Transport = enum { tcp, udp };

pub const Flags = struct {
    with_raw: bool = false,
    original_order: bool = false,
    with_packet_numbers: bool = false,
};

pub const Conf = struct {
    tcp: bool = true,
    tls: bool = true,
    http: bool = true,
    ssh: bool = true,
    time: bool = true,
    ssh_sample_size: usize = 200,
};

pub const SocketPair = struct {
    is_ipv6: bool,
    src: []const u8, // owned
    dst: []const u8, // owned
    src_port: u32,
    dst_port: u32,

    pub fn deinit(self: *SocketPair, gpa: std.mem.Allocator) void {
        gpa.free(self.src);
        gpa.free(self.dst);
    }
};

pub const Stream = struct {
    id: u32,
    transport: Transport,
    sockets: SocketPair,
    tcp_state: tcp.State = .{},
    tls_state: tls.State = .{},
    http_state: http.State = .{},
    ssh_state: ssh.State = .{},
    time_state: time.State,

    pub fn deinit(self: *Stream, gpa: std.mem.Allocator) void {
        self.sockets.deinit(gpa);
        self.tcp_state.deinit(gpa);
        self.tls_state.deinit(gpa);
        self.http_state.deinit(gpa);
        self.ssh_state.deinit(gpa);
    }

    pub fn senderOf(self: Stream, pkt: pcap.Packet) Sender {
        const ip_name: []const u8 = if (self.sockets.is_ipv6) "ipv6" else "ip";
        const src_field: []const u8 = if (self.sockets.is_ipv6) "ipv6.src" else "ip.src";
        const ip = pkt.lastProto(ip_name) orelse return .client;
        const src = ip.first(src_field) orelse return .client;
        return if (std.mem.eql(u8, src, self.sockets.src)) .client else .server;
    }
};

pub const Streams = struct {
    gpa: std.mem.Allocator,
    tcp: std.AutoArrayHashMapUnmanaged(u32, Stream) = .{},
    udp: std.AutoArrayHashMapUnmanaged(u32, Stream) = .{},
    conf: Conf,

    pub fn init(gpa: std.mem.Allocator, conf: Conf) Streams {
        return .{ .gpa = gpa, .conf = conf };
    }

    pub fn deinit(self: *Streams) void {
        for (self.tcp.values()) |*s| s.deinit(self.gpa);
        for (self.udp.values()) |*s| s.deinit(self.gpa);
        self.tcp.deinit(self.gpa);
        self.udp.deinit(self.gpa);
    }

    /// Process one packet. Identifies stream, dispatches to per-protocol
    /// modules. Errors from individual modules are swallowed (logged) so
    /// one malformed packet doesn't bring down the run.
    pub fn update(self: *Streams, pkt: pcap.Packet) !void {
        const ident = identify(pkt) orelse return;
        const map = switch (ident.transport) {
            .tcp => &self.tcp,
            .udp => &self.udp,
        };
        const gop = try map.getOrPut(self.gpa, ident.id);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .id = ident.id,
                .transport = ident.transport,
                .sockets = try buildSocketPair(self.gpa, pkt, ident),
                .time_state = time.State.init(switch (ident.transport) {
                    .tcp => .tcp,
                    .udp => .udp,
                }),
            };
            gop.value_ptr.ssh_state.sample_size = self.conf.ssh_sample_size;
        }
        const stream = gop.value_ptr;
        const sender = stream.senderOf(pkt);

        if (self.conf.tcp) tcp.update(&stream.tcp_state, pkt, self.gpa) catch {};
        if (self.conf.tls) tls.update(&stream.tls_state, pkt, self.gpa) catch {};
        if (self.conf.http) http.update(&stream.http_state, pkt, self.gpa) catch {};
        if (self.conf.ssh) {
            if (pkt.findProto("tcp") != null) ssh.update(&stream.ssh_state, pkt, sender, self.gpa) catch {};
        }
        if (self.conf.time) time.update(&stream.time_state, pkt) catch {};
    }

    pub fn finish(self: *Streams) !void {
        for (self.tcp.values()) |*s| try ssh.finish(&s.ssh_state, self.gpa);
        for (self.udp.values()) |*s| try ssh.finish(&s.ssh_state, self.gpa);
    }

    /// Emit YAML matching the insta snapshot format. Top-level is `[]` if no
    /// stream produced any fingerprints.
    pub fn emitYaml(self: *Streams, w: *std.Io.Writer, flags: Flags) !void {
        var written: usize = 0;
        for (self.tcp.values()) |*s| {
            if (try emitStream(self.gpa, s.*, w, flags)) written += 1;
        }
        for (self.udp.values()) |*s| {
            if (try emitStream(self.gpa, s.*, w, flags)) written += 1;
        }
        if (written == 0) {
            try w.print("[]\n", .{});
        }
        // Trailing-newline quirk: upstream insta snapshots inconsistently end
        // with `\n` or `\n\n` depending on which serde-yaml version
        // generated them. Single `\n` matches the majority of fixtures
        // (23 vs 14 with `\n\n`).
    }
};

const Ident = struct { id: u32, transport: Transport, is_ipv6: bool };

fn identify(pkt: pcap.Packet) ?Ident {
    if (pkt.findProto("icmp") != null) return null;
    if (pkt.findProto("icmpv6") != null) return null;

    var is_ipv6 = false;
    if (pkt.lastProto("ipv6") != null) is_ipv6 = true else if (pkt.lastProto("ip") == null) return null;

    if (pkt.lastProto("tcp")) |t| {
        const s = t.first("tcp.stream") orelse return null;
        const id = std.fmt.parseInt(u32, s, 10) catch return null;
        return .{ .id = id, .transport = .tcp, .is_ipv6 = is_ipv6 };
    }
    if (pkt.lastProto("udp")) |u| {
        const s = u.first("udp.stream") orelse return null;
        const id = std.fmt.parseInt(u32, s, 10) catch return null;
        return .{ .id = id, .transport = .udp, .is_ipv6 = is_ipv6 };
    }
    return null;
}

fn buildSocketPair(gpa: std.mem.Allocator, pkt: pcap.Packet, ident: Ident) !SocketPair {
    const ip_name: []const u8 = if (ident.is_ipv6) "ipv6" else "ip";
    const src_field: []const u8 = if (ident.is_ipv6) "ipv6.src" else "ip.src";
    const dst_field: []const u8 = if (ident.is_ipv6) "ipv6.dst" else "ip.dst";
    const ip = pkt.lastProto(ip_name) orelse return error.NoIp;
    const src = ip.first(src_field) orelse return error.NoSrc;
    const dst = ip.first(dst_field) orelse return error.NoDst;
    const tr_name: []const u8 = if (ident.transport == .tcp) "tcp" else "udp";
    const sp_field: []const u8 = if (ident.transport == .tcp) "tcp.srcport" else "udp.srcport";
    const dp_field: []const u8 = if (ident.transport == .tcp) "tcp.dstport" else "udp.dstport";
    const tr = pkt.lastProto(tr_name) orelse return error.NoTransport;
    const sp = std.fmt.parseInt(u32, tr.first(sp_field) orelse return error.NoSrcPort, 10) catch return error.BadPort;
    const dp = std.fmt.parseInt(u32, tr.first(dp_field) orelse return error.NoDstPort, 10) catch return error.BadPort;
    return .{
        .is_ipv6 = ident.is_ipv6,
        .src = try gpa.dupe(u8, src),
        .dst = try gpa.dupe(u8, dst),
        .src_port = sp,
        .dst_port = dp,
    };
}

fn emitStream(gpa: std.mem.Allocator, s: Stream, w: *std.Io.Writer, flags: Flags) !bool {
    // Drop streams that produced no fingerprint at all.
    if (s.tcp_state.client == null and
        s.tls_state.client == null and s.tls_state.server == null and
        s.tls_state.x509.groups.items.len == 0 and
        s.http_state.requests.items.len == 0 and
        s.ssh_state.fingerprints.items.len == 0 and
        s.ssh_state.extras.isEmpty() and
        !timeReady(s.time_state)) return false;

    try w.print("- stream: {d}\n", .{s.id});
    try w.print("  transport: {s}\n", .{@tagName(s.transport)});
    try w.print("  src: ", .{});
    try yaml.writeScalar(w, s.sockets.src);
    try w.print("\n  dst: ", .{});
    try yaml.writeScalar(w, s.sockets.dst);
    try w.print("\n  src_port: {d}\n  dst_port: {d}\n", .{ s.sockets.src_port, s.sockets.dst_port });

    try tcp.emit(s.tcp_state, w, flags.with_packet_numbers);
    try tls.emitServerName(s.tls_state, w);
    try tls.emitClient(s.tls_state, w, gpa, flags.with_packet_numbers, flags.with_raw, flags.original_order);
    try tls.emitServer(s.tls_state, w, gpa, flags.with_packet_numbers, flags.with_raw);
    try tls.emitX509(s.tls_state, w, flags.with_packet_numbers, flags.with_raw);
    try time.emit(s.time_state, w);
    try http.emit(s.http_state, w, gpa, flags.with_packet_numbers, flags.with_raw, flags.original_order);
    try ssh.emit(s.ssh_state, w);
    try ssh.emitExtras(s.ssh_state, w);
    return true;
}

fn timeReady(t: time.State) bool {
    return switch (t.transport) {
        .tcp => t.t_syn != null and t.t_syn_ack != null and t.t_ack != null,
        .udp => t.t_client_initial != null and t.t_server_initial != null and t.t_server_hs != null and t.t_client_hs != null,
    };
}
