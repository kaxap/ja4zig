//! JA4SSH — SSH packet-length sampling fingerprint.

const std = @import("std");
const pcap = @import("pcap.zig");
const Sender = @import("stream.zig").Sender;

pub const Stats = struct {
    client_len_counts: std.AutoArrayHashMapUnmanaged(usize, usize) = .{},
    server_len_counts: std.AutoArrayHashMapUnmanaged(usize, usize) = .{},
    nr_ssh_client: usize = 0,
    nr_ssh_server: usize = 0,
    nr_ack_client: usize = 0,
    nr_ack_server: usize = 0,

    pub fn deinit(self: *Stats, gpa: std.mem.Allocator) void {
        self.client_len_counts.deinit(gpa);
        self.server_len_counts.deinit(gpa);
    }

    pub fn isEmpty(self: Stats) bool {
        return self.client_len_counts.count() == 0 and self.server_len_counts.count() == 0;
    }
};

pub const Extras = struct {
    hassh: ?[]u8 = null, // owned
    hassh_server: ?[]u8 = null,
    ssh_protocol_client: ?[]u8 = null,
    ssh_protocol_server: ?[]u8 = null,
    client_algs: ?[]u8 = null, // raw csv from client, kept for negotiation
    encryption_algorithm: ?[]u8 = null,

    pub fn deinit(self: *Extras, gpa: std.mem.Allocator) void {
        if (self.hassh) |b| gpa.free(b);
        if (self.hassh_server) |b| gpa.free(b);
        if (self.ssh_protocol_client) |b| gpa.free(b);
        if (self.ssh_protocol_server) |b| gpa.free(b);
        if (self.client_algs) |b| gpa.free(b);
        if (self.encryption_algorithm) |b| gpa.free(b);
        self.* = .{};
    }

    pub fn isEmpty(self: Extras) bool {
        return self.hassh == null and self.hassh_server == null and
            self.ssh_protocol_client == null and self.ssh_protocol_server == null and
            self.encryption_algorithm == null;
    }
};

pub const State = struct {
    cur: Stats = .{},
    fingerprints: std.ArrayList([]u8) = .empty,
    sample_size: usize = 200,
    extras: Extras = .{},

    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        self.cur.deinit(gpa);
        for (self.fingerprints.items) |f| gpa.free(f);
        self.fingerprints.deinit(gpa);
        self.extras.deinit(gpa);
    }
};

pub fn update(state: *State, pkt: pcap.Packet, sender: Sender, gpa: std.mem.Allocator) !void {
    const tcp = pkt.findProto("tcp") orelse return;

    // Side: harvest SSH protocol-string / hassh / negotiated cipher.
    if (pkt.findProto("ssh")) |ssh_pkt| {
        try updateExtras(&state.extras, ssh_pkt, sender, gpa);
    }

    if (pkt.findProto("ssh") != null) {
        const len_str = tcp.first("tcp.len") orelse return;
        const len = std.fmt.parseInt(usize, len_str, 10) catch return;
        switch (sender) {
            .client => {
                const gop = try state.cur.client_len_counts.getOrPut(gpa, len);
                if (!gop.found_existing) gop.value_ptr.* = 0;
                gop.value_ptr.* += 1;
                state.cur.nr_ssh_client += 1;
            },
            .server => {
                const gop = try state.cur.server_len_counts.getOrPut(gpa, len);
                if (!gop.found_existing) gop.value_ptr.* = 0;
                gop.value_ptr.* += 1;
                state.cur.nr_ssh_server += 1;
            },
        }
    } else {
        // Bare ACK? Accept tshark's two encodings: rtshark's "0x0010" or
        // -T ek's plain integer "16".
        const flags_str = tcp.first("tcp.flags") orelse return;
        const flags = parseIntFlexible(u16, flags_str) catch return;
        if (flags != 0x0010) return;
        switch (sender) {
            .client => state.cur.nr_ack_client += 1,
            .server => state.cur.nr_ack_server += 1,
        }
    }

    if (state.cur.nr_ssh_client + state.cur.nr_ssh_server >= state.sample_size) {
        if (try flushFingerprint(&state.cur, gpa)) |fp| try state.fingerprints.append(gpa, fp);
        state.cur.client_len_counts.clearRetainingCapacity();
        state.cur.server_len_counts.clearRetainingCapacity();
        state.cur.nr_ssh_client = 0;
        state.cur.nr_ssh_server = 0;
        state.cur.nr_ack_client = 0;
        state.cur.nr_ack_server = 0;
    }
}

fn updateExtras(extras: *Extras, ssh: pcap.Proto, sender: Sender, gpa: std.mem.Allocator) !void {
    switch (sender) {
        .client => {
            if (extras.hassh == null) {
                if (ssh.first("ssh.kex.hassh")) |s| extras.hassh = try gpa.dupe(u8, s);
            }
            if (extras.client_algs == null) {
                if (ssh.first("ssh.encryption_algorithms_client_to_server")) |s| extras.client_algs = try gpa.dupe(u8, s);
            }
            if (extras.ssh_protocol_client == null) {
                if (ssh.first("ssh.protocol")) |s| extras.ssh_protocol_client = try gpa.dupe(u8, s);
            }
        },
        .server => {
            if (extras.hassh_server == null) {
                if (ssh.first("ssh.kex.hasshserver")) |s| extras.hassh_server = try gpa.dupe(u8, s);
            }
            if (extras.ssh_protocol_server == null) {
                if (ssh.first("ssh.protocol")) |s| extras.ssh_protocol_server = try gpa.dupe(u8, s);
            }
            if (extras.encryption_algorithm == null) {
                if (ssh.first("ssh.encryption_algorithms_server_to_client")) |s2c_raw| {
                    if (extras.client_algs) |c2s_raw| {
                        // Pick first server-offered alg that's also in the client list.
                        var it = std.mem.splitScalar(u8, s2c_raw, ',');
                        while (it.next()) |alg| {
                            if (algInList(c2s_raw, alg)) {
                                extras.encryption_algorithm = try gpa.dupe(u8, alg);
                                break;
                            }
                        }
                    }
                }
            }
        },
    }
}

fn algInList(csv: []const u8, alg: []const u8) bool {
    var it = std.mem.splitScalar(u8, csv, ',');
    while (it.next()) |a| if (std.mem.eql(u8, a, alg)) return true;
    return false;
}

pub fn finish(state: *State, gpa: std.mem.Allocator) !void {
    if (!state.cur.isEmpty()) {
        if (try flushFingerprint(&state.cur, gpa)) |fp| try state.fingerprints.append(gpa, fp);
    }
}

fn flushFingerprint(stats: *Stats, gpa: std.mem.Allocator) !?[]u8 {
    if (stats.isEmpty()) return null;
    const mode_c = minKeyMaxValue(&stats.client_len_counts);
    const mode_s = minKeyMaxValue(&stats.server_len_counts);
    return try std.fmt.allocPrint(gpa, "c{d}s{d}_c{d}s{d}_c{d}s{d}", .{
        mode_c, mode_s, stats.nr_ssh_client, stats.nr_ssh_server, stats.nr_ack_client, stats.nr_ack_server,
    });
}

fn parseIntFlexible(comptime T: type, s: []const u8) !T {
    if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) {
        return std.fmt.parseInt(T, s[2..], 16);
    }
    return std.fmt.parseInt(T, s, 10);
}

fn minKeyMaxValue(m: *const std.AutoArrayHashMapUnmanaged(usize, usize)) usize {
    var best_v: usize = 0;
    var best_k: usize = 0;
    var any = false;
    var it = m.iterator();
    while (it.next()) |entry| {
        const k = entry.key_ptr.*;
        const v = entry.value_ptr.*;
        if (!any or v > best_v or (v == best_v and k < best_k)) {
            best_v = v;
            best_k = k;
            any = true;
        }
    }
    return if (any) best_k else 0;
}

pub fn emit(state: State, w: *std.Io.Writer) !void {
    if (state.fingerprints.items.len == 0) return;
    try w.print("  ja4ssh:\n", .{});
    for (state.fingerprints.items) |fp| try w.print("  - {s}\n", .{fp});
}

pub fn emitExtras(state: State, w: *std.Io.Writer) !void {
    const e = state.extras;
    if (e.isEmpty()) return;
    const yaml = @import("yaml.zig");
    try w.print("  ssh_extras:\n", .{});
    try emitOpt(w, "hassh", e.hassh);
    try emitOpt(w, "hassh_server", e.hassh_server);
    try emitOpt(w, "ssh_protocol_client", e.ssh_protocol_client);
    try emitOpt(w, "ssh_protocol_server", e.ssh_protocol_server);
    try emitOpt(w, "encryption_algorithm", e.encryption_algorithm);
    _ = yaml;
}

fn emitOpt(w: *std.Io.Writer, key: []const u8, value: ?[]const u8) !void {
    const yaml = @import("yaml.zig");
    try w.print("    {s}: ", .{key});
    if (value) |s| {
        try yaml.writeScalar(w, s);
    } else {
        try w.print("null", .{});
    }
    try w.print("\n", .{});
}
