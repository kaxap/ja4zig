const std = @import("std");
const Io = std.Io;

const pcap = @import("pcap.zig");
const stream = @import("stream.zig");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        try printErr(io, "usage: ja4 <pcap>\n");
        std.process.exit(2);
    }

    var flags: stream.Flags = .{};
    var pcap_path: ?[]const u8 = null;
    for (args[1..]) |a| {
        if (std.mem.eql(u8, a, "-r") or std.mem.eql(u8, a, "--with-raw")) {
            flags.with_raw = true;
        } else if (std.mem.eql(u8, a, "-O") or std.mem.eql(u8, a, "--original-order")) {
            flags.original_order = true;
        } else if (std.mem.eql(u8, a, "-n") or std.mem.eql(u8, a, "--with-packet-numbers")) {
            flags.with_packet_numbers = true;
        } else if (std.mem.startsWith(u8, a, "-")) {
            try printErr(io, "ja4zig: unknown flag\n");
            std.process.exit(2);
        } else {
            pcap_path = a;
        }
    }
    const path = pcap_path orelse {
        try printErr(io, "ja4zig: missing pcap path\n");
        std.process.exit(2);
    };

    var reader = try pcap.Reader.open(arena, io, path, null);
    defer reader.close();

    var streams = stream.Streams.init(arena, .{});
    defer streams.deinit();

    while (try reader.next()) |pkt| {
        streams.update(pkt) catch |err| {
            std.debug.print("ja4zig: packet error {s}\n", .{@errorName(err)});
        };
    }
    try streams.finish();

    var stdout_buffer: [16 * 1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const w = &stdout_file_writer.interface;
    try streams.emitYaml(w, flags);
    try w.flush();
}

fn printErr(io: Io, msg: []const u8) !void {
    var buf: [256]u8 = undefined;
    var stderr_file_writer: Io.File.Writer = .init(.stderr(), io, &buf);
    const w = &stderr_file_writer.interface;
    try w.print("{s}", .{msg});
    try w.flush();
}
