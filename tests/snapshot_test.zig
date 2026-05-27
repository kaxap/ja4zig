//! Snapshot test harness.
//!
//! For every `*.pcap` / `*.pcapng` file under `tests/testdata/pcap/`, invokes
//! the locally-built `ja4` binary with no flags and diffs stdout against
//! `tests/testdata/snapshots/<basename>.yaml`.
//!
//! Until the implementation lands, the binary exits non-zero with a
//! "not implemented" message — every test fails, and that's the desired
//! starting state for phase 1.

const std = @import("std");
const build_options = @import("build_options");

const Io = std.Io;

test "snapshots match expected fingerprints" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var pcap_dir = try Io.Dir.cwd().openDir(io, build_options.pcap_dir, .{ .iterate = true });
    defer pcap_dir.close(io);

    var snapshots_dir = try Io.Dir.cwd().openDir(io, build_options.snapshots_dir, .{});
    defer snapshots_dir.close(io);

    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }

    var it = pcap_dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!isPcapName(entry.name)) continue;
        try names.append(gpa, try gpa.dupe(u8, entry.name));
    }
    // Deterministic order, mostly for the failure list.
    std.mem.sort([]const u8, names.items, {}, ltStr);

    var failures: usize = 0;
    var first_error: ?[]u8 = null;
    defer if (first_error) |e| gpa.free(e);

    for (names.items) |name| {
        const pcap_path = try std.fs.path.join(gpa, &.{ build_options.pcap_dir, name });
        defer gpa.free(pcap_path);

        const snap_name = try std.fmt.allocPrint(gpa, "{s}.yaml", .{name});
        defer gpa.free(snap_name);

        const expected = snapshots_dir.readFileAlloc(io, snap_name, gpa, .limited(1 * 1024 * 1024)) catch |err| {
            std.debug.print("[snapshot] missing fixture for {s}: {s}\n", .{ name, snap_name });
            return err;
        };
        defer gpa.free(expected);

        const result = try std.process.run(gpa, io, .{
            .argv = &.{ build_options.exe_path, pcap_path },
        });
        defer gpa.free(result.stdout);
        defer gpa.free(result.stderr);

        const exit_ok = switch (result.term) {
            .exited => |code| code == 0,
            else => false,
        };

        if (!exit_ok or !std.mem.eql(u8, result.stdout, expected)) {
            failures += 1;
            if (first_error == null) {
                first_error = try std.fmt.allocPrint(
                    gpa,
                    "[snapshot] mismatch in {s}\n--- expected ---\n{s}\n--- got (term={any}) ---\n{s}\n--- stderr ---\n{s}\n",
                    .{ name, expected, result.term, result.stdout, result.stderr },
                );
            }
        }
    }

    if (failures != 0) {
        if (first_error) |msg| std.debug.print("{s}", .{msg});
        std.debug.print("[snapshot] {d}/{d} fixtures failed\n", .{ failures, names.items.len });
        return error.SnapshotMismatch;
    }
}

fn isPcapName(name: []const u8) bool {
    // Matches the upstream insta glob `pcap/*.pcap*`: anything containing
    // `.pcap` (covers `.pcap` and `.pcapng`). Excludes `.notest.cap` because
    // it doesn't contain `.pcap`.
    return std.mem.indexOf(u8, name, ".pcap") != null;
}

fn ltStr(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}
