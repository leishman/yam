const std = @import("std");
const yam = @import("root.zig");
const scout = @import("scout.zig");
const relay = @import("relay.zig");
const Relay = relay.Relay;
const Explorer = @import("explorer.zig").Explorer;
const dashboard = @import("dashboard.zig");

const Command = enum {
    broadcast,
    explore,
    dashboard,
    help,
};

const BroadcastArgs = struct {
    tx_hex: []const u8,
    peer_count: u32 = 8,
    timing: relay.TimingStrategy = .staggered_random,
    discover: bool = false,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const result = gpa.deinit();
        if (result == .leak) {
            std.debug.print("Memory leak detected\n", .{});
        }
    }
    const allocator = gpa.allocator();

    var args_iter = try std.process.argsWithAllocator(allocator);
    defer args_iter.deinit();

    // Skip program name
    _ = args_iter.next();

    // Get subcommand
    const cmd_str = args_iter.next() orelse {
        // No args = explore mode
        var explorer = try Explorer.init(allocator);
        defer explorer.deinit();
        try explorer.run();
        return;
    };

    const cmd: Command = if (std.mem.eql(u8, cmd_str, "broadcast"))
        .broadcast
    else if (std.mem.eql(u8, cmd_str, "explore"))
        .explore
    else if (std.mem.eql(u8, cmd_str, "dashboard"))
        .dashboard
    else if (std.mem.eql(u8, cmd_str, "--help") or std.mem.eql(u8, cmd_str, "-h") or std.mem.eql(u8, cmd_str, "help"))
        .help
    else {
        std.debug.print("Unknown command: {s}\n\n", .{cmd_str});
        printUsage();
        return;
    };

    switch (cmd) {
        .broadcast => {
            const broadcast_args = parseBroadcastArgs(&args_iter) orelse {
                printBroadcastUsage();
                return;
            };
            try broadcastTransaction(allocator, broadcast_args);
        },
        .explore => {
            var explorer = try Explorer.init(allocator);
            defer explorer.deinit();
            try explorer.run();
        },
        .dashboard => {
            const config = parseDashboardArgs(&args_iter);
            var d = try dashboard.Dashboard.init(allocator, config);
            defer d.deinit();
            try d.run();
        },
        .help => printUsage(),
    }
}

fn parseDashboardArgs(args_iter: anytype) dashboard.DashboardConfig {
    var config = dashboard.DashboardConfig{};
    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "-p")) {
            if (args_iter.next()) |port_str| {
                config.port = std.fmt.parseInt(u16, port_str, 10) catch 8080;
            }
        } else if (std.mem.eql(u8, arg, "--bind") or std.mem.eql(u8, arg, "-b")) {
            if (args_iter.next()) |addr| {
                config.bind_address = addr;
            }
        } else if (std.mem.eql(u8, arg, "--read-only") or std.mem.eql(u8, arg, "-r")) {
            config.read_only = true;
        } else if (std.mem.eql(u8, arg, "--state-file") or std.mem.eql(u8, arg, "-s")) {
            if (args_iter.next()) |path| {
                config.state_file = path;
            }
        } else if (std.mem.eql(u8, arg, "--disable-topology")) {
            config.disable_topology = true;
        } else if (std.mem.eql(u8, arg, "--disable-map")) {
            config.disable_map = true;
        } else if (std.mem.eql(u8, arg, "--update-interval")) {
            if (args_iter.next()) |ms_str| {
                config.update_interval_ms = std.fmt.parseInt(u32, ms_str, 10) catch 2000;
            }
        }
    }
    return config;
}

fn parseBroadcastArgs(args_iter: anytype) ?BroadcastArgs {
    // First positional arg is tx_hex
    const tx_hex = args_iter.next() orelse return null;

    // Check it's not a flag (user forgot tx hex)
    if (tx_hex.len > 0 and tx_hex[0] == '-') {
        std.debug.print("Error: Transaction hex is required\n\n", .{});
        return null;
    }

    var result = BroadcastArgs{ .tx_hex = tx_hex };

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--peers") or std.mem.eql(u8, arg, "-p")) {
            if (args_iter.next()) |count_str| {
                result.peer_count = std.fmt.parseInt(u32, count_str, 10) catch 5;
            }
        } else if (std.mem.eql(u8, arg, "--simultaneous") or std.mem.eql(u8, arg, "-s")) {
            result.timing = .simultaneous;
        } else if (std.mem.eql(u8, arg, "--discover") or std.mem.eql(u8, arg, "-d")) {
            result.discover = true;
        }
    }

    return result;
}

fn printUsage() void {
    const usage =
        \\Yam - Bitcoin P2P Network Tool
        \\
        \\USAGE:
        \\  yam broadcast <tx_hex> [options]    Broadcast a transaction
        \\  yam explore                         Interactive network explorer (default)
        \\  yam dashboard [options]             Web dashboard
        \\  yam help                            Show this help
        \\
        \\Run 'yam broadcast --help' for broadcast options.
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn printBroadcastUsage() void {
    const usage =
        \\USAGE:
        \\  yam broadcast <tx_hex> [options]
        \\
        \\ARGUMENTS:
        \\  <tx_hex>                Raw transaction hex to broadcast
        \\
        \\OPTIONS:
        \\  --peers, -p <count>     Number of peers to broadcast to (default: 8)
        \\  --simultaneous, -s      Send to all peers at once (default: staggered)
        \\  --discover, -d          Enable recursive peer discovery via getaddr
        \\
        \\EXAMPLES:
        \\  yam broadcast 0100000001...
        \\  yam broadcast 0100000001... --peers 10 --simultaneous
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn broadcastTransaction(allocator: std.mem.Allocator, args: BroadcastArgs) !void {
    // Parse transaction hex to validate it
    std.debug.print("=== Validating Transaction ===\n", .{});
    const tx_bytes = yam.hexToBytes(allocator, args.tx_hex) catch |err| {
        std.debug.print("Error: Invalid transaction hex - {}\n", .{err});
        return err;
    };
    defer allocator.free(tx_bytes);

    // Parse to verify structure and get txid
    var fbs = std.io.fixedBufferStream(tx_bytes);
    const tx = yam.Transaction.deserialize(fbs.reader(), allocator) catch |err| {
        std.debug.print("Error: Failed to parse transaction - {}\n", .{err});
        return err;
    };
    defer tx.deinit(allocator);

    const txid_hex = try tx.txidHex(allocator);
    std.debug.print("Transaction ID: {s}\n", .{txid_hex});
    std.debug.print("Inputs: {d}, Outputs: {d}\n", .{ tx.inputs.len, tx.outputs.len });

    var total_output_value: f64 = 0;
    for (tx.outputs) |output| {
        total_output_value += output.valueBtc();
    }
    std.debug.print("Total output: {d:.8} BTC\n", .{total_output_value});

    // Discover peers
    std.debug.print("\n=== Scouting for Peers ===\n", .{});
    var peer_list = try scout.discoverPeers(allocator);

    if (peer_list.items.len == 0) {
        std.debug.print("Error: No peers discovered\n", .{});
        return error.NoPeersDiscovered;
    }

    // If --discover flag, connect to some peers and request more via getaddr
    if (args.discover) {
        std.debug.print("\n=== Recursive Discovery via getaddr ===\n", .{});
        const expanded_list = try scout.discoverPeersViaGetaddr(allocator, peer_list.items, 3);
        peer_list.deinit(allocator);
        peer_list = expanded_list;
    }
    defer peer_list.deinit(allocator);

    // Select more peers than needed since some connections will fail
    // Try to connect to 2x the requested count
    const connect_count = args.peer_count * 2;
    const selected_peers = try scout.selectRandomPeers(allocator, peer_list.items, connect_count);
    defer allocator.free(selected_peers);

    std.debug.print("\nSelected {d} peers to attempt connection (targeting {d} for broadcast)\n", .{ selected_peers.len, args.peer_count });

    // Initialize relay
    var r = try Relay.init(selected_peers, allocator);
    defer r.deinit();

    // Connect to peers (stops once we have enough)
    std.debug.print("\n=== Connecting to Peers ===\n", .{});
    const connected = r.connectAll(args.peer_count);
    std.debug.print("\nSuccessfully connected to {d} peers (target: {d})\n", .{ connected, args.peer_count });

    if (connected == 0) {
        std.debug.print("Error: No peers connected, aborting broadcast\n", .{});
        return error.NoPeersConnected;
    }

    // Broadcast info
    std.debug.print("\n=== Broadcasting ===\n", .{});
    std.debug.print("Transaction: {s}\n", .{txid_hex});
    std.debug.print("Peers: {d}\n", .{connected});
    std.debug.print("Timing: {s}\n", .{if (args.timing == .staggered_random) "staggered (privacy mode)" else "simultaneous"});

    // Broadcast transaction (stop after peer_count successful broadcasts)
    var result = try r.broadcastTx(tx_bytes, .{
        .strategy = args.timing,
        .max_peers = args.peer_count,
    });
    defer result.deinit(allocator);

    // Print results
    relay.printBroadcastReport(result.reports, allocator);

    if (result.success_count > 0) {
        std.debug.print("\nTransaction broadcast to {d} peer(s)\n", .{result.success_count});
    } else {
        std.debug.print("\nError: Broadcast failed to all peers\n", .{});
    }
}
