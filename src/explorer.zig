// Explorer.zig - Interactive network exploration mode

const std = @import("std");
const yam = @import("root.zig");
const scout = @import("scout.zig");
const platform = @import("platform.zig");

// ANSI color codes
const Color = struct {
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const red = "\x1b[31m";
    const dim = "\x1b[2m";
    const reset = "\x1b[0m";
};

pub const ConnectionState = enum { connecting, handshaking, connected, failed };

pub const Connection = struct {
    socket: std.posix.socket_t,
    node_index: usize, // 1-based index into known_nodes
    state: ConnectionState,
    streaming: bool,
    handshake_state: HandshakeState,

    const HandshakeState = struct {
        received_version: bool = false,
        received_verack: bool = false,
        sent_verack: bool = false,
    };
};

/// Metadata about a node discovered during connection
pub const NodeMetadata = struct {
    user_agent: ?[]const u8 = null,
    services: u64 = 0,
    ever_connected: bool = false,
    latency_ms: ?u64 = null,
    pending_ping_time: ?i64 = null,
    pending_ping_nonce: ?u64 = null,
    bytes_in: u64 = 0,
    bytes_out: u64 = 0,
    msgs_in: u64 = 0,
    msgs_out: u64 = 0,
    connect_time: ?i64 = null,
    start_height: u32 = 0,
    fee_filter: u64 = 0,

    pub fn canServeWitnesses(self: NodeMetadata) bool {
        return (self.services & yam.ServiceFlags.NODE_WITNESS) != 0;
    }

    pub fn deinit(self: *NodeMetadata, allocator: std.mem.Allocator) void {
        if (self.user_agent) |ua| {
            allocator.free(ua);
        }
    }
};

/// Record of a node announcing a transaction
pub const TxAnnouncement = struct {
    node_index: usize,
    timestamp: i64,
};

/// Mempool entry tracking a transaction and its announcements
pub const MempoolEntry = struct {
    txid: [32]u8,
    tx_data: ?[]u8, // raw transaction bytes, null until we receive full tx
    first_seen: i64,
    announcements: std.ArrayList(TxAnnouncement),

    pub fn init(allocator: std.mem.Allocator, txid: [32]u8, first_node: usize) MempoolEntry {
        var entry = MempoolEntry{
            .txid = txid,
            .tx_data = null,
            .first_seen = std.time.timestamp(),
            .announcements = std.ArrayList(TxAnnouncement).empty,
        };
        entry.announcements.append(allocator, .{
            .node_index = first_node,
            .timestamp = entry.first_seen,
        }) catch {};
        return entry;
    }

    pub fn addAnnouncement(self: *MempoolEntry, allocator: std.mem.Allocator, node_index: usize) void {
        self.announcements.append(allocator, .{
            .node_index = node_index,
            .timestamp = std.time.timestamp(),
        }) catch {};
    }

    pub fn deinit(self: *MempoolEntry, allocator: std.mem.Allocator) void {
        if (self.tx_data) |data| {
            allocator.free(data);
        }
        self.announcements.deinit(allocator);
    }
};

pub const ManagerCommand = union(enum) {
    connect: usize, // node_index
    disconnect: usize, // node_index
    set_streaming: struct { node_index: usize, enabled: bool },
    send_getaddr: usize, // node_index
    send_ping: usize, // node_index
};

/// Graph edge: source told us about node
pub const Edge = struct {
    source: []const u8,
    node: []const u8,
};

pub const Explorer = struct {
    allocator: std.mem.Allocator,
    known_nodes: std.ArrayList(yam.PeerInfo),
    connections: std.AutoHashMap(usize, *Connection), // keyed by node_index
    unconnected_nodes: std.AutoHashMap(usize, void), // node indices not yet connected
    node_metadata: std.AutoHashMap(usize, NodeMetadata), // discovered info about nodes
    mempool: std.StringHashMap(MempoolEntry), // txid hex -> entry
    seen_nodes: std.StringHashMap(void),
    edges: std.ArrayList(Edge),
    stdout: std.fs.File,

    manager_thread: ?std.Thread,
    pending_commands: std.ArrayList(ManagerCommand),
    mutex: std.Thread.Mutex,
    should_stop: std.atomic.Value(bool),
    fd_error_logged: std.atomic.Value(bool),

    msg_type_counts: std.StringHashMap(u64),
    last_block_hash: ?[64]u8 = null,
    last_block_time: ?i64 = null,
    blocks_seen: u64 = 0,
    session_start: i64,
    highest_peer_height: u32 = 0,

    pub fn init(allocator: std.mem.Allocator) !*Explorer {
        const self = try allocator.create(Explorer);
        self.* = .{
            .allocator = allocator,
            .known_nodes = std.ArrayList(yam.PeerInfo).empty,
            .connections = std.AutoHashMap(usize, *Connection).init(allocator),
            .unconnected_nodes = std.AutoHashMap(usize, void).init(allocator),
            .node_metadata = std.AutoHashMap(usize, NodeMetadata).init(allocator),
            .mempool = std.StringHashMap(MempoolEntry).init(allocator),
            .seen_nodes = std.StringHashMap(void).init(allocator),
            .edges = std.ArrayList(Edge).empty,
            .stdout = std.fs.File.stdout(),
            .manager_thread = null,
            .pending_commands = std.ArrayList(ManagerCommand).empty,
            .mutex = .{},
            .should_stop = std.atomic.Value(bool).init(false),
            .fd_error_logged = std.atomic.Value(bool).init(false),
            .msg_type_counts = std.StringHashMap(u64).init(allocator),
            .session_start = std.time.timestamp(),
        };
        return self;
    }

    pub fn deinit(self: *Explorer) void {
        self.should_stop.store(true, .release);
        if (self.manager_thread) |thread| {
            thread.join();
        }

        var conn_iter = self.connections.valueIterator();
        while (conn_iter.next()) |conn_ptr| {
            const conn = conn_ptr.*;
            std.posix.close(conn.socket);
            self.allocator.destroy(conn);
        }
        self.connections.deinit();
        self.unconnected_nodes.deinit();

        var meta_iter = self.node_metadata.valueIterator();
        while (meta_iter.next()) |meta| {
            @constCast(meta).deinit(self.allocator);
        }
        self.node_metadata.deinit();

        var mempool_iter = self.mempool.iterator();
        while (mempool_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            @constCast(entry.value_ptr).deinit(self.allocator);
        }
        self.mempool.deinit();

        var seen_iter = self.seen_nodes.keyIterator();
        while (seen_iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.seen_nodes.deinit();

        for (self.edges.items) |edge| {
            self.allocator.free(edge.source);
            self.allocator.free(edge.node);
        }
        self.edges.deinit(self.allocator);

        self.known_nodes.deinit(self.allocator);
        self.pending_commands.deinit(self.allocator);
        var msg_iter = self.msg_type_counts.keyIterator();
        while (msg_iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.msg_type_counts.deinit();
        self.allocator.destroy(self);
    }

    pub fn run(self: *Explorer) !void {
        var stdout_buffer: [4096]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
        const stdout = &stdout_writer.interface;

        // Set terminal to raw mode for character-by-character input
        const original_terminal = platform.setRawMode();
        defer platform.restoreTerminalMode(original_terminal);

        // Try to raise file descriptor limit
        const fd_limit = platform.raiseFileDescriptorLimit();

        // ASCII art banner
        try stdout.print("{s}", .{Color.yellow});
        try stdout.writeAll(
            \\  __   __   ___    __  __
            \\  \ \ / /  / _ \  |  \/  |
            \\   \ V /  | |_| | | |\/| |
            \\    | |   |  _  | | |  | |
            \\    |_|   |_| |_| |_|  |_|
            \\    ᠶᠠᠮ
        );
        try stdout.print("{s}\n\n", .{Color.reset});
        try stdout.print("  {s}Bitcoin P2P Explorer{s} - type 'help' for commands\n", .{ Color.dim, Color.reset });
        try stdout.print("  {s}Max connections: {d}{s}\n\n", .{ Color.dim, fd_limit, Color.reset });
        try stdout.flush();

        self.manager_thread = try std.Thread.spawn(.{}, managerThread, .{self});

        while (!self.should_stop.load(.acquire)) {
            try stdout.print("{s}>{s} ", .{ Color.green, Color.reset });
            try stdout.flush();

            var line_buf: [1024]u8 = undefined;
            var line_len: usize = 0;

            while (line_len < line_buf.len) {
                var byte_buf: [1]u8 = undefined;
                const n = std.fs.File.stdin().read(&byte_buf) catch break;
                if (n == 0) break;
                const c = byte_buf[0];
                if (c == '\n' or c == '\r') break;
                // Handle backspace (0x7F) and delete (0x08)
                if (c == 0x7F or c == 0x08) {
                    if (line_len > 0) {
                        line_len -= 1;
                        // Erase character on screen: backspace, space, backspace
                        try stdout.writeAll("\x08 \x08");
                        try stdout.flush();
                    }
                    continue;
                }
                // Ignore other control characters
                if (c < 32 and c != '\t') continue;
                // Echo the character
                try stdout.writeByte(c);
                try stdout.flush();
                line_buf[line_len] = c;
                line_len += 1;
            }

            // Echo newline
            try stdout.writeByte('\n');
            try stdout.flush();

            if (line_len == 0) continue;

            const line = line_buf[0..line_len];

            self.handleCommand(line, stdout) catch |err| {
                try stdout.print("{s}Error:{s} {}\n", .{ Color.red, Color.reset, err });
            };
            try stdout.flush();
        }
    }

    fn handleCommand(self: *Explorer, line: []const u8, stdout: anytype) !void {
        var iter = std.mem.tokenizeScalar(u8, line, ' ');
        const cmd = iter.next() orelse return;

        if (std.mem.eql(u8, cmd, "discover") or std.mem.eql(u8, cmd, "d")) {
            try self.cmdDiscover(stdout);
        } else if (std.mem.eql(u8, cmd, "nodes") or std.mem.eql(u8, cmd, "n") or std.mem.eql(u8, cmd, "ls")) {
            try self.cmdNodes(stdout);
        } else if (std.mem.eql(u8, cmd, "connect") or std.mem.eql(u8, cmd, "c")) {
            try self.cmdConnect(&iter, stdout);
        } else if (std.mem.eql(u8, cmd, "disconnect") or std.mem.eql(u8, cmd, "dc")) {
            try self.cmdDisconnect(&iter, stdout);
        } else if (std.mem.eql(u8, cmd, "stream")) {
            try self.cmdStream(&iter, stdout);
        } else if (std.mem.eql(u8, cmd, "getaddr") or std.mem.eql(u8, cmd, "ga")) {
            try self.cmdGetaddr(&iter, stdout);
        } else if (std.mem.eql(u8, cmd, "graph")) {
            try self.cmdGraph(stdout);
        } else if (std.mem.eql(u8, cmd, "mempool") or std.mem.eql(u8, cmd, "mp")) {
            try self.cmdMempool(stdout);
        } else if (std.mem.eql(u8, cmd, "status") or std.mem.eql(u8, cmd, "s")) {
            try self.cmdStatus(stdout);
        } else if (std.mem.eql(u8, cmd, "ping")) {
            try self.cmdPing(&iter, stdout);
        } else if (std.mem.eql(u8, cmd, "export") or std.mem.eql(u8, cmd, "x")) {
            try self.cmdExport(&iter, stdout);
        } else if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "h") or std.mem.eql(u8, cmd, "?")) {
            try self.cmdHelp(stdout);
        } else if (std.mem.eql(u8, cmd, "quit") or std.mem.eql(u8, cmd, "exit") or std.mem.eql(u8, cmd, "q")) {
            self.should_stop.store(true, .release);
        } else {
            try stdout.print("Unknown command: {s}\n", .{cmd});
        }
    }

    fn cmdDiscover(self: *Explorer, stdout: anytype) !void {
        try stdout.print("Discovering nodes via DNS...\n", .{});

        var node_list = try scout.discoverPeers(self.allocator);
        defer node_list.deinit(self.allocator);

        var added: usize = 0;
        for (node_list.items) |node| {
            const key = try self.formatNodeKey(node);

            try self.edges.append(self.allocator, .{
                .source = try self.allocator.dupe(u8, "dns"),
                .node = try self.allocator.dupe(u8, key),
            });

            if (!self.seen_nodes.contains(key)) {
                try self.seen_nodes.put(key, {});
                try self.known_nodes.append(self.allocator, node);
                try self.unconnected_nodes.put(self.known_nodes.items.len, {});
                added += 1;
            } else {
                self.allocator.free(key);
            }
        }

        try stdout.print("Found {s}{d}{s} nodes ({s}{d}{s} new)\n", .{
            Color.green, node_list.items.len, Color.reset,
            Color.green, added,               Color.reset,
        });
    }

    fn cmdNodes(self: *Explorer, stdout: anytype) !void {
        if (self.known_nodes.items.len == 0) {
            try stdout.print("No nodes known. Run {s}discover{s} first.\n", .{ Color.yellow, Color.reset });
            return;
        }

        // Build output in buffer first
        var output = std.ArrayList(u8).empty;
        defer output.deinit(self.allocator);
        const writer = output.writer(self.allocator);

        self.mutex.lock();
        defer self.mutex.unlock();

        var connected_count: usize = 0;
        var count_iter = self.connections.valueIterator();
        while (count_iter.next()) |conn| {
            if (conn.*.state == .connected) connected_count += 1;
        }

        try writer.print("Nodes ({s}{d}{s} known, {s}{d}{s} connected):\n", .{
            Color.dim,   self.known_nodes.items.len, Color.reset,
            Color.green, connected_count,            Color.reset,
        });

        for (self.known_nodes.items, 0..) |node, i| {
            const node_index = i + 1;
            const addr_str = node.format();
            const addr = std.mem.sliceTo(&addr_str, ' ');

            // Get metadata if we have it
            const metadata = self.node_metadata.get(node_index);
            const user_agent: []const u8 = if (metadata) |m| m.user_agent orelse "" else "";
            const latency_ms = if (metadata) |m| m.latency_ms else null;

            if (self.connections.get(node_index)) |conn| {
                const status = switch (conn.state) {
                    .connecting => .{ Color.yellow, "connecting" },
                    .handshaking => .{ Color.yellow, "handshaking" },
                    .connected => .{ Color.green, "connected" },
                    .failed => .{ Color.red, "failed" },
                };

                // Base line: index, address, status
                try writer.print("  [{d:>3}] {s:<21} {s}{s:<12}{s}", .{
                    node_index, addr, status[0], status[1], Color.reset,
                });

                // Add latency if available
                if (latency_ms) |lat| {
                    try writer.print(" {s}{d}ms{s}", .{ Color.dim, lat, Color.reset });
                }

                // Add user_agent if available
                if (user_agent.len > 0) {
                    try writer.print(" {s}{s}{s}", .{ Color.dim, user_agent, Color.reset });
                }

                try writer.writeByte('\n');
            } else {
                try writer.print("  {s}[{d:>3}] {s}{s}\n", .{ Color.dim, node_index, addr, Color.reset });
            }
        }

        // Use pager for long output, otherwise print directly
        const line_count = std.mem.count(u8, output.items, "\n");
        if (line_count > 30) {
            self.mutex.unlock();
            defer self.mutex.lock();
            pipeToLess(output.items) catch {
                try stdout.writeAll(output.items);
            };
        } else {
            try stdout.writeAll(output.items);
        }
    }

    fn pipeToLess(content: []const u8) !void {
        var child = std.process.Child.init(
            &.{ "less", "-R" },
            std.heap.page_allocator,
        );
        child.stdin_behavior = .Pipe;

        try child.spawn();

        if (child.stdin) |stdin| {
            stdin.writeAll(content) catch {};
            stdin.close();
        }
        // Set to null so wait() doesn't try to close again
        child.stdin = null;

        _ = child.wait() catch {};
    }

    fn cmdConnect(self: *Explorer, iter: *std.mem.TokenIterator(u8, .scalar), stdout: anytype) !void {
        var count: usize = 0;
        var has_args = false;

        while (iter.next()) |arg| {
            has_args = true;

            // Try parsing as range (e.g., 1-10)
            if (parseRange(arg)) |range| {
                for (range.start..range.end + 1) |idx| {
                    count += self.connectToIndex(idx, stdout);
                }
                continue;
            }

            // Try parsing as index
            if (std.fmt.parseInt(usize, arg, 10)) |idx| {
                count += self.connectToIndex(idx, stdout);
            } else |_| {
                // Try parsing as ip:port
                const node_index = self.addNodeFromString(arg) catch |err| {
                    try stdout.print("{s}Invalid address:{s} {s} ({s})\n", .{
                        Color.red, Color.reset, arg, @errorName(err),
                    });
                    continue;
                };
                count += self.connectToIndex(node_index, stdout);
            }
        }

        // No args = connect to all unconnected nodes
        if (!has_args) {
            if (self.unconnected_nodes.count() == 0) {
                try stdout.print("{s}No unconnected nodes{s}\n", .{ Color.yellow, Color.reset });
                return;
            }
            // Collect indices first to avoid iterator invalidation
            var indices = std.ArrayList(usize).empty;
            defer indices.deinit(self.allocator);
            var key_iter = self.unconnected_nodes.keyIterator();
            while (key_iter.next()) |idx| {
                indices.append(self.allocator, idx.*) catch {};
            }
            for (indices.items) |idx| {
                count += self.connectToIndex(idx, stdout);
            }
        }

        if (count == 0) {
            try stdout.print("{s}No new connections to make{s}\n", .{ Color.yellow, Color.reset });
        } else {
            try stdout.print("Connecting to {s}{d}{s} node(s)...\n", .{ Color.green, count, Color.reset });
        }
    }

    fn connectToIndex(self: *Explorer, idx: usize, _: anytype) usize {
        if (idx == 0 or idx > self.known_nodes.items.len) {
            return 0;
        }

        self.mutex.lock();
        const already_connected = self.connections.contains(idx);
        if (!already_connected) {
            self.pending_commands.append(self.allocator, .{ .connect = idx }) catch {};
            _ = self.unconnected_nodes.remove(idx);
        }
        self.mutex.unlock();

        if (already_connected) {
            return 0;
        }
        return 1;
    }

    fn addNodeFromString(self: *Explorer, addr_str: []const u8) !usize {
        // Parse ip:port format
        var port: u16 = 8333; // default Bitcoin port
        var ip_str = addr_str;

        if (std.mem.lastIndexOfScalar(u8, addr_str, ':')) |colon_idx| {
            port = std.fmt.parseInt(u16, addr_str[colon_idx + 1 ..], 10) catch 8333;
            ip_str = addr_str[0..colon_idx];
        }

        const addr = std.net.Address.parseIp4(ip_str, port) catch {
            return error.InvalidAddress;
        };

        const peer = yam.PeerInfo{
            .address = addr,
            .source = .cli_manual,
        };

        // Check if already known
        const key = try self.formatNodeKey(peer);
        if (self.seen_nodes.contains(key)) {
            // Find existing index by comparing formatted address
            for (self.known_nodes.items, 0..) |node, i| {
                const node_key = self.formatNodeKey(node) catch continue;
                defer self.allocator.free(node_key);
                if (std.mem.eql(u8, node_key, key)) {
                    self.allocator.free(key);
                    return i + 1;
                }
            }
            // Shouldn't happen, but just in case
            self.allocator.free(key);
            return error.InvalidAddress;
        }

        // Add new node
        try self.seen_nodes.put(key, {});
        try self.known_nodes.append(self.allocator, peer);
        const node_index = self.known_nodes.items.len;
        try self.unconnected_nodes.put(node_index, {});
        return node_index;
    }

    fn cmdDisconnect(self: *Explorer, iter: *std.mem.TokenIterator(u8, .scalar), stdout: anytype) !void {
        var count: usize = 0;
        while (iter.next()) |arg| {
            const idx = std.fmt.parseInt(usize, arg, 10) catch {
                try stdout.print("{s}Invalid index:{s} {s}\n", .{ Color.red, Color.reset, arg });
                continue;
            };

            self.mutex.lock();
            const exists = self.connections.contains(idx);
            if (exists) {
                self.pending_commands.append(self.allocator, .{ .disconnect = idx }) catch {};
            }
            self.mutex.unlock();

            if (!exists) {
                try stdout.print("{s}Not connected:{s} {d}\n", .{ Color.yellow, Color.reset, idx });
            } else {
                count += 1;
            }
        }

        if (count == 0) {
            try stdout.print("Usage: {s}disconnect <n> [n...]{s}\n", .{ Color.dim, Color.reset });
        } else {
            try stdout.print("Disconnecting from {s}{d}{s} node(s)...\n", .{ Color.yellow, count, Color.reset });
        }
    }

    fn cmdStream(self: *Explorer, iter: *std.mem.TokenIterator(u8, .scalar), stdout: anytype) !void {
        const idx_str = iter.next() orelse {
            try stdout.print("Usage: {s}stream <n> on|off{s}\n", .{ Color.dim, Color.reset });
            return;
        };
        const on_off = iter.next() orelse {
            try stdout.print("Usage: {s}stream <n> on|off{s}\n", .{ Color.dim, Color.reset });
            return;
        };

        const idx = std.fmt.parseInt(usize, idx_str, 10) catch {
            try stdout.print("{s}Invalid index:{s} {s}\n", .{ Color.red, Color.reset, idx_str });
            return;
        };

        const enabled = std.mem.eql(u8, on_off, "on");

        self.mutex.lock();
        const exists = self.connections.contains(idx);
        if (exists) {
            self.pending_commands.append(self.allocator, .{
                .set_streaming = .{ .node_index = idx, .enabled = enabled },
            }) catch {};
        }
        self.mutex.unlock();

        if (!exists) {
            try stdout.print("{s}Not connected:{s} {d}\n", .{ Color.yellow, Color.reset, idx });
        } else {
            try stdout.print("Streaming {s}{s}{s}\n", .{
                if (enabled) Color.green else Color.yellow,
                if (enabled) "enabled" else "disabled",
                Color.reset,
            });
        }
    }

    fn cmdGetaddr(self: *Explorer, iter: *std.mem.TokenIterator(u8, .scalar), stdout: anytype) !void {
        var count: usize = 0;
        var has_args = false;

        while (iter.next()) |arg| {
            has_args = true;
            const idx = std.fmt.parseInt(usize, arg, 10) catch {
                try stdout.print("{s}Invalid index:{s} {s}\n", .{ Color.red, Color.reset, arg });
                continue;
            };

            self.mutex.lock();
            const conn = self.connections.get(idx);
            const is_connected = conn != null and conn.?.state == .connected;
            if (is_connected) {
                self.pending_commands.append(self.allocator, .{ .send_getaddr = idx }) catch {};
            }
            self.mutex.unlock();

            if (conn == null) {
                try stdout.print("{s}Not connected:{s} {d}\n", .{ Color.yellow, Color.reset, idx });
            } else if (!is_connected) {
                try stdout.print("{s}Not ready:{s} {d}\n", .{ Color.yellow, Color.reset, idx });
            } else {
                count += 1;
            }
        }

        // No args = send to all connected nodes
        if (!has_args) {
            self.mutex.lock();
            var conn_iter = self.connections.iterator();
            while (conn_iter.next()) |entry| {
                if (entry.value_ptr.*.state == .connected) {
                    self.pending_commands.append(self.allocator, .{ .send_getaddr = entry.key_ptr.* }) catch {};
                    count += 1;
                }
            }
            self.mutex.unlock();
        }

        if (count == 0) {
            try stdout.print("{s}No connected nodes{s}\n", .{ Color.yellow, Color.reset });
        } else {
            try stdout.print("Sent getaddr to {s}{d}{s} node(s)\n", .{ Color.green, count, Color.reset });
        }
    }

    fn cmdGraph(self: *Explorer, stdout: anytype) !void {
        if (self.edges.items.len == 0) {
            try stdout.print("No edges. Run {s}discover{s} first.\n", .{ Color.yellow, Color.reset });
            return;
        }

        // Build output in buffer for potential paging
        var output = std.ArrayList(u8).empty;
        defer output.deinit(self.allocator);
        const writer = output.writer(self.allocator);

        try writer.print("Network graph ({s}{d}{s} edges):\n", .{ Color.dim, self.edges.items.len, Color.reset });
        for (self.edges.items) |edge| {
            try writer.print("  {s} {s}<-{s} {s}\n", .{ edge.node, Color.dim, Color.reset, edge.source });
        }

        // Use pager for long output
        const line_count = std.mem.count(u8, output.items, "\n");
        if (line_count > 30) {
            pipeToLess(output.items) catch {
                try stdout.writeAll(output.items);
            };
        } else {
            try stdout.writeAll(output.items);
        }
    }

    fn cmdMempool(self: *Explorer, stdout: anytype) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.mempool.count() == 0) {
            try stdout.print("Mempool is empty. Connect to nodes to receive transactions.\n", .{});
            return;
        }

        // Build output in buffer for potential paging
        var output = std.ArrayList(u8).empty;
        defer output.deinit(self.allocator);
        const writer = output.writer(self.allocator);

        try writer.print("Mempool ({s}{d}{s} transactions):\n\n", .{
            Color.green, self.mempool.count(), Color.reset,
        });

        var iter = self.mempool.iterator();
        while (iter.next()) |entry| {
            const mp_entry = entry.value_ptr;
            const has_data = mp_entry.tx_data != null;

            // Full txid
            try writer.print("  {s}{s}{s}", .{
                if (has_data) Color.green else Color.yellow,
                entry.key_ptr.*,
                Color.reset,
            });

            // Size if we have data
            if (mp_entry.tx_data) |data| {
                try writer.print(" ({d} bytes)", .{data.len});
            }

            try writer.print("\n", .{});

            // Announcements
            try writer.print("    {s}Announced by {d} node(s):{s}", .{
                Color.dim,
                mp_entry.announcements.items.len,
                Color.reset,
            });

            // Show first few announcing nodes
            const max_show: usize = 5;
            for (mp_entry.announcements.items, 0..) |ann, i| {
                if (i >= max_show) {
                    try writer.print(" ...", .{});
                    break;
                }
                try writer.print(" [{d}]", .{ann.node_index});
            }
            try writer.print("\n\n", .{});
        }

        // Use pager for long output
        const line_count = std.mem.count(u8, output.items, "\n");
        if (line_count > 30) {
            self.mutex.unlock();
            defer self.mutex.lock();
            pipeToLess(output.items) catch {
                try stdout.writeAll(output.items);
            };
        } else {
            try stdout.writeAll(output.items);
        }
    }

    fn cmdStatus(self: *Explorer, stdout: anytype) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var connected: usize = 0;
        var connecting: usize = 0;
        var failed: usize = 0;

        var conn_iter = self.connections.valueIterator();
        while (conn_iter.next()) |conn| {
            switch (conn.*.state) {
                .connected => connected += 1,
                .connecting, .handshaking => connecting += 1,
                .failed => failed += 1,
            }
        }

        const total_nodes = self.known_nodes.items.len;
        const other = total_nodes -| connected -| connecting -| failed;
        const mempool_size = self.mempool.count();

        // Count transactions with full data vs just seen
        var tx_with_data: usize = 0;
        var mempool_iter = self.mempool.valueIterator();
        while (mempool_iter.next()) |entry| {
            if (entry.tx_data != null) {
                tx_with_data += 1;
            }
        }

        try stdout.print(
            \\{0s}Status:{1s}
            \\  Nodes:       {2s}{3d}{1s} connected / {4d} known
            \\  Connections: {5s}{6d}{1s} connecting, {7s}{8d}{1s} failed, {9d} other
            \\  Mempool:     {2s}{10d}{1s} with data / {11d} seen
            \\
        , .{
            Color.dim,    Color.reset,
            Color.green,  connected,
            total_nodes,  Color.yellow,
            connecting,   Color.red,
            failed,       other,
            tx_with_data, mempool_size,
        });
    }

    fn cmdPing(self: *Explorer, iter: *std.mem.TokenIterator(u8, .scalar), stdout: anytype) !void {
        var count: usize = 0;
        var has_args = false;

        while (iter.next()) |arg| {
            has_args = true;

            // Try parsing as range (e.g., 1-10)
            if (parseRange(arg)) |range| {
                for (range.start..range.end + 1) |idx| {
                    count += self.pingNode(idx);
                }
                continue;
            }

            const idx = std.fmt.parseInt(usize, arg, 10) catch {
                try stdout.print("{s}Invalid index:{s} {s}\n", .{ Color.red, Color.reset, arg });
                continue;
            };

            count += self.pingNode(idx);
        }

        // No args = ping all connected nodes
        if (!has_args) {
            self.mutex.lock();
            var conn_iter = self.connections.iterator();
            while (conn_iter.next()) |entry| {
                if (entry.value_ptr.*.state == .connected) {
                    self.pending_commands.append(self.allocator, .{ .send_ping = entry.key_ptr.* }) catch {};
                    count += 1;
                }
            }
            self.mutex.unlock();
        }

        if (count == 0) {
            try stdout.print("{s}No connected nodes{s}\n", .{ Color.yellow, Color.reset });
        } else {
            try stdout.print("Sent ping to {s}{d}{s} node(s)\n", .{ Color.green, count, Color.reset });
        }
    }

    fn pingNode(self: *Explorer, idx: usize) usize {
        self.mutex.lock();
        const conn = self.connections.get(idx);
        const is_connected = conn != null and conn.?.state == .connected;
        if (is_connected) {
            self.pending_commands.append(self.allocator, .{ .send_ping = idx }) catch {};
        }
        self.mutex.unlock();

        if (is_connected) {
            return 1;
        }
        return 0;
    }

    fn cmdExport(self: *Explorer, iter: *std.mem.TokenIterator(u8, .scalar), stdout: anytype) !void {
        const export_type = iter.next() orelse {
            try stdout.print("Usage: {s}export <nodes|mempool|graph|tx> [csv|dot|txid]{s}\n", .{ Color.dim, Color.reset });
            return;
        };

        if (std.mem.eql(u8, export_type, "nodes")) {
            try self.exportNodes(stdout);
        } else if (std.mem.eql(u8, export_type, "mempool")) {
            try self.exportMempool(stdout);
        } else if (std.mem.eql(u8, export_type, "graph")) {
            const format = iter.next() orelse "csv";
            if (std.mem.eql(u8, format, "csv")) {
                try self.exportGraphCSV(stdout);
            } else if (std.mem.eql(u8, format, "dot")) {
                try self.exportGraphDOT(stdout);
            } else {
                try stdout.print("Unknown format: {s}. Use 'csv' or 'dot'\n", .{format});
            }
        } else if (std.mem.eql(u8, export_type, "tx")) {
            const txid = iter.next() orelse {
                try stdout.print("Usage: {s}export tx <txid>{s}\n", .{ Color.dim, Color.reset });
                return;
            };
            try self.exportTx(txid, stdout);
        } else {
            try stdout.print("Unknown export type: {s}\n", .{export_type});
            try stdout.print("Usage: {s}export <nodes|mempool|graph|tx> [csv|dot|txid]{s}\n", .{ Color.dim, Color.reset });
        }
    }

    fn exportNodes(self: *Explorer, stdout: anytype) !void {
        const filename = try self.makeTimestampedFilename("nodes", "csv");
        defer self.allocator.free(filename);

        const file = std.fs.cwd().createFile(filename, .{}) catch |err| {
            try stdout.print("{s}Error creating file:{s} {s}\n", .{ Color.red, Color.reset, @errorName(err) });
            return;
        };
        defer file.close();

        var buf: [4096]u8 = undefined;
        var file_writer = file.writer(&buf);
        const writer = &file_writer.interface;

        // Write CSV header
        try writer.writeAll("ip,port,user_agent,connection_established,latency_ms\n");

        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.known_nodes.items, 0..) |node, i| {
            const node_index = i + 1;

            // Get IP and port
            var ip_buf: [16]u8 = undefined;
            var port: u16 = 0;
            var ip: []const u8 = "";
            if (node.address.any.family == std.posix.AF.INET) {
                const addr = node.address.in;
                const ip_bytes = @as(*const [4]u8, @ptrCast(&addr.sa.addr));
                ip = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                }) catch continue;
                port = std.mem.bigToNative(u16, addr.sa.port);
            } else {
                continue; // Skip non-IPv4
            }

            // Get metadata
            const metadata = self.node_metadata.get(node_index);
            const user_agent = if (metadata) |m| m.user_agent orelse "" else "";
            const ever_connected = if (metadata) |m| m.ever_connected else false;
            const latency_ms = if (metadata) |m| m.latency_ms else null;

            // Write CSV row - escape user_agent if it contains commas
            try writer.print("{s},{d},", .{ ip, port });
            try writeCSVField(writer, user_agent);
            try writer.print(",{s},", .{if (ever_connected) "true" else "false"});

            if (latency_ms) |lat| {
                try writer.print("{d}", .{lat});
            }
            try writer.writeByte('\n');
        }

        try writer.flush();
        try stdout.print("Exported {s}{d}{s} nodes to {s}{s}{s}\n", .{
            Color.green, self.known_nodes.items.len, Color.reset,
            Color.green, filename,                   Color.reset,
        });
    }

    fn exportMempool(self: *Explorer, stdout: anytype) !void {
        const filename = try self.makeTimestampedFilename("mempool", "csv");
        defer self.allocator.free(filename);

        const file = std.fs.cwd().createFile(filename, .{}) catch |err| {
            try stdout.print("{s}Error creating file:{s} {s}\n", .{ Color.red, Color.reset, @errorName(err) });
            return;
        };
        defer file.close();

        var buf: [4096]u8 = undefined;
        var file_writer = file.writer(&buf);
        const writer = &file_writer.interface;

        // Write CSV header
        try writer.writeAll("txid,node_ip,node_user_agent,announcement_timestamp\n");

        self.mutex.lock();
        defer self.mutex.unlock();

        var row_count: usize = 0;
        var iter = self.mempool.iterator();
        while (iter.next()) |entry| {
            const txid = entry.key_ptr.*;
            const mp_entry = entry.value_ptr;

            for (mp_entry.announcements.items) |ann| {
                // Get node info
                if (ann.node_index == 0 or ann.node_index > self.known_nodes.items.len) continue;
                const node = self.known_nodes.items[ann.node_index - 1];

                // Get IP
                var ip_buf: [22]u8 = undefined;
                var ip: []const u8 = "";
                if (node.address.any.family == std.posix.AF.INET) {
                    const addr = node.address.in;
                    const ip_bytes = @as(*const [4]u8, @ptrCast(&addr.sa.addr));
                    const port = std.mem.bigToNative(u16, addr.sa.port);
                    ip = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}:{d}", .{
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port,
                    }) catch continue;
                } else {
                    continue;
                }

                // Get user_agent
                const metadata = self.node_metadata.get(ann.node_index);
                const user_agent = if (metadata) |m| m.user_agent orelse "" else "";

                // Write row
                try writer.print("{s},{s},", .{ txid, ip });
                try writeCSVField(writer, user_agent);
                try writer.print(",{d}\n", .{ann.timestamp});
                row_count += 1;
            }
        }

        try writer.flush();
        try stdout.print("Exported {s}{d}{s} announcements to {s}{s}{s}\n", .{
            Color.green, row_count, Color.reset,
            Color.green, filename,  Color.reset,
        });
    }

    fn exportGraphCSV(self: *Explorer, stdout: anytype) !void {
        if (self.edges.items.len == 0) {
            try stdout.print("No edges to export. Run {s}getaddr{s} first.\n", .{ Color.yellow, Color.reset });
            return;
        }

        const filename = try self.makeTimestampedFilename("graph", "csv");
        defer self.allocator.free(filename);

        const file = std.fs.cwd().createFile(filename, .{}) catch |err| {
            try stdout.print("{s}Error creating file:{s} {s}\n", .{ Color.red, Color.reset, @errorName(err) });
            return;
        };
        defer file.close();

        var buf: [4096]u8 = undefined;
        var file_writer = file.writer(&buf);
        const writer = &file_writer.interface;

        // Write CSV header
        try writer.writeAll("source,target\n");

        for (self.edges.items) |edge| {
            try writer.print("{s},{s}\n", .{ edge.source, edge.node });
        }

        try writer.flush();
        try stdout.print("Exported {s}{d}{s} edges to {s}{s}{s}\n", .{
            Color.green, self.edges.items.len, Color.reset,
            Color.green, filename,             Color.reset,
        });
    }

    fn exportGraphDOT(self: *Explorer, stdout: anytype) !void {
        if (self.edges.items.len == 0) {
            try stdout.print("No edges to export. Run {s}getaddr{s} first.\n", .{ Color.yellow, Color.reset });
            return;
        }

        const filename = try self.makeTimestampedFilename("graph", "dot");
        defer self.allocator.free(filename);

        const file = std.fs.cwd().createFile(filename, .{}) catch |err| {
            try stdout.print("{s}Error creating file:{s} {s}\n", .{ Color.red, Color.reset, @errorName(err) });
            return;
        };
        defer file.close();

        var buf: [4096]u8 = undefined;
        var file_writer = file.writer(&buf);
        const writer = &file_writer.interface;

        // Write DOT format
        try writer.writeAll("digraph node_getaddr_graph {\n");
        try writer.writeAll("  rankdir=LR;\n");
        try writer.writeAll("  node [shape=box];\n\n");

        for (self.edges.items) |edge| {
            try writer.print("  \"{s}\" -> \"{s}\";\n", .{ edge.source, edge.node });
        }

        try writer.writeAll("}\n");

        try writer.flush();
        try stdout.print("Exported {s}{d}{s} edges to {s}{s}{s}\n", .{
            Color.green, self.edges.items.len, Color.reset,
            Color.green, filename,             Color.reset,
        });
        try stdout.print("View at: {s}https://dreampuf.github.io/GraphvizOnline/{s}\n", .{ Color.dim, Color.reset });
    }

    fn exportTx(self: *Explorer, txid: []const u8, stdout: anytype) !void {
        // Validate txid length
        if (txid.len != 64) {
            try stdout.print("{s}Invalid txid:{s} must be 64 hex characters\n", .{ Color.red, Color.reset });
            return;
        }

        // Make sure we can find the transaction and it has data
        self.mutex.lock();
        defer self.mutex.unlock();

        const entry = self.mempool.get(txid) orelse {
            try stdout.print("{s}Transaction not found:{s} {s}\n", .{ Color.red, Color.reset, txid });
            return;
        };
        const tx_data = entry.tx_data orelse {
            try stdout.print("{s}Transaction data not available:{s} only seen in INV, not yet received\n", .{ Color.red, Color.reset });
            return;
        };

        // Create filename and file
        const filename = try std.fmt.allocPrint(self.allocator, "{s}.hex", .{txid});
        defer self.allocator.free(filename);

        const file = std.fs.cwd().createFile(filename, .{}) catch |err| {
            try stdout.print("{s}Error creating file:{s} {s}\n", .{ Color.red, Color.reset, @errorName(err) });
            return;
        };
        defer file.close();

        var buf: [4096]u8 = undefined;
        var file_writer = file.writer(&buf);
        const writer = &file_writer.interface;

        // Write hex
        for (tx_data) |byte| {
            var hex_byte: [2]u8 = undefined;
            _ = std.fmt.bufPrint(&hex_byte, "{x:0>2}", .{byte}) catch unreachable;
            file.writeAll(&hex_byte) catch |err| {
                try stdout.print("{s}Error writing file:{s} {s}\n", .{ Color.red, Color.reset, @errorName(err) });
                return;
            };
        }

        try writer.flush();
        try stdout.print("Exported transaction to {s}{s}{s} ({d} bytes)\n", .{
            Color.green, filename, Color.reset, tx_data.len,
        });
    }

    fn makeTimestampedFilename(self: *Explorer, prefix: []const u8, ext: []const u8) ![]u8 {
        const now = std.time.timestamp();

        // Convert timestamp to date/time components
        // Days since epoch
        const days_since_epoch = @divFloor(now, 86400);
        const secs_today: u64 = @intCast(@mod(now, 86400));

        // Calculate year, month, day
        var year: i32 = 1970;
        var remaining_days: i64 = days_since_epoch;

        while (true) {
            const days_in_year: i64 = if (@mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0)) 366 else 365;
            if (remaining_days < days_in_year) break;
            remaining_days -= days_in_year;
            year += 1;
        }

        const is_leap = @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
        const days_in_month = [_]u8{ 31, if (is_leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

        var month: u8 = 1;
        for (days_in_month) |dim| {
            if (remaining_days < dim) break;
            remaining_days -= dim;
            month += 1;
        }
        const day: u8 = @intCast(remaining_days + 1);

        const hour: u8 = @intCast(secs_today / 3600);
        const minute: u8 = @intCast((secs_today % 3600) / 60);
        const second: u8 = @intCast(secs_today % 60);

        // Format: prefix_YYYY-MM-DD_HHMMSS.ext
        return std.fmt.allocPrint(self.allocator, "{s}_{d:0>4}-{d:0>2}-{d:0>2}_{d:0>2}{d:0>2}{d:0>2}.{s}", .{
            prefix, year, month, day, hour, minute, second, ext,
        });
    }

    fn cmdHelp(self: *Explorer, stdout: anytype) !void {
        _ = self;
        try stdout.print(
            \\{0s}Commands:{1s}
            \\  {0s}discover, d{1s}            Discover nodes via DNS seeds
            \\  {0s}nodes, n, ls{1s}           List nodes (with connection status)
            \\  {0s}connect, c{1s} [n|n-m|ip]  Connect to nodes (all if no args)
            \\  {0s}disconnect, dc{1s} <n>     Disconnect from node(s)
            \\  {0s}stream{1s} <n> on|off      Toggle message streaming
            \\  {0s}getaddr, ga{1s} [n...]     Request addresses (all if no args)
            \\  {0s}ping{1s} [n...]            Measure latency (all if no args)
            \\  {0s}graph{1s}                  Show network graph
            \\  {0s}mempool, mp{1s}            Show observed mempool transactions
            \\  {0s}status, s{1s}              Show connection status
            \\  {0s}export, x{1s} <nodes|mempool|graph|tx> [csv|dot|txid]  Export data
            \\  {0s}help, h, ?{1s}             Show this help
            \\  {0s}quit, q{1s}                Exit
            \\
        , .{ Color.green, Color.reset });
    }

    fn formatNodeKey(self: *Explorer, node: yam.PeerInfo) ![]u8 {
        const addr_str = node.format();
        return try self.allocator.dupe(u8, std.mem.sliceTo(&addr_str, ' '));
    }

    fn writeCSVField(writer: anytype, field: []const u8) !void {
        if (std.mem.indexOfScalar(u8, field, ',') != null or
            std.mem.indexOfScalar(u8, field, '"') != null)
        {
            try writer.writeByte('"');
            for (field) |c| {
                if (c == '"') {
                    try writer.writeAll("\"\"");
                } else {
                    try writer.writeByte(c);
                }
            }
            try writer.writeByte('"');
        } else {
            try writer.writeAll(field);
        }
    }

    fn parseRange(arg: []const u8) ?struct { start: usize, end: usize } {
        const dash_idx = std.mem.indexOfScalar(u8, arg, '-') orelse return null;
        if (dash_idx == 0 or dash_idx >= arg.len - 1) return null;
        const start = std.fmt.parseInt(usize, arg[0..dash_idx], 10) catch return null;
        const end = std.fmt.parseInt(usize, arg[dash_idx + 1 ..], 10) catch return null;
        if (start > end) return null;
        return .{ .start = start, .end = end };
    }

    // =========================================================================
    // Manager Thread
    // =========================================================================

    pub fn managerThread(self: *Explorer) void {
        while (!self.should_stop.load(.acquire)) {
            self.processPendingCommands();
            self.pollConnections();
        }
    }

    fn processPendingCommands(self: *Explorer) void {
        self.mutex.lock();
        var cmds = self.pending_commands;
        self.pending_commands = std.ArrayList(ManagerCommand).empty;
        self.mutex.unlock();

        defer cmds.deinit(self.allocator);

        for (cmds.items) |cmd| {
            switch (cmd) {
                .connect => |idx| self.startConnect(idx),
                .disconnect => |idx| self.closeConnectionByIndex(idx),
                .set_streaming => |s| self.setStreaming(s.node_index, s.enabled),
                .send_getaddr => |idx| self.sendGetaddr(idx),
                .send_ping => |idx| self.sendPing(idx),
            }
        }
    }

    fn startConnect(self: *Explorer, node_index: usize) void {
        if (node_index == 0 or node_index > self.known_nodes.items.len) return;
        const peer = self.known_nodes.items[node_index - 1];

        const socket = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK, 0) catch |err| {
            if (err == error.ProcessFdQuotaExceeded or err == error.SystemFdQuotaExceeded) {
                std.debug.print("{s}Out of file descriptors{s} - try increasing ulimit\n", .{ Color.red, Color.reset });
            }
            return;
        };
        errdefer std.posix.close(socket);

        std.posix.connect(socket, &peer.address.any, @sizeOf(std.posix.sockaddr.in)) catch |err| {
            if (err != error.WouldBlock) {
                std.posix.close(socket);
                return;
            }
        };

        const conn = self.allocator.create(Connection) catch {
            std.posix.close(socket);
            return;
        };
        conn.* = .{
            .socket = socket,
            .node_index = node_index,
            .state = .connecting,
            .streaming = false,
            .handshake_state = .{},
        };

        self.connections.put(node_index, conn) catch {
            self.allocator.destroy(conn);
            std.posix.close(socket);
        };
    }

    fn closeConnectionByIndex(self: *Explorer, node_index: usize) void {
        if (self.connections.fetchRemove(node_index)) |entry| {
            std.posix.close(entry.value.socket);
            self.allocator.destroy(entry.value);
        }
    }

    fn setStreaming(self: *Explorer, node_index: usize, enabled: bool) void {
        if (self.connections.get(node_index)) |conn| {
            conn.streaming = enabled;
        }
    }

    fn sendGetaddr(self: *Explorer, node_index: usize) void {
        const conn = self.connections.get(node_index) orelse return;
        const checksum = yam.calculateChecksum(&.{});
        const header = yam.MessageHeader.new("getaddr", 0, checksum);
        const written = platform.socketWrite(conn.socket, std.mem.asBytes(&header)) catch 0;
        self.trackBytesOut(node_index, written);
    }

    fn sendPing(self: *Explorer, node_index: usize) void {
        const conn = self.connections.get(node_index) orelse return;

        // Generate random nonce
        var nonce: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&nonce)) catch return;

        // Store pending ping info in metadata
        const entry = self.node_metadata.getOrPut(node_index) catch return;
        if (!entry.found_existing) {
            entry.value_ptr.* = .{};
        }
        entry.value_ptr.pending_ping_nonce = nonce;
        entry.value_ptr.pending_ping_time = std.time.milliTimestamp();

        // Send ping with nonce as payload
        const payload = std.mem.asBytes(&nonce);
        const checksum = yam.calculateChecksum(payload);
        const header = yam.MessageHeader.new("ping", @intCast(payload.len), checksum);
        const h_written = platform.socketWrite(conn.socket, std.mem.asBytes(&header)) catch return;
        const p_written = platform.socketWrite(conn.socket, payload) catch return;
        self.trackBytesOut(node_index, h_written + p_written);
    }

    fn pollConnections(self: *Explorer) void {
        self.mutex.lock();
        const count = self.connections.count();
        self.mutex.unlock();

        if (count == 0) {
            std.Thread.sleep(100_000_000);
            return;
        }

        // Heap allocate for large connection counts
        const fds = self.allocator.alloc(std.posix.pollfd, count) catch return;
        defer self.allocator.free(fds);
        const indices = self.allocator.alloc(usize, count) catch return;
        defer self.allocator.free(indices);

        var fd_count: usize = 0;

        self.mutex.lock();
        var conn_iter = self.connections.iterator();
        while (conn_iter.next()) |entry| {
            if (fd_count >= count) break;
            const conn = entry.value_ptr.*;
            indices[fd_count] = entry.key_ptr.*;
            fds[fd_count] = .{
                .fd = conn.socket,
                .events = if (conn.state == .connecting) std.posix.POLL.OUT else std.posix.POLL.IN,
                .revents = 0,
            };
            fd_count += 1;
        }
        self.mutex.unlock();

        if (fd_count == 0) return;

        // Poll in batches to avoid EINVAL on macOS (poll has ~1024 fd limit)
        const batch_size: usize = 1000;
        var offset: usize = 0;
        while (offset < fd_count) {
            const end = @min(offset + batch_size, fd_count);
            const ready = std.posix.poll(fds[offset..end], 10) catch return;
            if (ready > 0) {
                for (fds[offset..end], indices[offset..end]) |fd, node_index| {
                    if (fd.revents == 0) continue;

                    if (fd.revents & std.posix.POLL.OUT != 0) {
                        self.handleConnectComplete(node_index);
                    }
                    if (fd.revents & std.posix.POLL.IN != 0) {
                        self.handleIncoming(node_index);
                    }
                    if (fd.revents & (std.posix.POLL.ERR | std.posix.POLL.HUP) != 0) {
                        self.mutex.lock();
                        self.closeConnectionByIndex(node_index);
                        self.mutex.unlock();
                    }
                }
            }
            offset = end;
        }
    }

    fn handleConnectComplete(self: *Explorer, node_index: usize) void {
        self.mutex.lock();
        const conn = self.connections.get(node_index) orelse {
            self.mutex.unlock();
            return;
        };
        conn.state = .handshaking;
        const socket = conn.socket;
        self.mutex.unlock();

        var err_buf: [@sizeOf(c_int)]u8 = undefined;
        std.posix.getsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.ERROR, &err_buf) catch {
            self.mutex.lock();
            self.closeConnectionByIndex(node_index);
            self.mutex.unlock();
            return;
        };
        const err = std.mem.bytesToValue(c_int, &err_buf);

        if (err != 0) {
            self.mutex.lock();
            self.closeConnectionByIndex(node_index);
            self.mutex.unlock();
            return;
        }

        self.sendVersionMessage(node_index) catch {
            self.mutex.lock();
            self.closeConnectionByIndex(node_index);
            self.mutex.unlock();
        };
    }

    fn sendVersionMessage(self: *Explorer, node_index: usize) !void {
        const conn = self.connections.get(node_index) orelse return error.NotFound;

        var nonce: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&nonce));

        const version_payload = yam.VersionPayload{
            .timestamp = std.time.timestamp(),
            .nonce = nonce,
            .relay = true,
        };

        var payload_buffer: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&payload_buffer);
        try version_payload.serialize(fbs.writer());
        const payload = fbs.getWritten();

        const checksum = yam.calculateChecksum(payload);
        const header = yam.MessageHeader.new("version", @intCast(payload.len), checksum);

        const h_written = try platform.socketWrite(conn.socket, std.mem.asBytes(&header));
        const p_written = try platform.socketWrite(conn.socket, payload);
        self.trackBytesOut(node_index, h_written + p_written);
    }

    fn handleIncoming(self: *Explorer, node_index: usize) void {
        self.mutex.lock();
        const conn = self.connections.get(node_index) orelse {
            self.mutex.unlock();
            return;
        };
        const socket = conn.socket;
        self.mutex.unlock();

        var header_buf: [24]u8 align(4) = undefined;
        const header_read = platform.socketRead(socket, &header_buf) catch {
            self.mutex.lock();
            self.closeConnectionByIndex(node_index);
            self.mutex.unlock();
            return;
        };

        if (header_read == 0) {
            self.mutex.lock();
            self.closeConnectionByIndex(node_index);
            self.mutex.unlock();
            return;
        }

        if (header_read < 24) return;

        const header = std.mem.bytesAsValue(yam.MessageHeader, &header_buf).*;
        if (header.magic != 0xD9B4BEF9) return;

        var payload: [65536]u8 = undefined;
        const payload_len = @min(header.length, payload.len);
        var payload_read: usize = 0;
        if (payload_len > 0) {
            payload_read = platform.socketRead(socket, payload[0..payload_len]) catch 0;
        }

        const cmd = std.mem.sliceTo(&header.command, 0);

        // Track bytes and message stats
        self.mutex.lock();
        if (self.node_metadata.getPtr(node_index)) |meta| {
            meta.bytes_in += header_read + payload_read;
            meta.msgs_in += 1;
        }
        // Track message type counts
        if (cmd.len > 0) {
            if (self.msg_type_counts.getPtr(cmd)) |count| {
                count.* += 1;
            } else {
                const key = self.allocator.dupe(u8, cmd) catch null;
                if (key) |k| {
                    self.msg_type_counts.put(k, 1) catch {
                        self.allocator.free(k);
                    };
                }
            }
        }
        const conn2 = self.connections.get(node_index);
        self.mutex.unlock();

        if (conn2 == null) return;

        if (conn2.?.state == .handshaking) {
            self.handleHandshakeMessage(node_index, conn2.?, cmd, payload[0..payload_read]);
            return;
        }

        if (std.mem.eql(u8, cmd, "ping")) {
            self.sendPong(socket, node_index, payload[0..payload_read]);
        } else if (std.mem.eql(u8, cmd, "pong")) {
            self.handlePongMessage(node_index, payload[0..payload_read]);
        } else if (std.mem.eql(u8, cmd, "addr")) {
            self.handleAddrMessage(node_index, conn2.?, payload[0..payload_read]);
        } else if (std.mem.eql(u8, cmd, "inv")) {
            self.handleInvMessage(node_index, conn2.?, payload[0..payload_read]);
        } else if (std.mem.eql(u8, cmd, "tx")) {
            self.handleTxMessage(payload[0..payload_read]);
        } else if (std.mem.eql(u8, cmd, "feefilter")) {
            self.handleFeefilterMessage(node_index, payload[0..payload_read]);
        }

        if (conn2.?.streaming and !std.mem.eql(u8, cmd, "addr") and !std.mem.eql(u8, cmd, "inv") and !std.mem.eql(u8, cmd, "tx")) {
            var buf: [256]u8 = undefined;
            var stdout_writer = self.stdout.writer(&buf);
            const stdout = &stdout_writer.interface;
            stdout.print("{s}[{d}]{s} {s}\n{s}>{s} ", .{
                Color.dim, node_index, Color.reset, cmd, Color.green, Color.reset,
            }) catch {};
            stdout.flush() catch {};
        }
    }

    fn handleHandshakeMessage(self: *Explorer, node_index: usize, conn: *Connection, cmd: []const u8, payload: []const u8) void {
        if (std.mem.eql(u8, cmd, "version")) {
            conn.handshake_state.received_version = true;

            // Parse version message to extract user_agent
            var fbs = std.io.fixedBufferStream(payload);
            if (yam.VersionPayload.deserialize(fbs.reader(), self.allocator)) |version_msg| {
                // Store user_agent in node_metadata
                const ua_copy = self.allocator.dupe(u8, version_msg.user_agent) catch null;
                self.allocator.free(version_msg.user_agent);

                if (ua_copy) |ua| {
                    const entry = self.node_metadata.getOrPut(node_index) catch null;
                    if (entry) |e| {
                        if (e.found_existing) {
                            if (e.value_ptr.user_agent) |old_ua| {
                                self.allocator.free(old_ua);
                            }
                        } else {
                            e.value_ptr.* = .{};
                        }
                        e.value_ptr.user_agent = ua;
                        e.value_ptr.services = version_msg.services;
                        if (version_msg.start_height > 0) {
                            e.value_ptr.start_height = @intCast(version_msg.start_height);
                            if (e.value_ptr.start_height > self.highest_peer_height) {
                                self.highest_peer_height = e.value_ptr.start_height;
                            }
                        }
                    } else {
                        self.allocator.free(ua);
                    }
                }
            } else |_| {}

            if (!conn.handshake_state.sent_verack) {
                conn.handshake_state.sent_verack = true;
                const checksum = yam.calculateChecksum(&.{});
                const header = yam.MessageHeader.new("verack", 0, checksum);
                const written = platform.socketWrite(conn.socket, std.mem.asBytes(&header)) catch 0;
                self.trackBytesOut(node_index, written);
            }
        } else if (std.mem.eql(u8, cmd, "verack")) {
            conn.handshake_state.received_verack = true;
        }

        if (conn.handshake_state.received_version and conn.handshake_state.received_verack) {
            conn.state = .connected;

            // Mark this node as having been connected at some point
            const entry = self.node_metadata.getOrPut(node_index) catch null;
            if (entry) |e| {
                if (!e.found_existing) {
                    e.value_ptr.* = .{};
                }
                e.value_ptr.ever_connected = true;
                e.value_ptr.connect_time = std.time.timestamp();
            }
        }
    }

    fn trackBytesOut(self: *Explorer, node_index: usize, bytes: usize) void {
        if (self.node_metadata.getPtr(node_index)) |meta| {
            meta.bytes_out += bytes;
            meta.msgs_out += 1;
        }
    }

    fn sendPong(self: *Explorer, socket: std.posix.socket_t, node_index: usize, ping_payload: []const u8) void {
        const checksum = yam.calculateChecksum(ping_payload);
        const header = yam.MessageHeader.new("pong", @intCast(ping_payload.len), checksum);
        const h_written = platform.socketWrite(socket, std.mem.asBytes(&header)) catch 0;
        var p_written: usize = 0;
        if (ping_payload.len > 0) {
            p_written = platform.socketWrite(socket, ping_payload) catch 0;
        }
        self.trackBytesOut(node_index, h_written + p_written);
    }

    fn handlePongMessage(self: *Explorer, node_index: usize, payload: []const u8) void {
        // Pong should contain the same nonce we sent in ping
        if (payload.len < 8) return;

        const received_nonce = std.mem.readInt(u64, payload[0..8], .little);
        const now = std.time.milliTimestamp();

        // Check if this matches our pending ping
        const metadata = self.node_metadata.getPtr(node_index) orelse return;

        if (metadata.pending_ping_nonce) |expected_nonce| {
            if (received_nonce == expected_nonce) {
                if (metadata.pending_ping_time) |send_time| {
                    const latency: u64 = @intCast(now - send_time);
                    metadata.latency_ms = latency;

                    // Only print if streaming is enabled for this connection
                    if (self.connections.get(node_index)) |conn| {
                        if (conn.streaming) {
                            var buf: [128]u8 = undefined;
                            var stdout_writer = self.stdout.writer(&buf);
                            const stdout = &stdout_writer.interface;
                            stdout.print("{s}[{d}]{s} pong: {s}{d}ms{s}\n{s}>{s} ", .{
                                Color.dim,   node_index,  Color.reset,
                                Color.green, latency,     Color.reset,
                                Color.green, Color.reset,
                            }) catch {};
                            stdout.flush() catch {};
                        }
                    }
                }
                // Clear pending ping
                metadata.pending_ping_nonce = null;
                metadata.pending_ping_time = null;
            }
        }
    }

    fn handleAddrMessage(self: *Explorer, node_index: usize, conn: *Connection, payload: []const u8) void {
        if (payload.len < 1) return;

        var fbs = std.io.fixedBufferStream(payload);
        const addr_msg = yam.AddrMessage.deserialize(fbs.reader(), self.allocator) catch return;
        defer addr_msg.deinit(self.allocator);

        const source_peer = self.known_nodes.items[node_index - 1];
        const source_key = self.formatNodeKey(source_peer) catch return;

        var added: usize = 0;
        var edges_added: usize = 0;
        for (addr_msg.addresses) |net_addr| {
            if (net_addr.toPeerInfo(.addr_message)) |node| {
                const key = self.formatNodeKey(node) catch continue;

                // Skip self-referential edges
                if (!std.mem.eql(u8, key, source_key)) {
                    self.edges.append(self.allocator, .{
                        .source = self.allocator.dupe(u8, source_key) catch continue,
                        .node = self.allocator.dupe(u8, key) catch continue,
                    }) catch continue;
                    edges_added += 1;
                }

                if (!self.seen_nodes.contains(key)) {
                    self.seen_nodes.put(key, {}) catch {
                        self.allocator.free(key);
                        continue;
                    };
                    self.known_nodes.append(self.allocator, node) catch {};
                    self.unconnected_nodes.put(self.known_nodes.items.len, {}) catch {};
                    added += 1;
                } else {
                    self.allocator.free(key);
                }
            }
        }

        self.allocator.free(source_key);

        if (conn.streaming) {
            var buf: [256]u8 = undefined;
            var stdout_writer = self.stdout.writer(&buf);
            const stdout = &stdout_writer.interface;
            stdout.print("{s}[{d}]{s} addr: {d} received, {s}{d}{s} new nodes\n{s}>{s} ", .{
                Color.dim,              node_index,  Color.reset,
                addr_msg.addresses.len, Color.green, added,
                Color.reset,            Color.green, Color.reset,
            }) catch {};
            stdout.flush() catch {};
        }
    }

    fn handleInvMessage(self: *Explorer, node_index: usize, conn: *Connection, payload: []const u8) void {
        if (payload.len < 1) return;

        var fbs = std.io.fixedBufferStream(payload);
        const inv_msg = yam.InvMessage.deserialize(fbs.reader(), self.allocator) catch return;
        defer inv_msg.deinit(self.allocator);

        var tx_count: usize = 0;
        var new_tx_count: usize = 0;

        // Collect TX inv vectors to request
        var tx_invs = std.ArrayList(yam.InvVector).empty;
        defer tx_invs.deinit(self.allocator);

        for (inv_msg.vectors) |inv| {
            // Track block announcements
            if (inv.type == .msg_block) {
                const block_hash_hex = inv.hashHex();
                self.last_block_hash = block_hash_hex;
                self.last_block_time = std.time.timestamp();
                self.blocks_seen += 1;
            }
            // Handle transactions (type 1)
            if (inv.type == .msg_tx or inv.type == .msg_witness_tx) {
                tx_count += 1;
                const txid_hex = inv.hashHex();

                // Check if we've seen this tx
                if (self.mempool.getPtr(&txid_hex)) |entry| {
                    // Already seen - add this node as announcer
                    entry.addAnnouncement(self.allocator, node_index);
                } else {
                    // New tx - create entry
                    const key = self.allocator.dupe(u8, &txid_hex) catch continue;
                    const new_entry = MempoolEntry.init(self.allocator, inv.hash, node_index);
                    self.mempool.put(key, new_entry) catch {
                        self.allocator.free(key);
                        continue;
                    };
                    new_tx_count += 1;

                    // Request the full transaction (with witness if peer supports it)
                    const use_witness = if (self.node_metadata.get(node_index)) |m| m.canServeWitnesses() else false;
                    tx_invs.append(self.allocator, .{
                        .type = if (use_witness) .msg_witness_tx else inv.type,
                        .hash = inv.hash,
                    }) catch {};
                }
            }
        }

        // Send getdata for new transactions
        if (tx_invs.items.len > 0) {
            self.sendGetdata(node_index, tx_invs.items);
        }

        if (tx_count > 0 and conn.streaming) {
            var buf: [256]u8 = undefined;
            var stdout_writer = self.stdout.writer(&buf);
            const stdout = &stdout_writer.interface;
            stdout.print("{s}[{d}]{s} inv: {d} tx ({s}{d}{s} new)\n{s}>{s} ", .{
                Color.dim,   node_index,  Color.reset,
                tx_count,    Color.green, new_tx_count,
                Color.reset, Color.green, Color.reset,
            }) catch {};
            stdout.flush() catch {};
        }
    }

    fn sendGetdata(self: *Explorer, node_index: usize, invs: []const yam.InvVector) void {
        const conn = self.connections.get(node_index) orelse return;

        // Build getdata message
        var payload_buf: [65536]u8 = undefined;
        var payload_fbs = std.io.fixedBufferStream(&payload_buf);
        const payload_writer = payload_fbs.writer();

        // Write count as varint
        yam.writeVarInt(payload_writer, invs.len) catch return;

        // Write each inv vector
        for (invs) |inv| {
            inv.serialize(payload_writer) catch return;
        }

        const payload = payload_fbs.getWritten();
        const checksum = yam.calculateChecksum(payload);
        const header = yam.MessageHeader.new("getdata", @intCast(payload.len), checksum);

        const h_written = platform.socketWrite(conn.socket, std.mem.asBytes(&header)) catch return;
        const p_written = platform.socketWrite(conn.socket, payload) catch return;
        self.trackBytesOut(node_index, h_written + p_written);
    }

    fn handleTxMessage(self: *Explorer, payload: []const u8) void {
        if (payload.len < 10) return; // Minimum tx size

        // Parse transaction to get txid
        var fbs = std.io.fixedBufferStream(payload);
        const tx = yam.Transaction.deserialize(fbs.reader(), self.allocator) catch return;
        defer tx.deinit(self.allocator);

        const txid_hex = tx.txidHex(self.allocator) catch return;

        // Update mempool entry with tx data
        if (self.mempool.getPtr(&txid_hex)) |entry| {
            if (entry.tx_data == null) {
                entry.tx_data = self.allocator.dupe(u8, payload) catch null;
            }
        }
    }

    fn handleFeefilterMessage(self: *Explorer, node_index: usize, payload: []const u8) void {
        if (payload.len < 8) return;
        const fee_rate = std.mem.readInt(u64, payload[0..8], .little);
        if (self.node_metadata.getPtr(node_index)) |meta| {
            meta.fee_filter = fee_rate;
        }
    }
};
