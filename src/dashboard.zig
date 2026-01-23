const std = @import("std");
const net = std.net;

const yam = @import("root.zig");
const scout = @import("scout.zig");
const Explorer = @import("explorer.zig").Explorer;

const ws = @import("dashboard/ws.zig");
const http = @import("dashboard/http.zig");
const state_mod = @import("dashboard/state.zig");
const api = @import("dashboard/api.zig");
const json = @import("dashboard/json.zig");

pub const DashboardConfig = state_mod.DashboardConfig;
pub const DashboardState = state_mod.DashboardState;
pub const BlockRecord = state_mod.BlockRecord;
pub const PeerRecord = state_mod.PeerRecord;
pub const BanRecord = state_mod.BanRecord;
pub const BanEntry = state_mod.BanEntry;
pub const PersistentState = state_mod.PersistentState;

const index_html = @embedFile("dashboard.html");

pub const Dashboard = struct {
    allocator: std.mem.Allocator,
    state: *DashboardState,
    explorer: *Explorer,
    listener: ?net.Server,
    update_thread: ?std.Thread,
    should_stop: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, config: DashboardConfig) !*Dashboard {
        const explorer = try Explorer.init(allocator);
        errdefer explorer.deinit();

        const state = try DashboardState.init(allocator, explorer, config);
        errdefer state.deinit();

        const self = try allocator.create(Dashboard);
        self.* = .{
            .allocator = allocator,
            .state = state,
            .explorer = explorer,
            .listener = null,
            .update_thread = null,
            .should_stop = std.atomic.Value(bool).init(false),
        };
        return self;
    }

    pub fn deinit(self: *Dashboard) void {
        self.should_stop.store(true, .release);
        self.explorer.should_stop.store(true, .release);

        if (self.listener) |*l| {
            l.deinit();
            self.listener = null;
        }

        if (self.update_thread) |thread| thread.join();

        self.state.deinit();
        self.explorer.deinit();
        self.allocator.destroy(self);
    }

    pub fn run(self: *Dashboard) !void {
        std.debug.print("Dashboard starting on http://{s}:{d}\n", .{ self.state.config.bind_address, self.state.config.port });
        if (self.state.config.state_file) |path| std.debug.print("State file: {s}\n", .{path});
        std.debug.print("Press Ctrl+C to stop\n\n", .{});

        try self.discoverAndConnect();
        self.update_thread = try std.Thread.spawn(.{}, updateBroadcaster, .{self});

        if (self.state.config.state_file != null) {
            self.state.save_thread = try std.Thread.spawn(.{}, stateSaver, .{self.state});
        }

        const address = try net.Address.parseIp(self.state.config.bind_address, self.state.config.port);
        self.listener = try address.listen(.{ .reuse_address = true });

        while (!self.should_stop.load(.acquire)) {
            const conn = self.listener.?.accept() catch |err| {
                if (err == error.SocketNotListening) break;
                continue;
            };

            const thread = std.Thread.spawn(.{}, handleConnection, .{ self, conn }) catch {
                conn.stream.close();
                continue;
            };
            thread.detach();
        }
    }

    fn handleConnection(self: *Dashboard, conn: net.Server.Connection) void {
        defer conn.stream.close();

        var buf: [8192]u8 = undefined;
        const n = conn.stream.read(&buf) catch return;
        if (n == 0) return;

        const req_data = buf[0..n];
        const method, const path = parseRequest(req_data) orelse return;

        if (std.ascii.indexOfIgnoreCase(req_data, "upgrade: websocket") != null) {
            self.handleWebsocket(conn, req_data) catch {};
            return;
        }

        if (std.mem.eql(u8, method, "GET")) {
            self.handleGet(conn, path) catch {};
        } else if (std.mem.eql(u8, method, "POST")) {
            if (self.state.config.read_only) {
                http.sendResponse(conn.stream, 403, "application/json", "{\"error\":\"read-only mode\"}") catch {};
                return;
            }
            const body_start = std.mem.indexOf(u8, req_data, "\r\n\r\n") orelse return;
            self.handlePost(conn, path, req_data[body_start + 4 .. n]) catch {};
        } else {
            http.sendResponse(conn.stream, 405, "text/plain", "Method Not Allowed") catch {};
        }
    }

    fn parseRequest(data: []const u8) ?struct { []const u8, []const u8 } {
        const method_end = std.mem.indexOf(u8, data, " ") orelse return null;
        const path_start = method_end + 1;
        const path_end = std.mem.indexOfPos(u8, data, path_start, " ") orelse return null;
        return .{ data[0..method_end], data[path_start..path_end] };
    }

    fn handleGet(self: *Dashboard, conn: net.Server.Connection, path: []const u8) !void {
        if (std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, "/index.html")) {
            try self.serveIndex(conn.stream);
        } else if (std.mem.eql(u8, path, "/api/v1/status")) {
            try api.handleStatus(self.allocator, self.state, conn.stream);
        } else if (std.mem.eql(u8, path, "/api/v1/nodes")) {
            try api.handleNodes(self.allocator, self.state, conn.stream);
        } else if (std.mem.eql(u8, path, "/api/v1/mempool")) {
            try api.handleMempool(self.allocator, self.state, conn.stream);
        } else if (std.mem.eql(u8, path, "/api/v1/blocks")) {
            try api.handleBlocks(self.allocator, self.state, conn.stream);
        } else if (std.mem.eql(u8, path, "/api/peers/banned")) {
            try api.handleBannedList(self.allocator, self.state, conn.stream);
        } else {
            try http.sendResponse(conn.stream, 404, "text/plain", "Not Found");
        }
    }

    fn handlePost(self: *Dashboard, conn: net.Server.Connection, path: []const u8, body: []const u8) !void {
        if (std.mem.eql(u8, path, "/api/peer/disconnect")) {
            try api.handleDisconnect(self.allocator, self.state, conn.stream, body);
        } else if (std.mem.eql(u8, path, "/api/peer/ban")) {
            try api.handleBan(self.allocator, self.state, conn.stream, body);
        } else if (std.mem.eql(u8, path, "/api/peer/unban")) {
            try api.handleUnban(self.allocator, self.state, conn.stream, body);
        } else if (std.mem.eql(u8, path, "/api/state/clear")) {
            try api.handleClearState(self.state, conn.stream);
        } else {
            try http.sendJson(conn.stream, 404, "{\"error\":\"not found\"}");
        }
    }

    fn serveIndex(self: *Dashboard, stream: net.Stream) !void {
        const ctx = self.state;
        const config_script = std.fmt.allocPrint(ctx.allocator,
            \\<script>window.DASHBOARD_CONFIG={{readOnly:{},disableTopology:{},disableMap:{},updateInterval:{d},hasStateFile:{}}};</script>
        , .{
            ctx.config.read_only,
            ctx.config.disable_topology,
            ctx.config.disable_map,
            ctx.config.update_interval_ms,
            ctx.config.state_file != null,
        }) catch return http.sendResponse(stream, 200, "text/html", index_html);
        defer ctx.allocator.free(config_script);

        const head_pos = std.mem.indexOf(u8, index_html, "<head>") orelse
            return http.sendResponse(stream, 200, "text/html", index_html);

        const insert_pos = head_pos + 6;
        const html_content = std.fmt.allocPrint(ctx.allocator, "{s}{s}{s}", .{
            index_html[0..insert_pos], config_script, index_html[insert_pos..],
        }) catch return http.sendResponse(stream, 200, "text/html", index_html);
        defer ctx.allocator.free(html_content);

        try http.sendResponse(stream, 200, "text/html", html_content);
    }

    fn handleWebsocket(self: *Dashboard, conn: net.Server.Connection, req_data: []const u8) !void {
        const key = http.extractHeader(req_data, "Sec-WebSocket-Key:") orelse return;
        const accept = ws.secAccept(std.mem.trim(u8, key, " \t\r\n"));

        if (!self.state.registerClient(conn.stream)) {
            try http.sendResponse(conn.stream, 503, "text/plain", "Too many WebSocket clients");
            return;
        }
        defer self.state.unregisterClient(conn.stream);

        var response_buf: [256]u8 = undefined;
        const response = try std.fmt.bufPrint(&response_buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&accept});
        try conn.stream.writeAll(response);

        if (json.buildStatusJson(self.state)) |status_json| {
            defer self.state.allocator.free(status_json);
            ws.writeText(conn.stream, status_json) catch {};
        } else |_| {}

        // WebSocket message loop
        var frame_buf: [65536]u8 = undefined;
        var read_pos: usize = 0;

        while (!self.should_stop.load(.acquire)) {
            const bytes_read = conn.stream.read(frame_buf[read_pos..]) catch break;
            if (bytes_read == 0) break;
            read_pos += bytes_read;

            while (read_pos > 0) {
                const frame, const frame_len = ws.WsFrame.parse(frame_buf[0..read_pos]) catch |err| {
                    if (err == error.SplitBuffer) break;
                    return;
                };

                switch (frame.opcode) {
                    .close => {
                        var close_buf: [4]u8 = undefined;
                        const close_len = (ws.WsFrame{ .fin = 1, .mask = 0, .opcode = .close, .payload = &.{} }).encode(&close_buf);
                        conn.stream.writeAll(close_buf[0..close_len]) catch {};
                        return;
                    },
                    .ping => {
                        var pong_buf: [256]u8 = undefined;
                        const pong_len = (ws.WsFrame{ .fin = 1, .mask = 0, .opcode = .pong, .payload = frame.payload }).encode(&pong_buf);
                        conn.stream.writeAll(pong_buf[0..pong_len]) catch {};
                    },
                    .text => self.sendStatusUpdate(conn.stream),
                    else => {},
                }

                if (frame_len < read_pos) std.mem.copyForwards(u8, &frame_buf, frame_buf[frame_len..read_pos]);
                read_pos -= frame_len;
            }
        }
    }

    fn discoverAndConnect(self: *Dashboard) !void {
        std.debug.print("Discovering peers via DNS seeds...\n", .{});
        var node_list = try scout.discoverPeers(self.allocator);
        defer node_list.deinit(self.allocator);

        std.debug.print("Found {d} peers from DNS seeds\n", .{node_list.items.len});

        for (node_list.items) |node| {
            const key = try self.formatNodeKey(node);
            if (!self.explorer.seen_nodes.contains(key)) {
                try self.explorer.seen_nodes.put(key, {});
                try self.explorer.known_nodes.append(self.allocator, node);
                const idx = self.explorer.known_nodes.items.len;
                try self.explorer.unconnected_nodes.put(idx, {});
            } else {
                self.allocator.free(key);
            }
        }

        std.debug.print("Starting network manager thread...\n", .{});
        self.explorer.manager_thread = try std.Thread.spawn(.{}, Explorer.managerThread, .{self.explorer});

        const connect_count = @min(20, self.explorer.known_nodes.items.len);
        std.debug.print("Connecting to {d} peers...\n", .{connect_count});

        for (1..connect_count + 1) |idx| {
            self.explorer.mutex.lock();
            self.explorer.pending_commands.append(self.allocator, .{ .connect = idx }) catch {};
            _ = self.explorer.unconnected_nodes.remove(idx);
            self.explorer.mutex.unlock();
        }
    }

    fn formatNodeKey(self: *Dashboard, node: yam.PeerInfo) ![]u8 {
        const addr_str = node.format();
        return try self.allocator.dupe(u8, std.mem.sliceTo(&addr_str, ' '));
    }

    fn sendStatusUpdate(self: *Dashboard, stream: net.Stream) void {
        const status_json = json.buildStatusJson(self.state) catch return;
        defer self.state.allocator.free(status_json);
        ws.writeText(stream, status_json) catch {};
    }
};

fn stateSaver(state: *DashboardState) void {
    while (!state.explorer.should_stop.load(.acquire)) {
        std.Thread.sleep(60_000_000_000);
        if (state.explorer.should_stop.load(.acquire)) break;
        if (state.config.state_file) |path| state.saveState(path);
    }
}

fn updateBroadcaster(dashboard: *Dashboard) void {
    const state = dashboard.state;
    while (!dashboard.should_stop.load(.acquire)) {
        std.Thread.sleep(1_000_000_000);

        state.explorer.mutex.lock();
        const node_count = state.explorer.known_nodes.items.len;
        const mempool_count = state.explorer.mempool.count();
        state.explorer.mutex.unlock();

        const now = std.time.timestamp();
        const should_broadcast = node_count != state.last_node_count or
            mempool_count != state.last_mempool_count or
            now - state.last_broadcast_time >= 5;

        if (should_broadcast) {
            state.last_node_count = node_count;
            state.last_mempool_count = mempool_count;
            state.last_broadcast_time = now;

            if (json.buildStatusJson(state)) |status_json| {
                state.broadcastJson(status_json);
                state.allocator.free(status_json);
            } else |_| {}
        }
    }
}
