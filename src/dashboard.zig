const std = @import("std");
const httpz = @import("httpz");
const websocket = httpz.websocket;
const yam = @import("root.zig");
const scout = @import("scout.zig");
const Explorer = @import("explorer.zig").Explorer;

const index_html = @embedFile("dashboard.html");

pub const DashboardState = struct {
    allocator: std.mem.Allocator,
    explorer: *Explorer,
    ws_clients: std.ArrayList(*WsHandler),
    ws_mutex: std.Thread.Mutex,
    last_node_count: usize,
    last_mempool_count: usize,
    last_broadcast_time: i64,

    pub const WebsocketHandler = WsHandler;

    pub fn init(allocator: std.mem.Allocator, explorer: *Explorer) !*DashboardState {
        const self = try allocator.create(DashboardState);
        self.* = .{
            .allocator = allocator,
            .explorer = explorer,
            .ws_clients = std.ArrayList(*WsHandler).empty,
            .ws_mutex = .{},
            .last_node_count = 0,
            .last_mempool_count = 0,
            .last_broadcast_time = 0,
        };
        return self;
    }

    pub fn deinit(self: *DashboardState) void {
        self.ws_clients.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn registerClient(self: *DashboardState, client: *WsHandler) void {
        self.ws_mutex.lock();
        defer self.ws_mutex.unlock();
        self.ws_clients.append(self.allocator, client) catch {};
    }

    pub fn unregisterClient(self: *DashboardState, client: *WsHandler) void {
        self.ws_mutex.lock();
        defer self.ws_mutex.unlock();
        for (self.ws_clients.items, 0..) |c, i| {
            if (c == client) {
                _ = self.ws_clients.swapRemove(i);
                break;
            }
        }
    }

    pub fn broadcastJson(self: *DashboardState, json: []const u8) void {
        self.ws_mutex.lock();
        defer self.ws_mutex.unlock();
        for (self.ws_clients.items) |client| {
            client.conn.writeText(json) catch {};
        }
    }
};

pub const WsHandler = struct {
    conn: *websocket.Conn,
    state: *DashboardState,

    pub fn init(conn: *websocket.Conn, ctx: *DashboardState) !WsHandler {
        return .{ .conn = conn, .state = ctx };
    }

    pub fn afterInit(self: *WsHandler) !void {
        self.state.registerClient(self);
        if (buildStatusJson(self.state)) |json| {
            defer self.state.allocator.free(json);
            try self.conn.writeText(json);
        } else |_| {}
    }

    pub fn clientMessage(self: *WsHandler, _: []const u8) !void {
        if (buildStatusJson(self.state)) |json| {
            defer self.state.allocator.free(json);
            try self.conn.writeText(json);
        } else |_| {}
    }

    pub fn close(self: *WsHandler) void {
        self.state.unregisterClient(self);
    }
};

pub const Dashboard = struct {
    allocator: std.mem.Allocator,
    server: httpz.Server(*DashboardState),
    state: *DashboardState,
    explorer: *Explorer,
    update_thread: ?std.Thread,

    pub fn init(allocator: std.mem.Allocator) !*Dashboard {
        const explorer = try Explorer.init(allocator);
        errdefer explorer.deinit();

        const state = try DashboardState.init(allocator, explorer);
        errdefer state.deinit();

        var server = try httpz.Server(*DashboardState).init(allocator, .{
            .port = 8080,
        }, state);
        errdefer server.deinit();

        var router = try server.router(.{});
        router.get("/", serveIndex, .{});
        router.get("/ws", serveWebsocket, .{});

        const self = try allocator.create(Dashboard);
        self.* = .{
            .allocator = allocator,
            .server = server,
            .state = state,
            .explorer = explorer,
            .update_thread = null,
        };
        return self;
    }

    pub fn deinit(self: *Dashboard) void {
        self.explorer.should_stop.store(true, .release);
        if (self.update_thread) |thread| {
            thread.join();
        }
        self.server.deinit();
        self.state.deinit();
        self.explorer.deinit();
        self.allocator.destroy(self);
    }

    pub fn run(self: *Dashboard) !void {
        std.debug.print("Dashboard starting on http://localhost:8080\n", .{});
        std.debug.print("Press Ctrl+C to stop\n\n", .{});

        try self.discoverAndConnect();
        self.update_thread = try std.Thread.spawn(.{}, updateBroadcaster, .{self.state});
        try self.server.listen();
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
};

fn serveIndex(_: *DashboardState, _: *httpz.Request, res: *httpz.Response) !void {
    res.content_type = httpz.ContentType.HTML;
    res.body = index_html;
}

fn serveWebsocket(ctx: *DashboardState, req: *httpz.Request, res: *httpz.Response) !void {
    _ = httpz.upgradeWebsocket(WsHandler, req, res, ctx) catch {
        res.status = 400;
        res.body = "invalid websocket handshake";
    };
}

fn updateBroadcaster(state: *DashboardState) void {
    while (!state.explorer.should_stop.load(.acquire)) {
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

            if (buildStatusJson(state)) |json| {
                state.broadcastJson(json);
                state.allocator.free(json);
            } else |_| {}
        }
    }
}

fn buildStatusJson(state: *DashboardState) ![]u8 {
    const explorer = state.explorer;

    explorer.mutex.lock();
    defer explorer.mutex.unlock();

    var json = std.ArrayList(u8).empty;
    errdefer json.deinit(state.allocator);
    const writer = json.writer(state.allocator);

    try writer.writeAll("{");

    var connected: usize = 0;
    var connecting: usize = 0;
    var failed: usize = 0;

    var conn_iter = explorer.connections.valueIterator();
    while (conn_iter.next()) |conn| {
        switch (conn.*.state) {
            .connected => connected += 1,
            .connecting, .handshaking => connecting += 1,
            .failed => failed += 1,
        }
    }

    try writer.print("\"nodes\":{{\"total\":{d},\"connected\":{d},\"connecting\":{d},\"failed\":{d}}},", .{
        explorer.known_nodes.items.len,
        connected,
        connecting,
        failed,
    });

    try writer.print("\"mempool\":{{\"count\":{d}}},", .{explorer.mempool.count()});

    try writer.writeAll("\"node_list\":[");
    var first = true;
    var idx: usize = 0;
    for (explorer.known_nodes.items) |node| {
        idx += 1;
        if (explorer.connections.get(idx)) |conn| {
            if (!first) try writer.writeByte(',');
            first = false;

            const addr_fmt = node.format();
            const addr = std.mem.sliceTo(&addr_fmt, ' ');
            const metadata = explorer.node_metadata.get(idx);
            const latency = if (metadata) |m| m.latency_ms else null;
            const state_str = switch (conn.state) {
                .connecting => "connecting",
                .handshaking => "handshaking",
                .connected => "connected",
                .failed => "failed",
            };

            try writer.print("{{\"index\":{d},\"addr\":\"{s}\",\"state\":\"{s}\"", .{
                idx,
                addr,
                state_str,
            });
            if (latency) |lat| {
                try writer.print(",\"latency\":{d}", .{lat});
            }
            try writer.writeAll("}");
        }
    }
    try writer.writeAll("],");

    try writer.writeAll("\"recent_txs\":[");
    first = true;
    var mp_iter = explorer.mempool.iterator();
    var tx_count: usize = 0;
    while (mp_iter.next()) |entry| {
        if (tx_count >= 50) break;
        tx_count += 1;

        if (!first) try writer.writeByte(',');
        first = false;

        const mp_entry = entry.value_ptr;
        try writer.print("{{\"txid\":\"{s}\",\"sources\":{d},\"first_seen\":{d}}}", .{
            entry.key_ptr.*,
            mp_entry.announcements.items.len,
            mp_entry.first_seen,
        });
    }
    try writer.writeAll("],");

    try writer.print("\"timestamp\":{d}", .{std.time.timestamp()});
    try writer.writeAll("}");

    return json.toOwnedSlice(state.allocator);
}
