const std = @import("std");
const net = std.net;

pub fn extractHeader(data: []const u8, header_name: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < data.len) {
        const line_end = std.mem.indexOfPos(u8, data, pos, "\r\n") orelse data.len;
        const line = data[pos..line_end];
        if (line.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(line, header_name)) {
            return line[header_name.len..];
        }
        pos = line_end + 2;
    }
    return null;
}

fn statusText(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        else => "Unknown",
    };
}

pub fn sendResponse(stream: net.Stream, status: u16, content_type: []const u8, body: []const u8) !void {
    var buf: [1024]u8 = undefined;
    const header = try std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\n" ++
        "Content-Type: {s}\r\n" ++
        "Content-Length: {d}\r\n" ++
        "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://d3js.org https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data: https://*.basemaps.cartocdn.com; connect-src 'self' ws: wss: https://ipinfo.io https://ip-api.com\r\n" ++
        "X-Frame-Options: DENY\r\n" ++
        "X-Content-Type-Options: nosniff\r\n" ++
        "Connection: close\r\n\r\n", .{ status, statusText(status), content_type, body.len });
    try stream.writeAll(header);
    try stream.writeAll(body);
}

pub fn sendJson(stream: net.Stream, status: u16, body: []const u8) !void {
    try sendResponse(stream, status, "application/json", body);
}
