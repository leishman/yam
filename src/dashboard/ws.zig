const std = @import("std");
const net = std.net;

pub const WS_MAGIC_KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub fn secAccept(key: []const u8) [28]u8 {
    var h = std.crypto.hash.Sha1.init(.{});
    var buf: [20]u8 = undefined;
    h.update(key);
    h.update(WS_MAGIC_KEY);
    h.final(&buf);
    var ret: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&ret, &buf);
    return ret;
}

pub const WsFrame = struct {
    pub const Opcode = enum(u4) {
        continuation = 0,
        text = 1,
        binary = 2,
        close = 8,
        ping = 9,
        pong = 0xa,

        pub fn decode(val: u4) !Opcode {
            return switch (val) {
                0 => .continuation,
                1 => .text,
                2 => .binary,
                8 => .close,
                9 => .ping,
                0xa => .pong,
                else => return error.ReservedOpcode,
            };
        }

        pub fn isControl(self: Opcode) bool {
            return self == .close or self == .ping or self == .pong;
        }
    };

    fin: u1,
    mask: u1,
    opcode: Opcode,
    payload: []const u8,

    pub fn parse(data: []u8) !struct { WsFrame, usize } {
        if (data.len < 2) return error.SplitBuffer;

        const fin: u1 = if (data[0] & 0b1000_0000 != 0) 1 else 0;
        const opcode = try Opcode.decode(@intCast(data[0] & 0b0000_1111));
        const mask_bit: u1 = if (data[1] & 0b1000_0000 != 0) 1 else 0;

        const payload_len, const payload_len_bytes = try readPayloadLen(data[1..]);

        if (opcode.isControl()) {
            if (payload_len > 125) return error.TooBigPayload;
            if (fin == 0) return error.FragmentedControl;
        }

        const mask_start = payload_len_bytes + 1;
        const mask_end: usize = mask_start + @as(usize, if (mask_bit == 1) 4 else 0);
        const payload_start = mask_end;
        const payload_end = payload_start + payload_len;

        if (data.len < payload_end) return error.SplitBuffer;

        const masking_key = data[mask_start..mask_end];
        const payload = data[payload_start..payload_end];
        if (mask_bit == 1) {
            maskUnmask(masking_key, payload);
        }

        return .{
            .{ .fin = fin, .mask = mask_bit, .opcode = opcode, .payload = payload },
            payload_end,
        };
    }

    fn readPayloadLen(data: []const u8) !struct { usize, usize } {
        if (data.len < 1) return error.SplitBuffer;
        const len: usize = @intCast(data[0] & 0b0111_1111);
        switch (len) {
            126 => {
                if (data.len < 3) return error.SplitBuffer;
                return .{ @intCast(std.mem.readInt(u16, data[1..3], .big)), 3 };
            },
            127 => {
                if (data.len < 9) return error.SplitBuffer;
                const len64 = std.mem.readInt(u64, data[1..9], .big);
                if (len64 > 16 * 1024 * 1024) return error.TooBigPayload;
                if (len64 > std.math.maxInt(usize)) return error.TooBigPayload;
                return .{ @intCast(len64), 9 };
            },
            else => return .{ len, 1 },
        }
    }

    fn maskUnmask(mask_bytes: []const u8, buf: []u8) void {
        for (buf, 0..) |c, i|
            buf[i] = c ^ mask_bytes[i % 4];
    }

    pub fn encode(self: WsFrame, buf: []u8) usize {
        buf[0] = (@as(u8, self.fin) << 7) + @intFromEnum(self.opcode);

        var offset: usize = 2;
        if (self.payload.len < 126) {
            buf[1] = @intCast(self.payload.len);
        } else if (self.payload.len < 65536) {
            buf[1] = 126;
            std.mem.writeInt(u16, buf[2..4], @intCast(self.payload.len), .big);
            offset = 4;
        } else {
            buf[1] = 127;
            std.mem.writeInt(u64, buf[2..10], self.payload.len, .big);
            offset = 10;
        }

        @memcpy(buf[offset .. offset + self.payload.len], self.payload);
        return offset + self.payload.len;
    }
};

pub fn writeText(stream: net.Stream, data: []const u8) !void {
    var header: [10]u8 = undefined;
    header[0] = 0x81; // FIN=1, opcode=text

    var header_len: usize = 2;
    if (data.len < 126) {
        header[1] = @intCast(data.len);
    } else if (data.len < 65536) {
        header[1] = 126;
        std.mem.writeInt(u16, header[2..4], @intCast(data.len), .big);
        header_len = 4;
    } else {
        header[1] = 127;
        std.mem.writeInt(u64, header[2..10], data.len, .big);
        header_len = 10;
    }

    var iovecs = [_]std.posix.iovec_const{
        .{ .base = &header, .len = header_len },
        .{ .base = data.ptr, .len = data.len },
    };
    _ = try stream.writev(&iovecs);
}
