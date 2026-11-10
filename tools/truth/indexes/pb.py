"""Minimal protobuf wire codec and a gRPC-web (binary, HTTP/1.1) client. Stdlib only."""
import http.client, struct, time, base64

def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def field_varint(num, v):
    return varint(num << 3) + varint(v)

def field_bytes(num, b):
    if isinstance(b, str):
        b = b.encode()
    return varint((num << 3) | 2) + varint(len(b)) + b

def mask(paths):
    return b"".join(field_bytes(1, p) for p in paths)

def read_varint(buf, i):
    n = s = 0
    while True:
        b = buf[i]; i += 1
        n |= (b & 0x7F) << s; s += 7
        if b < 0x80:
            return n, i

def fields(buf):
    """Yields (number, wire, value) with value int for varint/fixed, bytes for length-delimited."""
    i = 0
    while i < len(buf):
        key, i = read_varint(buf, i)
        num, wt = key >> 3, key & 7
        if wt == 0:
            v, i = read_varint(buf, i)
        elif wt == 2:
            ln, i = read_varint(buf, i)
            v = bytes(buf[i:i + ln]); i += ln
        elif wt == 1:
            v = struct.unpack_from("<Q", buf, i)[0]; i += 8
        elif wt == 5:
            v = struct.unpack_from("<I", buf, i)[0]; i += 4
        else:
            raise ValueError("wire type %d" % wt)
        yield num, wt, v

def get(buf, num):
    return [v for n, _, v in fields(buf) if n == num]

def one(buf, num, default=None):
    r = get(buf, num)
    return r[-1] if r else default

class Client:
    def __init__(self, host="127.0.0.1", port=19004, rate=15.0):
        self.host, self.port, self.min_gap = host, port, 1.0 / rate
        self.conn = None
        self.last = 0.0
        self.calls = 0

    def call(self, service, method, body):
        """Returns (grpc_status:int, message:str, response_bytes:bytes|None, details_bin:bytes)."""
        gap = time.monotonic() - self.last
        if gap < self.min_gap:
            time.sleep(self.min_gap - gap)
        self.last = time.monotonic()
        self.calls += 1
        frame = b"\x00" + struct.pack(">I", len(body)) + body
        for attempt in range(3):
            try:
                if self.conn is None:
                    self.conn = http.client.HTTPConnection(self.host, self.port, timeout=60)
                self.conn.request("POST", "/sui.rpc.v2.%s/%s" % (service, method), frame, {
                    "content-type": "application/grpc-web+proto", "x-grpc-web": "1"})
                r = self.conn.getresponse()
                data = r.read()
                hdrs = {k.lower(): v for k, v in r.getheaders()}
                break
            except (http.client.HTTPException, OSError):
                self.conn = None
                if attempt == 2:
                    raise
                time.sleep(1)
        msg, trailers = None, {}
        i = 0
        while i + 5 <= len(data):
            flag = data[i]; ln = struct.unpack(">I", data[i + 1:i + 5])[0]
            payload = data[i + 5:i + 5 + ln]; i += 5 + ln
            if flag & 0x80:
                for line in payload.decode().split("\r\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        trailers[k.strip().lower()] = v.strip()
            else:
                msg = payload
        st = trailers.get("grpc-status", hdrs.get("grpc-status", "0"))
        m = trailers.get("grpc-message", hdrs.get("grpc-message", ""))
        det = trailers.get("grpc-status-details-bin", hdrs.get("grpc-status-details-bin", ""))
        det = base64.b64decode(det + "=" * (-len(det) % 4)) if det else b""
        from urllib.parse import unquote
        return int(st), unquote(m), msg, det
