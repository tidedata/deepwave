"""Raw wire clients for sui-node captures: gRPC over h2c / TLS+h2 (h2 library), grpc-web over
HTTP/1.1, and plain HTTP (admin). Each call returns the record dict of cases.jsonl."""
import base64, json, socket, ssl, time

import h2.config, h2.connection, h2.events, h2.settings

DROP_HEADERS = {"date"}
B64 = lambda b: base64.b64encode(b).decode()


def frame(msg, flag=0):
    return bytes([flag]) + len(msg).to_bytes(4, "big") + msg


def unframe(buf):
    """Split a gRPC body into (flag, payload) frames; trailing partial bytes are returned as rest."""
    out, i = [], 0
    while i + 5 <= len(buf):
        n = int.from_bytes(buf[i + 1:i + 5], "big")
        if i + 5 + n > len(buf):
            break
        out.append((buf[i], bytes(buf[i + 5:i + 5 + n])))
        i += 5 + n
    return out, bytes(buf[i:])


def _connect(host, port, tls, alpn=("h2",), timeout=10):
    s = socket.create_connection((host, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if alpn:
            ctx.set_alpn_protocols(list(alpn))
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


def grpc(host, port, path, msgs, headers=None, tls=False, max_msgs=None, read_s=10.0, authority=None, alpn=("h2",)):
    """One gRPC call. Stops after max_msgs response messages (then cancels the stream) or on
    stream end or after read_s seconds. Returns the cases.jsonl 'resp' dict plus timing."""
    t0 = time.time()
    s = _connect(host, port, tls, alpn=alpn)
    conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding=None))
    conn.initiate_connection()
    conn.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 16 * 1024 * 1024})
    conn.increment_flow_control_window(64 * 1024 * 1024)
    s.sendall(conn.data_to_send())
    sid = conn.get_next_available_stream_id()
    hdrs = [(":method", "POST"), (":scheme", "https" if tls else "http"), (":path", path),
            (":authority", authority or f"{host}:{port}"), ("content-type", "application/grpc"), ("te", "trailers")]
    for k, v in (headers or {}).items():
        hdrs.append((k, v))
    body = b"".join(frame(m) for m in msgs)
    conn.send_headers(sid, hdrs, end_stream=not body)
    if body:
        conn.send_data(sid, body, end_stream=True)
    s.sendall(conn.data_to_send())
    resp = {"http_status": None, "headers": {}, "trailers_only": False, "messages_b64": [], "trailers": {}}
    buf = bytearray()
    first_msg_t = None
    ended = False
    got_headers = False
    s.settimeout(0.5)
    while time.time() - t0 < read_s and not ended:
        try:
            data = s.recv(1 << 20)
        except socket.timeout:
            continue
        except (ssl.SSLError, ConnectionResetError) as e:
            resp["conn_error"] = repr(e)
            break
        if not data:
            resp["conn_closed"] = True
            break
        for ev in conn.receive_data(data):
            if isinstance(ev, h2.events.ResponseReceived):
                hd = {k.decode().lower(): v.decode() for k, v in ev.headers}
                resp["http_status"] = int(hd.pop(":status"))
                if "grpc-status" in hd:
                    resp["trailers_only"] = True
                    for k in ("grpc-status", "grpc-message", "grpc-status-details-bin"):
                        if k in hd:
                            resp["trailers"][k] = hd.pop(k)
                    if ev.stream_ended:
                        ended = True
                resp["headers"] = {k: v for k, v in hd.items() if k not in DROP_HEADERS}
                got_headers = True
            elif isinstance(ev, h2.events.DataReceived):
                conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                buf += ev.data
                frames, rest = unframe(buf)
                buf = bytearray(rest)
                for flag, p in frames:
                    if first_msg_t is None:
                        first_msg_t = time.time() - t0
                    if flag & 1:
                        resp.setdefault("compressed_flags", []).append(len(resp["messages_b64"]))
                    resp["messages_b64"].append(B64(p))
            elif isinstance(ev, h2.events.TrailersReceived):
                for k, v in ev.headers:
                    resp["trailers"][k.decode().lower()] = v.decode()
                ended = True
            elif isinstance(ev, h2.events.StreamEnded):
                ended = True
            elif isinstance(ev, h2.events.StreamReset):
                resp["rst_stream"] = int(ev.error_code)
                ended = True
            elif isinstance(ev, h2.events.ConnectionTerminated):
                resp["goaway"] = int(ev.error_code)
                ended = True
        out = conn.data_to_send()
        if out:
            s.sendall(out)
        if max_msgs is not None and len(resp["messages_b64"]) >= max_msgs:
            resp["client_cancelled_after"] = max_msgs
            try:
                conn.reset_stream(sid, 8)
                s.sendall(conn.data_to_send())
            except Exception:
                pass
            break
    if not ended and "client_cancelled_after" not in resp:
        resp["client_timeout_s"] = read_s
    try:
        s.close()
    except Exception:
        pass
    timing = {"elapsed_s": round(time.time() - t0, 3), "first_msg_s": first_msg_t and round(first_msg_t, 3)}
    return resp, timing


def http1(host, port, method, path, body=b"", headers=None, tls=False, read_s=10.0, alpn=None):
    """Raw HTTP/1.1 request. Returns (status, headers dict, body bytes, raw bytes)."""
    s = _connect(host, port, tls, alpn=alpn)
    lines = [f"{method} {path} HTTP/1.1", f"host: {host}:{port}"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    if body or method == "POST":
        lines.append(f"content-length: {len(body)}")
    lines.append("connection: close")
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
    s.settimeout(read_s)
    raw = bytearray()
    t0 = time.time()
    try:
        while time.time() - t0 < read_s:
            d = s.recv(65536)
            if not d:
                break
            raw += d
    except (socket.timeout, ssl.SSLError, ConnectionResetError):
        pass
    s.close()
    head, _, rest = bytes(raw).partition(b"\r\n\r\n")
    hl = head.decode(errors="replace").split("\r\n")
    status = int(hl[0].split()[1]) if hl and len(hl[0].split()) > 1 else None
    hd = {}
    for l in hl[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            k = k.strip().lower()
            if k not in DROP_HEADERS:
                hd[k] = v.strip()
    if hd.get("transfer-encoding") == "chunked":
        b, r = bytearray(), rest
        while r:
            n_s, _, r = r.partition(b"\r\n")
            n = int(n_s.split(b";")[0] or b"0", 16)
            if n == 0:
                break
            b += r[:n]
            r = r[n + 2:]
        rest = bytes(b)
    return status, hd, rest, bytes(raw)


def grpc_web(host, port, path, msgs, headers=None, text=False, read_s=10.0, tls=False):
    body = b"".join(frame(m) for m in msgs)
    ct = "application/grpc-web-text" if text else "application/grpc-web+proto"
    if text:
        body = base64.b64encode(body)
    h = {"content-type": ct, "x-grpc-web": "1", "accept": ct}
    h.update(headers or {})
    st, hd, b, raw = http1(host, port, "POST", path, body, h, read_s=read_s, tls=tls, alpn=("http/1.1",) if tls else None)
    if text:
        b = base64.b64decode(b) if b else b""
    resp = {"http_status": st, "headers": hd, "trailers_only": False, "messages_b64": [], "trailers": {}}
    if "grpc-status" in hd:
        resp["trailers_only"] = True
        for k in ("grpc-status", "grpc-message", "grpc-status-details-bin"):
            if k in hd:
                resp["trailers"][k] = hd.pop(k)
    frames, rest = unframe(b)
    for flag, p in frames:
        if flag & 0x80:
            for l in p.decode(errors="replace").split("\r\n"):
                if ":" in l:
                    k, v = l.split(":", 1)
                    resp["trailers"][k.strip().lower()] = v.strip()
        else:
            resp["messages_b64"].append(B64(p))
    if rest:
        resp["body_rest_b64"] = B64(rest)
    return resp
