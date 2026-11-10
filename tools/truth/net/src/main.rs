//! zui-net-truth: ground truth for the deepwave `net` lane (CONTRACTS.md section 3.3 suites
//! `anemo-wire`, `anemo-interop`, `sync-rpc-codec`). Links Mysten's anemo (rev 68adc31),
//! mysten-network's BcsSnappyCodec and sui-types at mainnet-v1.83.1.
//!
//!   zui-net-truth wire <out.jsonl>                 anemo frames and headers as anemo's serde/bincode/tokio-util produce them
//!   zui-net-truth snappy <out.jsonl>               snap::write::FrameEncoder outputs for raw payloads
//!   zui-net-truth sync <out.jsonl> <chk-dir> <n>   BcsSnappyCodec bytes of state-sync messages (real checkpoints from the corpus)
//!   zui-net-truth peer [--key HEX] [--port N] [--server-name S] [--log FILE]
//!                                                  a Rust anemo peer for interop; prints "READY <port> <peer id hex>"
//!   zui-net-truth sync-from --peer HOST:PORT --peer-id HEX --from N --to M ...
//!                                                  sui-node-like state-sync client vs the public bucket (syncfrom.rs)
//!   zui-net-truth serve-probe --peer HOST:PORT --peer-id HEX [--interval-s 5] [--count N]
//!                                                  a mainnet-peer-like availability poller
use anemo::{Network, Request, Response, Router, types::response::StatusCode};
use anyhow::{Result, bail};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::io::Write;
use std::sync::{Arc, Mutex};

mod bench;
mod discovery;
mod sync;
mod syncfrom;

// anemo's RawRequestHeader / RawResponseHeader are pub(crate); these are field-for-field
// copies with the same serde derive, serialized by the same bincode 1.3 default config.
#[derive(Serialize, Deserialize)]
struct RawRequestHeader {
    route: String,
    headers: HashMap<String, String>,
}
#[derive(Serialize, Deserialize)]
struct RawResponseHeader {
    status: u16,
    headers: HashMap<String, String>,
}

fn frame(data: &[u8]) -> Vec<u8> {
    use tokio_util::codec::{Encoder, LengthDelimitedCodec};
    let mut c = LengthDelimitedCodec::builder().length_field_length(4).big_endian().new_codec();
    let mut out = bytes::BytesMut::new();
    c.encode(Bytes::copy_from_slice(data), &mut out).unwrap();
    out.to_vec()
}

const VERSION_FRAME: [u8; 8] = [b'a', b'n', b'e', b'm', b'o', 0, 1, 0];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn wire(out: &str) -> Result<()> {
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);
    let mut rng = Rng(0x616e656d6f);
    let mut n = 0u32;
    let mut emit = |v: serde_json::Value| -> Result<()> {
        writeln!(f, "{}", v)?;
        Ok(())
    };
    emit(json!({"id":"version/v1","kind":"version","hex":hex::encode(VERSION_FRAME)}))?;
    // frames: lengths around every boundary
    for len in [0usize, 1, 2, 3, 4, 5, 63, 64, 255, 256, 257, 65535, 65536, 65537, 1 << 20, (1 << 20) + 1] {
        let payload = rng.bytes(len);
        n += 1;
        emit(json!({"id":format!("frame/{len}"),"kind":"frame","payload_len":len,
            "payload_hex":hex::encode(&payload),"hex":hex::encode(frame(&payload))}))?;
    }
    // request headers: routes and header maps. Several headers appear in Rust's HashMap order.
    let routes = [
        "/", "/sui.StateSync/GetCheckpointSummary", "/sui.StateSync/GetCheckpointAvailability",
        "/sui.Discovery/GetKnownPeersV3", "/sui.Randomness/SendSignatures", "/é/ü", &"/x".repeat(300),
    ];
    for (ri, route) in routes.iter().enumerate() {
        for hs in 0..5usize {
            let mut headers = HashMap::new();
            for h in 0..hs {
                let k = ["timeout", "content-type", "status-message", "x-a", "x-longer-header-name"][h];
                let v = match h { 0 => (rng.next() % 100_000_000_000).to_string(), 1 => "bcs".into(), _ => format!("value-{h}-{}", rng.next()) };
                headers.insert(k.to_string(), v);
            }
            let raw = RawRequestHeader { route: route.to_string(), headers: headers.clone() };
            let enc = bincode::serialize(&raw)?;
            let body = rng.bytes(ri * 7 + hs);
            let mut stream = VERSION_FRAME.to_vec();
            stream.extend(frame(&enc));
            stream.extend(frame(&body));
            let mut hv: Vec<_> = headers.iter().map(|(k, v)| json!([k, v])).collect();
            hv.sort_by_key(|x| x[0].as_str().unwrap().to_string());
            emit(json!({"id":format!("request/{ri}/{hs}"),"kind":"request","route":route,"headers":hv,
                "header_hex":hex::encode(&enc),"body_hex":hex::encode(&body),"hex":hex::encode(&stream),
                "ordered": hs <= 1}))?;
            n += 1;
        }
    }
    for status in [200u16, 400, 404, 408, 429, 500, 505, 520] {
        for hs in 0..4usize {
            let mut headers = HashMap::new();
            if hs > 0 { headers.insert("status-message".to_string(), format!("msg {status}")); }
            if hs > 1 { headers.insert("content-type".to_string(), "bcs".to_string()); }
            if hs > 2 { headers.insert("x-zzz".to_string(), "".to_string()); }
            let raw = RawResponseHeader { status, headers: headers.clone() };
            let enc = bincode::serialize(&raw)?;
            let body = rng.bytes(status as usize % 13 + hs);
            let mut stream = VERSION_FRAME.to_vec();
            stream.extend(frame(&enc));
            stream.extend(frame(&body));
            let mut hv: Vec<_> = headers.iter().map(|(k, v)| json!([k, v])).collect();
            hv.sort_by_key(|x| x[0].as_str().unwrap().to_string());
            emit(json!({"id":format!("response/{status}/{hs}"),"kind":"response","status":status,"headers":hv,
                "header_hex":hex::encode(&enc),"body_hex":hex::encode(&body),"hex":hex::encode(&stream),
                "ordered": hs <= 1}))?;
            n += 1;
        }
    }
    eprintln!("wire: {n} vectors");
    Ok(())
}

fn snappy(out: &str) -> Result<()> {
    use std::io::Write as _;
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);
    let mut rng = Rng(0x736e6170);
    let mut n = 0;
    let mut kinds: Vec<(String, Vec<u8>)> = vec![("empty".into(), vec![])];
    for len in [1usize, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 63, 64, 100, 255, 1000, 4095, 4096, 65535, 65536, 65537, 131072, 200_000, 1 << 20] {
        kinds.push((format!("random/{len}"), rng.bytes(len)));
        kinds.push((format!("zeros/{len}"), vec![0u8; len]));
        let rep: Vec<u8> = (0..len).map(|i| (i % 37) as u8).collect();
        kinds.push((format!("period37/{len}"), rep));
        // text-like: small alphabet with runs and repeats of earlier substrings
        let mut t = Vec::with_capacity(len);
        while t.len() < len {
            let r = rng.next();
            if t.len() > 16 && r % 3 == 0 {
                let start = (rng.next() as usize) % (t.len() - 8);
                let l = 4 + (rng.next() as usize) % 60;
                for k in 0..l { if t.len() < len { let b = t[start + (k % (t.len() - start))]; t.push(b); } }
            } else {
                t.push(b'a' + (r % 7) as u8);
            }
        }
        kinds.push((format!("text/{len}"), t));
    }
    for (id, data) in kinds {
        let mut enc = snap::write::FrameEncoder::new(Vec::new());
        enc.write_all(&data)?;
        let framed = enc.into_inner().map_err(|e| anyhow::anyhow!("{e}"))?;
        // raw block (no framing) for the block codec
        let block = snap::raw::Encoder::new().compress_vec(&data)?;
        writeln!(f, "{}", json!({"id":id,"raw_len":data.len(),"raw_hex":hex::encode(&data),"framed_hex":hex::encode(&framed),"block_hex":hex::encode(&block)}))?;
        n += 1;
    }
    eprintln!("snappy: {n} vectors");
    Ok(())
}

// ---- interop peer ----

#[derive(Clone)]
struct PeerState {
    log: Arc<Mutex<std::fs::File>>,
    fixtures: Arc<HashMap<String, Bytes>>,
    /// Set once the network is up; lets handlers call back into the connected client.
    net: Arc<std::sync::OnceLock<Network>>,
    /// Status codes the client answered to server-initiated requests (u16 each).
    callback_results: Arc<Mutex<Vec<u16>>>,
}

async fn handle(st: PeerState, req: Request<Bytes>) -> Result<Response<Bytes>, Infallible> {
    let route = req.route().to_string();
    let mut hs: Vec<(String, String)> = req.headers().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    hs.sort();
    let body = req.body().clone();
    {
        let mut l = st.log.lock().unwrap();
        let _ = writeln!(l, "{}", json!({"route":route,"headers":hs,"body_hex":hex::encode(&body),"peer":req.peer_id().map(|p| hex::encode(p.0))}));
    }
    let resp = match route.as_str() {
        "/zui.Test/Echo" => {
            let mut r = Response::new(body.clone());
            for (k, v) in hs.iter().filter(|(k, _)| k.starts_with("x-")) {
                r = r.with_header(k.clone(), v.clone());
            }
            r
        }
        "/zui.Test/Big" => {
            // body is 8 bytes LE: size. Response is a deterministic byte stream of that size.
            let mut sz = [0u8; 8];
            sz[..body.len().min(8)].copy_from_slice(&body[..body.len().min(8)]);
            let n = u64::from_le_bytes(sz) as usize;
            static CACHE: Mutex<Option<(usize, Bytes)>> = Mutex::new(None);
            let mut g = CACHE.lock().unwrap();
            if g.as_ref().map(|(k, _)| *k) != Some(n) {
                *g = Some((n, Bytes::from((0..n).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8).collect::<Vec<u8>>())));
            }
            Response::new(g.as_ref().unwrap().1.clone())
        }
        "/zui.Test/Callback" => {
            // Server-initiated requests: the peer calls the client back on new bidi streams. A
            // read-only deepwave client must answer 404 to unknown routes and 200 to checkpoint pushes.
            if let (Some(net), Some(pid)) = (st.net.get().cloned(), req.peer_id().copied()) {
                let results = st.callback_results.clone();
                tokio::spawn(async move {
                    for route in ["/sui.StateSync/PushCheckpointSummary", "/zui.Nope/Unknown", "/sui.Discovery/GetKnownPeersV2"] {
                        let r = net.rpc(pid, Request::new(Bytes::from_static(b"\x00")).with_route(route)).await;
                        results.lock().unwrap().push(r.map(|r| r.status().to_u16()).unwrap_or(0));
                    }
                });
            }
            Response::new(Bytes::new())
        }
        "/zui.Test/CallbackResult" => {
            let v: Vec<u8> = st.callback_results.lock().unwrap().iter().flat_map(|c| c.to_le_bytes()).collect();
            Response::new(Bytes::from(v))
        }
        "/zui.Test/Status" => {
            let code = u16::from_le_bytes([body.get(0).copied().unwrap_or(0), body.get(1).copied().unwrap_or(0)]);
            let sc = StatusCode::new(code).unwrap_or(StatusCode::Unknown);
            Response::new(Bytes::new()).with_status(sc).with_header("status-message", "from the Rust peer")
        }
        r => match st.fixtures.get(r) {
            Some(b) => Response::new(b.clone()),
            None => Response::new(Bytes::new()).with_status(StatusCode::NotFound),
        },
    };
    Ok(resp)
}

async fn peer(args: Vec<String>) -> Result<()> {
    let mut key = [7u8; 32];
    let mut port = 0u16;
    let mut name = "sui-35834a8a".to_string();
    let mut log = "/dev/null".to_string();
    let mut fixdir: Option<String> = None;
    let mut ready: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => { key.copy_from_slice(&hex::decode(&args[i + 1])?); i += 1; }
            "--port" => { port = args[i + 1].parse()?; i += 1; }
            "--server-name" => { name = args[i + 1].clone(); i += 1; }
            "--log" => { log = args[i + 1].clone(); i += 1; }
            "--fixtures" => { fixdir = Some(args[i + 1].clone()); i += 1; }
            "--ready" => { ready = Some(args[i + 1].clone()); i += 1; }
            a => bail!("unknown arg {a}"),
        }
        i += 1;
    }
    // fixtures: file `<dir>/<route with / replaced by _>.bin` is the response body of that route
    let mut fixtures = HashMap::new();
    if let Some(d) = fixdir {
        for e in std::fs::read_dir(d)? {
            let e = e?;
            let fname = e.file_name().to_string_lossy().to_string();
            if let Some(stem) = fname.strip_suffix(".bin") {
                fixtures.insert(stem.replace('_', "/"), Bytes::from(std::fs::read(e.path())?));
            }
        }
    }
    let st = PeerState {
        log: Arc::new(Mutex::new(std::fs::File::create(&log)?)),
        fixtures: Arc::new(fixtures),
        net: Arc::new(std::sync::OnceLock::new()),
        callback_results: Arc::new(Mutex::new(Vec::new())),
    };
    let svc = {
        let st = st.clone();
        tower::service_fn(move |req| handle(st.clone(), req))
    };
    let router = Router::new().route("/*rest", svc);
    // Same QUIC settings as sui-node 1.83.1 (sui-node/src/lib.rs).
    let mut cfg = anemo::Config::default();
    cfg.max_request_frame_size = Some(1 << 20);
    cfg.max_response_frame_size = Some(128 << 20);
    let mut q = anemo::QuicConfig::default();
    q.max_concurrent_bidi_streams = Some(500);
    q.max_concurrent_uni_streams = Some(500);
    q.stream_receive_window = Some(100 << 20);
    q.receive_window = Some(200 << 20);
    q.send_window = Some(200 << 20);
    q.crypto_buffer_size = Some(1 << 20);
    q.max_idle_timeout_ms = Some(10_000);
    q.keep_alive_interval_ms = Some(5_000);
    cfg.quic = Some(q);
    let network = Network::bind(format!("127.0.0.1:{port}"))
        .server_name(&name)
        .private_key(key)
        .config(cfg)
        .start(router)?;
    let _ = st.net.set(network.clone());
    let line = format!("READY {} {}\n", network.local_addr().port(), hex::encode(network.peer_id().0));
    print!("{line}");
    std::io::stdout().flush()?;
    if let Some(r) = ready {
        // write-then-rename so a poller never sees a partial line
        std::fs::write(format!("{r}.tmp"), &line)?;
        std::fs::rename(format!("{r}.tmp"), r)?;
    }
    // serve until killed
    std::future::pending::<()>().await;
    network.shutdown().await.ok();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("wire") => wire(&a[2]),
        Some("snappy") => snappy(&a[2]),
        Some("sync") => sync::run(&a[2], &a[3], a[4].parse()?),
        Some("peer") => peer(a[2..].to_vec()).await,
        Some("discovery") => discovery::run(&a[2]),
        Some("bench") => bench::run(&a[2..]).await,
        Some("sync-from") => syncfrom::run(&a[2..]).await,
        Some("serve-probe") => syncfrom::probe(&a[2..]).await,
        Some("peer-id") => syncfrom::peer_id(&a[2..]),
        _ => bail!("usage: wire|snappy|sync|peer|discovery|bench|sync-from|serve-probe"),
    }
}
