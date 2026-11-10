//! `zui-net-truth bench <name> --iters N --list FILE`: the Rust side of `zig build bench -Dsuite=...`
//! (harness protocol, CONTRACTS.md section 7). One JSON line with the median pass.
//!   snappy-compress    snap FrameEncoder over each listed file (one write_all), unit byte
//!   snappy-decompress  snap FrameDecoder over the compressed form, unit byte (decompressed)
//!   rpc-handshake      anemo connect to an in-process anemo server on loopback, unit handshake
//!   rpc-small          small request/response round trip on a warm connection, unit request
//!   rpc-big            download of a 64 MiB response, unit byte
use anemo::{Network, Request, Response};
use anyhow::{Result, bail};
use bytes::Bytes;
use std::convert::Infallible;
use std::io::{Read, Write};
use std::time::Instant;

fn emit(name: &str, unit: &str, units: u64, bytes: u64, mut passes: Vec<u128>) {
    passes.sort();
    let med = passes[passes.len() / 2];
    println!(
        "{{\"impl\":\"rust\",\"bench\":\"{}\",\"unit\":\"{}\",\"units\":{},\"bytes\":{},\"iters\":{},\"median_ns\":{},\"min_ns\":{},\"ns_per_unit\":{:.2}}}",
        name, unit, units, bytes, passes.len(), med, passes[0], med as f64 / units.max(1) as f64
    );
}

fn timed(iters: usize, mut f: impl FnMut() -> Result<()>) -> Result<Vec<u128>> {
    f()?;
    let mut v = Vec::new();
    for _ in 0..iters {
        let t = Instant::now();
        f()?;
        v.push(t.elapsed().as_nanos());
    }
    Ok(v)
}

pub async fn run(args: &[String]) -> Result<()> {
    let name = args.first().cloned().unwrap_or_default();
    let mut iters = 5usize;
    let mut list = String::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => { iters = args[i + 1].parse()?; i += 1; }
            "--list" => { list = args[i + 1].clone(); i += 1; }
            a => bail!("unknown bench arg {a}"),
        }
        i += 1;
    }
    match name.as_str() {
        "snappy-compress" | "snappy-decompress" => {
            let mut blobs = Vec::new();
            for p in std::fs::read_to_string(&list)?.lines() {
                blobs.push(std::fs::read(p)?);
            }
            let total: u64 = blobs.iter().map(|b| b.len() as u64).sum();
            if name == "snappy-compress" {
                let mut sink = 0usize;
                let p = timed(iters, || {
                    for b in &blobs {
                        let mut enc = snap::write::FrameEncoder::new(Vec::with_capacity(b.len() / 2));
                        enc.write_all(b)?;
                        let out = enc.into_inner().map_err(|e| anyhow::anyhow!("{e}"))?;
                        sink = sink.wrapping_add(out.len());
                    }
                    Ok(())
                })?;
                std::hint::black_box(sink);
                emit("snappy-compress", "byte", total, total, p);
            } else {
                let comp: Vec<Vec<u8>> = blobs.iter().map(|b| {
                    let mut enc = snap::write::FrameEncoder::new(Vec::new());
                    enc.write_all(b).unwrap();
                    enc.into_inner().unwrap()
                }).collect();
                let mut sink = 0usize;
                let p = timed(iters, || {
                    for c in &comp {
                        let mut out = Vec::with_capacity(c.len() * 2);
                        snap::read::FrameDecoder::new(&c[..]).read_to_end(&mut out)?;
                        sink = sink.wrapping_add(out.len());
                    }
                    Ok(())
                })?;
                std::hint::black_box(sink);
                emit("snappy-decompress", "byte", total, total, p);
            }
            Ok(())
        }
        "rpc-handshake" | "rpc-small" | "rpc-big" => rpc(&name, iters).await,
        n => bail!("unknown bench {n}"),
    }
}

async fn rpc(name: &str, iters: usize) -> Result<()> {
    // The server is the same Rust peer process deepwave benches against (`peer` subcommand), so both
    // clients see an identical out-of-process server.
    let ready = format!("{}/zui-net-bench-ready-{}", std::env::temp_dir().display(), std::process::id());
    let _ = std::fs::remove_file(&ready);
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args(["peer", "--key", "0707070707070707070707070707070707070707070707070707070707070707", "--ready", &ready])
        .stdout(std::process::Stdio::null())
        .spawn()?;
    let mut line = String::new();
    for _ in 0..400 {
        if let Ok(l) = std::fs::read_to_string(&ready) { line = l; break; }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let r = rpc_inner(name, iters, &line).await;
    let _ = child.kill();
    let _ = std::fs::remove_file(&ready);
    r
}

async fn rpc_inner(name: &str, iters: usize, ready_line: &str) -> Result<()> {
    let mut it = ready_line.split_whitespace();
    it.next();
    let port: u16 = it.next().ok_or_else(|| anyhow::anyhow!("peer did not start"))?.parse()?;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let server_id = anemo::PeerId(hex::decode(it.next().unwrap())?.try_into().unwrap());
    let mut cfg = anemo::Config::default();
    cfg.max_response_frame_size = Some(128 << 20);
    let mut q = anemo::QuicConfig::default();
    q.max_concurrent_bidi_streams = Some(500);
    q.max_concurrent_uni_streams = Some(500);
    q.stream_receive_window = Some(100 << 20);
    q.receive_window = Some(200 << 20);
    q.send_window = Some(200 << 20);
    q.max_idle_timeout_ms = Some(10_000);
    q.keep_alive_interval_ms = Some(5_000);
    cfg.quic = Some(q);
    let new_client = |k: u8| -> Result<Network> {
        Ok(Network::bind("127.0.0.1:0").server_name("sui-35834a8a").private_key([k; 32]).config(cfg.clone()).start(tower::service_fn(|_r: Request<Bytes>| async { Ok::<_, Infallible>(Response::new(Bytes::new())) }))?)
    };
    match name {
        "rpc-handshake" => {
            let mut p = Vec::new();
            for k in 0..=iters {
                let c = new_client(10 + k as u8)?;
                let t = Instant::now();
                c.connect_with_peer_id(addr, server_id).await?;
                if k > 0 { p.push(t.elapsed().as_nanos()); }
                c.shutdown().await.ok();
            }
            emit("rpc-handshake", "handshake", 1, 0, p);
        }
        "rpc-small" => {
            let c = new_client(9)?;
            let id = c.connect_with_peer_id(addr, server_id).await?;
            let n = 2000u64;
            let mut p = Vec::new();
            for k in 0..=iters {
                let t = Instant::now();
                for _ in 0..n {
                    let r = c.rpc(id, Request::new(Bytes::from_static(&[1u8; 64])).with_route("/zui.Test/Echo")).await?;
                    std::hint::black_box(r);
                }
                if k > 0 { p.push(t.elapsed().as_nanos()); }
            }
            emit("rpc-small", "request", n, 0, p);
        }
        _ => {
            let c = new_client(9)?;
            let id = c.connect_with_peer_id(addr, server_id).await?;
            let mut p = Vec::new();
            let sz = (64u64 << 20).to_le_bytes();
            for k in 0..=iters.min(5) {
                let t = Instant::now();
                let r = c.rpc(id, Request::new(Bytes::copy_from_slice(&sz)).with_route("/zui.Test/Big")).await?;
                std::hint::black_box(r.body().len());
                if k > 0 { p.push(t.elapsed().as_nanos()); }
            }
            emit("rpc-big", "byte", 64 << 20, 64 << 20, p);
        }
    }
    Ok(())
}
