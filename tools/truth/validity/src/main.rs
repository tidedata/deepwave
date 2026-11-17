//! zui-truth-validity: golden accept/reject vectors for the validator's signing path, computed
//! by Mysten's sui 1.83.1 code (README.md). One subcommand per suite; each writes one
//! zstd-compressed vector file that a Zig test embeds.

mod common;
mod denycfg;
mod signing;
mod validity;
mod verifier;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: zui-truth-validity <validity|denycfg|signing|verifier> <out.txt.zst>";
    let (cmd, out) = match args.as_slice() {
        [_, cmd, out] => (cmd.as_str(), out.as_str()),
        _ => anyhow::bail!(usage),
    };
    match cmd {
        "validity" => validity::run(out),
        "denycfg" => denycfg::run(out),
        "signing" => signing::run(out),
        "verifier" => verifier::run(out),
        _ => anyhow::bail!(usage),
    }
}
