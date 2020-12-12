extern crate clap;
extern crate ecvrf;
extern crate env_logger;
extern crate jsonrpc_core;
extern crate rustc_hex as hex;
extern crate serde_json;
extern crate ureq;
#[macro_use]
extern crate log;

extern crate miner;
extern crate primitives;
extern crate rpc;

use std::io::prelude::*;

use clap::Clap;
use ecvrf::VrfPk;
use hex::{FromHex, ToHex};
use jsonrpc_core::types::response::{Output, Response, Success};

use miner::BlockTemplate as minerBlockTemplate;
use primitives::compact::Compact;
use rpc::v1::types::BlockTemplate as rpcBlockTemplate;

/// RandChain miner client
#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    command: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Generate a key pair
    KeyGen(KeyGenOpts),
    /// Connect to randchaind rpc port and mine with a key
    Mine(MineOpts),
}

/// A subcommand for generating key pair
#[derive(Clap)]
struct KeyGenOpts {
    /// Output public key file
    #[clap(short = "u", long = "pub", default_value = "pub.key")]
    pubkey: String,
    /// Output private key file
    #[clap(short = "r", long = "pri", default_value = "pri.key")]
    prikey: String,
}

/// A subcommand for mining
#[derive(Clap)]
struct MineOpts {
    /// Output public key file
    #[clap(short = "u", long = "pub", default_value = "pub.key")]
    pubkey: String,
    /// randchaind rpc endpoint
    #[clap(short = "r", long = "rpc", default_value = "http://127.0.0.1:8332/")]
    endpoint: String,
}

fn main() {
    ::std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::KeyGen(o) => {
            key_gen(o);
        }
        SubCommand::Mine(o) => {
            mine(o);
        }
    }
}

fn key_gen(opts: KeyGenOpts) {
    if std::path::Path::new(&opts.prikey).exists() {
        log::error!("{} existed", &opts.prikey);
        return;
    }
    if std::path::Path::new(&opts.pubkey).exists() {
        log::error!("{} existed", &opts.pubkey);
        return;
    }

    let (sk, pk) = ecvrf::keygen();
    let sk_hex: String = sk.to_bytes().to_hex();
    let pk_hex: String = pk.to_bytes().to_hex();

    std::fs::write(&opts.prikey, sk_hex).expect("save prikey err");
    log::info!("PriKey saved to: {}", opts.prikey);
    std::fs::write(&opts.pubkey, pk_hex).expect("save pubkey err");
    log::info!("PubKey saved to: {}", opts.pubkey);
}

fn load_pk(filename: &str) -> VrfPk {
    let mut pk_hex = String::new();
    let mut f = std::fs::File::open(filename).expect("unable to open.");
    f.read_to_string(&mut pk_hex).expect("unable to read pk.");
    log::info!("loaded pubkey: {}", pk_hex);

    let mut pk: [u8; 32] = [0; 32];
    pk.copy_from_slice(&pk_hex.from_hex::<Vec<u8>>().expect("pubkey format err."));
    VrfPk::from_bytes(&pk).expect("pubkey format err.")
}

fn mine(opts: MineOpts) {
    let pubkey = load_pk(&opts.pubkey);

    let resp = ureq::post(&opts.endpoint)
        .set("X-My-Header", "Secret")
        .send_json(ureq::json!({
        "jsonrpc": "2.0",
        "method": "getblocktemplate",
        "params": [{}],
        // TODO; ID management
        "id": format!("\"{}\"", 1)
         }));
    // TODO: error handling
    let ser_resp = resp.into_string().unwrap();
    log::info!("recieved: {:?}", ser_resp);

    // TODO: error handling
    let success_resp = serde_json::from_str::<Success>(&ser_resp).unwrap();
    let template =
        serde_json::from_str::<rpcBlockTemplate>(&success_resp.result.to_string()).unwrap();
    log::info!("template: {:?}", template);

    let parsed_template = minerBlockTemplate {
        version: template.version,
        previous_header_hash: template.previousblockhash.reversed().into(), // TODO:
        time: template.curtime,
        height: template.height,
        bits: Compact::from(template.bits),
    };

    let solution = match miner::find_solution(&parsed_template, &pubkey, 1) {
        Some(sol) => sol,
        None => return, // TODO:
    };

    log::info!("found solution: {:?}", solution.iterations);

    // submit
}
