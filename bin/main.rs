#[macro_use]
extern crate chan;
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
use std::time::Duration;

use clap::Clap;
use ecvrf::VrfPk;
use hex::{FromHex, ToHex};
use jsonrpc_core::types::response::{Output, Response, Success};

use miner::BlockTemplate as minerBlockTemplate;
use primitives::compact::Compact;
use rpc::v1::types::{BlockTemplate as rpcBlockTemplate, SubmitBlockRequest, SubmitBlockResponse};

#[derive(Debug, PartialEq, Clone)]
enum Error {
    SerError,
}

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
    #[clap(short = "r", long = "prv", default_value = "prv.key")]
    prvkey: String,
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
    if std::path::Path::new(&opts.prvkey).exists() {
        log::error!("{} existed", &opts.prvkey);
        return;
    }
    if std::path::Path::new(&opts.pubkey).exists() {
        log::error!("{} existed", &opts.pubkey);
        return;
    }

    let (sk, pk) = ecvrf::keygen();
    let sk_hex: String = sk.to_bytes().to_hex();
    let pk_hex: String = pk.to_bytes().to_hex();

    std::fs::write(&opts.prvkey, sk_hex).expect("save prvkey err");
    log::info!("PrvKey saved to: {}", opts.prvkey);
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
    let tick = chan::tick(Duration::from_secs(1));
    let mut req_id = 1u64;
    let mut last_height = 1u32;

    loop {
        chan_select! {
            default => {},

            tick.recv() => {
                log::info!("req_id: {}", req_id);

                match getblocktemplate(&opts.endpoint, req_id) {
                    Err(_) =>  continue,

                    Ok(template) => {
                        if template.height == last_height {
                            continue;
                        };

                        req_id += 1;
                        last_height = template.height;
                        let solution = match miner::find_solution(&template, &pubkey, Duration::from_secs(1)) {
                            Some(sol) => sol,
                            None => continue,
                        };

                        log::info!("found solution: {:?}", solution.iterations);
                        match submit_block(&opts.endpoint, &template) {
                            Ok(res) => log::info!("submit_block ok: {}", res),
                            Err(e) => log::error!("submit_block error: {}", e),
                        };
                    }
                }
            },
        }
    }
}

fn getblocktemplate(url: &str, req_id: u64) -> Result<minerBlockTemplate, Error> {
    let resp = ureq::post(url)
        .set("X-My-Header", "Secret")
        .send_json(ureq::json!({
        "jsonrpc": "2.0",
        "method": "getblocktemplate",
        "params": [{}],
        "id": format!("\"{}\"", req_id)
         }));
    let ser_resp = resp.into_string().unwrap();
    log::debug!("recieved: {:?}", ser_resp);

    let success_resp = match serde_json::from_str::<Success>(&ser_resp) {
        Err(_) => return Err(Error::SerError),
        success_resp => success_resp.unwrap(),
    };

    let template =
        serde_json::from_str::<rpcBlockTemplate>(&success_resp.result.to_string()).unwrap();
    log::info!("receive template: {:?}", template);

    Ok(minerBlockTemplate {
        version: template.version,
        previous_header_hash: template.previousblockhash.reversed().into(), // TODO:
        time: template.curtime,
        height: template.height,
        bits: Compact::from(template.bits),
    })
}

fn submit_block(
    url: &str,
    block_template: &miner::BlockTemplate,
) -> Result<SubmitBlockResponse, Error> {
    let block = SubmitBlockRequest {};

    let resp = ureq::post(url)
        .set("X-My-Header", "Secret")
        .send_json(ureq::json!({
        "jsonrpc": "2.0",
        "method": "submit_block",
        "params": [{}],
        "block": format!("\"{}\"", block)
         }));

    unimplemented!();
    // let ser_resp = resp.into_string().unwrap();
    // log::debug!("recieved: {:?}", ser_resp);

    // let success_resp = match serde_json::from_str::<Success>(&ser_resp) {
    //     Err(_) => return Err(Error::SerError),
    //     success_resp => success_resp.unwrap(),
    // };

    // let template =
    //     serde_json::from_str::<rpcBlockTemplate>(&success_resp.result.to_string()).unwrap();
    // log::info!("receive template: {:?}", template);

    // Ok(minerBlockTemplate {
    //     version: template.version,
    //     previous_header_hash: template.previousblockhash.reversed().into(), // TODO:
    //     time: template.curtime,
    //     height: template.height,
    //     bits: Compact::from(template.bits),
    // })
}
