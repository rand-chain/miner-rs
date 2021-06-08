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
extern crate chain;
extern crate miner;
extern crate primitives;
#[macro_use]
extern crate rpc;
extern crate serialization as ser;

use chain::{Block, BlockHeader, IndexedBlock};
use clap::Clap;
use ecvrf::VrfPk;
use hex::{FromHex, ToHex};
use jsonrpc_core::types::response::{Output, Response, Success};
use miner::BlockTemplate as minerBlockTemplate;
use miner::{init, prove, solve};
use primitives::compact::Compact;
use primitives::hash::H256 as GlobalH256;
use rpc::v1::types::BlockTemplate as rpcBlockTemplate;
use ser::{deserialize, serialize};
use std::io::prelude::*;
use std::thread;
use std::time::Duration;

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
#[derive(Clap, Clone)]
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

fn try_req(url: &str, req_id: u64) -> Result<minerBlockTemplate, Error> {
    let req = ureq::post(url)
        .set("X-My-Header", "Secret")
        .send_json(ureq::json!({
           "jsonrpc": "2.0",
           "method": "getblocktemplate",
           "params": [{}],
           "id": format!("\"{}\"", req_id)
        }));
    let resp = req.unwrap(); // TODO error handling
    log::debug!("receive response of getblocktemplate: {:?}", resp);
    let success_resp = resp.into_json::<Success>().unwrap();

    let template =
        serde_json::from_str::<rpcBlockTemplate>(&success_resp.result.to_string()).unwrap();

    let previous_header_global_hash: GlobalH256 = template.previousblockhash.into();
    Ok(minerBlockTemplate {
        version: template.version,
        previous_header_hash: previous_header_global_hash,
        height: template.height,
        bits: Compact::from(template.bits),
    })
}

fn mine(opts: MineOpts) {
    let pubkey = load_pk(&opts.pubkey);
    let mut req_id = 1u64;

    let mut tpl: minerBlockTemplate = match try_req(&opts.endpoint, req_id) {
        Err(err) => {
            error!("error upon getblocktemplate: {:?}", err);
            return;
        }
        Ok(template) => template,
    };

    // update block template thread
    let endpoint = opts.endpoint.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        match try_req(&endpoint, req_id) {
            Err(err) => {
                error!("error upon getblocktemplate: {:?}", err);
            }
            Ok(template) => {
                req_id += 1;
                if tpl.previous_header_hash != template.previous_header_hash {
                    info!(
                        "receive new template with previous block hash {:?} and height {} from {:?}",
                        template.previous_header_hash,
                        template.height,
                        endpoint.clone(),
                    );
                    tpl = template;
                }
            }
        };
    });

    // mine thread
    let mut sol = init(&tpl, &pubkey);
    let mut previous_header_hash = tpl.previous_header_hash;
    loop {
        // when tpl is new,
        // re-init solution and update header hash
        if previous_header_hash != tpl.previous_header_hash {
            sol = init(&tpl, &pubkey);
            previous_header_hash = tpl.previous_header_hash;
        }

        // increment by SeqPoW:Solve()
        let (new_solution, valid) = solve(&tpl, &pubkey, &sol);

        // if valid,
        // 1. generate proof
        // 2. construct block
        // 3. send block to node
        if valid {
            sol = prove(&tpl, &pubkey, &new_solution);
            info!("find solution: {:?}", sol.element);
            // construct block
            let blk = Block {
                block_header: BlockHeader {
                    version: tpl.version,
                    previous_header_hash: tpl.previous_header_hash,
                    bits: tpl.bits,
                    pubkey: pubkey.clone(),
                    iterations: sol.iterations as u32,
                    randomness: sol.element.clone(),
                },
                proof: sol.proof.clone(),
            };
            // serialise block
            let ser_block: String = serialize(&blk).to_hex();
            // make request and receive response
            let req = ureq::post(&opts.endpoint)
                .set("X-My-Header", "Secret")
                .send_json(ureq::json!({
                    "jsonrpc": "2.0",
                    "method": "submitblock",
                    "params": [{"data": &ser_block}],
                    "id": format!("\"{}\"", req_id)
                }));
            match req {
                Ok(resp) => {
                    log::info!("received response of submitblock: {:?}", resp.into_string())
                }
                Err(err) => log::info!("error upon submitblock: {:?}", err),
            }
        }
    }
}

// fn mine(opts: MineOpts) {
//     let pubkey = load_pk(&opts.pubkey);
//     let tick = chan::tick(Duration::from_secs(1));
//     let mut req_id = 1u64;
//     let mut last_height = 0u32;

//     loop {
//         chan_select! {
//             default => {},

//             tick.recv() => {
//                 log::info!("req_id: {}", req_id);

//                 match try_req(&opts.endpoint, req_id) {
//                     Err(_) =>  continue,

//                     Ok(template) => {
//                         // refresh request ID and last height
//                         req_id += 1;

//                         // if the template does not change, skip
//                         if last_height == template.height {
//                             continue
//                         }
//                         last_height = template.height;

//                         log::info!(
//                             "receive new template with previous block hash {:?} and height {} from {:?}",
//                             template.previous_header_hash,
//                             template.height,
//                             opts.endpoint
//                         );

//                         let solution = match miner::find_solution(&template, &pubkey, Duration::from_secs(60)) {
//                             Some(sol) => sol,
//                             None => continue,
//                         };
//                         // let solution = match miner::find_solution_dry(&template, &pubkey) {
//                         //     Some(sol) => sol,
//                         //     None => continue,
//                         // };
//                         log::info!("find solution: {:?}", solution.element);

//                         // construct block
//                         let blk = Block {
//                             block_header: BlockHeader {
//                                 version: template.version,
//                                 previous_header_hash: template.previous_header_hash,
//                                 bits: template.bits,
//                                 pubkey: pubkey.clone(),
//                                 iterations: solution.iterations as u32,
//                                 randomness: solution.element,
//                             },
//                             proof: solution.proof,
//                         };
//                         // serialise block
//                         let ser_block: String = serialize(&blk).to_hex();
//                         // make request and receive response
//                         let req = ureq::post(&opts.endpoint)
//                             .set("X-My-Header", "Secret")
//                             .send_json(ureq::json!({
//                                 "jsonrpc": "2.0",
//                                 "method": "submitblock",
//                                 "params": [{"data": &ser_block}],
//                                 "id": format!("\"{}\"", req_id)
//                             }));
//                         match req {
//                             Ok(resp) => log::info!("received response of submitblock: {:?}", resp.into_string()),
//                             Err(err) => log::info!("error upon submitblock: {:?}", err),
//                         }
//                     }
//                 }
//             },
//         }
//     }
// }
