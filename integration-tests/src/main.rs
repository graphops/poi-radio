pub mod checks;
pub mod setup;
pub mod utils;

use checks::simple_tests::run_simple_tests;
use dotenv::dotenv;
use graphcast_sdk::config::Config;
use once_cell::sync::OnceCell;
use setup::basic::run_basic_instance;
use std::str::FromStr;
use tracing::{error, info};

use crate::{
    checks::{
        invalid_messages::run_invalid_messages, invalid_sender::run_invalid_sender_check,
        poi_divergence_local::run_poi_divergence_local,
        poi_divergence_remote::run_poi_divergence_remote,
    },
    setup::{
        divergent::run_divergent_instance, invalid_block_hash::run_invalid_block_hash_instance,
        invalid_nonce::run_invalid_nonce_instance, invalid_payload::run_invalid_payload_instance,
    },
};

#[derive(Clone, Debug)]
enum Instance {
    Basic,
    InvalidPayload,
    Divergent,
    InvalidNonce,
    InvalidHash,
}

#[derive(Clone, Debug)]
enum Check {
    SimpleTests,
    PoiDivergenceRemote,
    PoiDivergenceLocal,
    InvalidSender,
    InvalidMessages,
}

impl FromStr for Instance {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "basic" => Ok(Instance::Basic),
            "invalid_payload" => Ok(Instance::InvalidPayload),
            "divergent" => Ok(Instance::Divergent),
            "invalid_hash" => Ok(Instance::InvalidHash),
            "invalid_nonce" => Ok(Instance::InvalidNonce),
            _ => Err(format!("Invalid instance type: {s}")),
        }
    }
}

impl FromStr for Check {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "simple_tests" => Ok(Check::SimpleTests),
            "poi_divergence_remote" => Ok(Check::PoiDivergenceRemote),
            "poi_divergence_local" => Ok(Check::PoiDivergenceLocal),
            "invalid_messages" => Ok(Check::InvalidMessages),
            "invalid_sender" => Ok(Check::InvalidSender),
            _ => Err(format!("Invalid check type: {s}")),
        }
    }
}

pub static CONFIG: OnceCell<Config> = OnceCell::new();

#[tokio::main]
pub async fn main() {
    dotenv().ok();
    let args = Config::args();
    _ = CONFIG.set(args.clone());

    if let Some(instance) = &args.instance {
        match Instance::from_str(instance) {
            Ok(Instance::Basic) => {
                info!("Starting basic instance");
                std::thread::spawn(|| {
                    run_basic_instance();
                })
                .join()
                .expect("Thread panicked")
            }
            Ok(Instance::InvalidPayload) => {
                info!("Starting invalid payload instance");
                std::thread::spawn(|| {
                    run_invalid_payload_instance();
                })
                .join()
                .expect("Thread panicked")
            }
            Ok(Instance::InvalidNonce) => {
                info!("Starting invalid nonce instance");
                std::thread::spawn(|| {
                    run_invalid_nonce_instance();
                })
                .join()
                .expect("Thread panicked")
            }
            Ok(Instance::InvalidHash) => {
                info!("Starting invalid hash instance");
                std::thread::spawn(|| {
                    run_invalid_block_hash_instance();
                })
                .join()
                .expect("Thread panicked")
            }
            Ok(Instance::Divergent) => {
                info!("Starting divergent instance");
                std::thread::spawn(|| {
                    run_divergent_instance();
                })
                .join()
                .expect("Thread panicked")
            }
            Err(err) => error!("Error: {}", err),
        }
    }

    if let Some(check) = &args.check {
        match Check::from_str(check) {
            Ok(Check::SimpleTests) => std::thread::spawn(|| {
                info!("Starting simple tests");
                run_simple_tests();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::InvalidMessages) => std::thread::spawn(|| {
                info!("Starting invalid_messages check");
                run_invalid_messages();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::PoiDivergenceRemote) => std::thread::spawn(|| {
                info!("Starting poi_divergence_remote check");
                run_poi_divergence_remote();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::PoiDivergenceLocal) => std::thread::spawn(|| {
                info!("Starting poi_divergence_local check");
                run_poi_divergence_local();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::InvalidSender) => std::thread::spawn(|| {
                info!("Starting invalid_sender check");
                run_invalid_sender_check();
            })
            .join()
            .expect("Thread panicked"),
            Err(err) => error!("Error: {}", err),
        }
    }
}
