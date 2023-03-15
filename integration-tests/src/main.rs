pub mod checks;
pub mod setup;
pub mod utils;

use checks::poi_ok::run_poi_ok;
use dotenv::dotenv;
use graphcast_sdk::{config::Config, init_tracing};
use setup::basic::run_basic_instance;
use std::str::FromStr;
use tracing::{error, info, warn};

use crate::{
    checks::{
        clear_store::run_clear_store, comparison_interval::run_comparison_interval,
        correct_filtering_default_topics::run_correct_filtering_default_topics,
        correct_filtering_different_topics::run_correct_filtering_different_topics,
        invalid_block_hash::run_invalid_block_hash, invalid_payload::run_invalid_payload,
        invalid_sender::run_invalid_sender, invalid_time::run_invalid_time,
        num_messages::run_num_messages, poi_divergence_local::run_poi_divergence_local,
        poi_divergence_remote::run_poi_divergence_remote,
        skip_messages_from_self::run_skip_messages_from_self,
        store_attestations::run_store_attestations,
    },
    setup::{divergent::run_divergent_instance, invalid_payload::run_invalid_payload_instance},
};

#[derive(Clone, Debug)]
enum Instance {
    Basic,
    InvalidPayload,
    Divergent,
}

#[derive(Clone, Debug)]
enum Check {
    PoiOk,
    NumMessages,
    CorrectFilteringDefaultTopics,
    CorrectFilteringDifferentTopics,
    InvalidSender,
    InvalidTime,
    InvalidBlockHash,
    InvalidPayload,
    SkipMessagesFromSelf,
    StoreAttestations,
    PoiDivergenceRemote,
    PoiDivergenceLocal,
    ClearStore,
    ComparisonInterval,
}

impl FromStr for Instance {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "basic" => Ok(Instance::Basic),
            "invalid_payload" => Ok(Instance::InvalidPayload),
            "divergent" => Ok(Instance::Divergent),
            _ => Err(format!("Invalid instance type: {s}")),
        }
    }
}

impl FromStr for Check {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "poi_ok" => Ok(Check::PoiOk),
            "num_messages" => Ok(Check::NumMessages),
            "correct_filtering_default_topics" => Ok(Check::CorrectFilteringDefaultTopics),
            "correct_filtering_different_topics" => Ok(Check::CorrectFilteringDifferentTopics),
            "invalid_sender" => Ok(Check::InvalidSender),
            "invalid_time" => Ok(Check::InvalidTime),
            "invalid_hash" => Ok(Check::InvalidBlockHash),
            "invalid_payload" => Ok(Check::InvalidPayload),
            "skip_messages_from_self" => Ok(Check::SkipMessagesFromSelf),
            "store_attestations" => Ok(Check::StoreAttestations),
            "poi_divergence_remote" => Ok(Check::PoiDivergenceRemote),
            "poi_divergence_local" => Ok(Check::PoiDivergenceLocal),
            "clear_store" => Ok(Check::ClearStore),
            "comparison_interval" => Ok(Check::ComparisonInterval),
            _ => Err(format!("Invalid check type: {s}")),
        }
    }
}

#[tokio::main]
pub async fn main() {
    dotenv().ok();

    let args = Config::args();

    init_tracing().expect("Could not set up global default subscriber");

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
            Ok(Check::PoiOk) => std::thread::spawn(|| {
                info!("Starting poi_ok check");
                run_poi_ok();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::NumMessages) => {
                let count = args.count;

                let count = count.unwrap_or_else(|| {
                    warn!("No 'count' argument provided, defaulting to '5'.");
                    5
                });

                std::thread::spawn(move || {
                    info!("Starting num_messages check");
                    run_num_messages(count);
                })
                .join()
                .expect("Thread panicked");
            }
            Ok(Check::CorrectFilteringDefaultTopics) => std::thread::spawn(|| {
                info!("Starting correct_filtering_default_topics check");
                run_correct_filtering_default_topics();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::CorrectFilteringDifferentTopics) => std::thread::spawn(|| {
                info!("Starting correct_filtering_different_topics check");
                run_correct_filtering_different_topics();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::InvalidSender) => std::thread::spawn(|| {
                info!("Starting invalid_sender check");
                run_invalid_sender();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::InvalidTime) => std::thread::spawn(|| {
                info!("Starting invalid_time check");
                run_invalid_time();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::InvalidBlockHash) => std::thread::spawn(|| {
                info!("Starting invalid_block_hash check");
                run_invalid_block_hash();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::InvalidPayload) => std::thread::spawn(|| {
                info!("Starting invalid_payload check");
                run_invalid_payload();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::SkipMessagesFromSelf) => std::thread::spawn(|| {
                info!("Starting skip_messages_from_self check");
                run_skip_messages_from_self();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::StoreAttestations) => std::thread::spawn(|| {
                info!("Starting store_attestations check");
                run_store_attestations();
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
            Ok(Check::ClearStore) => std::thread::spawn(|| {
                info!("Starting clear_store check");
                run_clear_store();
            })
            .join()
            .expect("Thread panicked"),
            Ok(Check::ComparisonInterval) => {
                info!("Starting divergent instance");

                std::thread::spawn(|| {
                    run_comparison_interval();
                })
                .join()
                .expect("Thread panicked")
            }
            Err(err) => error!("Error: {}", err),
        }
    }
}
