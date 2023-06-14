use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Parser, Serialize, Deserialize)]
#[clap(name = "test-sender", about = "Mock message sender")]
pub struct SenderConfig {
    #[clap(long, value_name = "TOPICS", help = "Topics for test messages")]
    pub topics: Vec<String>,
    #[clap(long, value_name = "RADIO_NAME", help = "Instance-specific radio name")]
    pub radio_name: String,
}
