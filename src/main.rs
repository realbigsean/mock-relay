use clap::Parser;
use color_eyre::eyre;
use color_eyre::eyre::eyre;
use execution_layer::auth::{Auth, JwtKey};
use execution_layer::http::{
    ENGINE_FORKCHOICE_UPDATED_TIMEOUT, ENGINE_FORKCHOICE_UPDATED_V1, JSONRPC_VERSION,
};
use execution_layer::{Config, HttpJsonRpc};
use lru::LruCache;
use parking_lot::lock_api::RwLock;
use sensitive_url::SensitiveUrl;
use serde::de::DeserializeOwned;
use serde_json::json;
use serde_json::Value as JsonValue;
use std::fmt::Debug;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use eth2::Timeouts;
use execution_layer::test_utils::MockBuilderContext;
use mev_build_rs::ApiServer;
use sloggers::Build;
use task_executor::ShutdownReason;
use tokio::signal::ctrl_c;
use tokio::sync::oneshot;
use tracing::{instrument, Level};
use tracing_core::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber;
use tracing_subscriber::prelude::*;
use types::{BlindedPayload, ChainSpec, ExecutionPayload, ExecutionPayloadHeader, Hash256, MainnetEthSpec, Signature, SignedBeaconBlock, Uint256};
use warp::Filter;

#[derive(Parser)]
#[clap(
    about = "mock execution payload relay",
    version = "0.1.0",
    author = "@realbigsean"
)]
struct MockRelay {
    #[clap(
        long,
        help = "URL of the execution engine",
        default_value = "http://localhost:8551"
    )]
    execution_endpoint: String,
    #[clap(
        long,
        help = "URL of the beacon node",
        default_value = "http://localhost:5052"
    )]
    beacon_node: String,
    #[clap(
        long,
        help = "File path which contain the corresponding hex-encoded JWT secrets for the provided \
            execution endpoint"
    )]
    jwt_secret: PathBuf,
    #[clap(long, help = "Address to listen on", default_value = "127.0.0.1")]
    address: Ipv4Addr,
    #[clap(long, help = "Port to listen on", default_value_t = 8650)]
    port: u16,
    #[clap(long, short = 'l', help = "Set the log level", default_value = "info")]
    log_level: Level,
}

#[instrument]
#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    let relay_config: MockRelay = MockRelay::parse();
    let log_level: LevelFilter = relay_config.log_level.into();

    // Initialize logging.
    color_eyre::install()?;
    tracing_subscriber::Registry::default()
        .with(tracing_subscriber::fmt::layer().with_filter(log_level))
        .with(ErrorLayer::default())
        .init();

    tracing::info!("Starting mock relay");


    let url = SensitiveUrl::parse(relay_config.execution_endpoint.as_str())
        .map_err(|e| eyre!(format!("{e:?}")))?;
    let null_logger = sloggers::null::NullLoggerBuilder.build().unwrap();
    let (shutdown_tx, shutdown_rx) = futures_channel::mpsc::channel::<ShutdownReason>(1);
    let (signal, exit) = exit_future::signal();
    let task_executor = task_executor::TaskExecutor::new(tokio::runtime::Handle::current(), exit, null_logger.clone(), shutdown_tx);

    let mut config = Config {
        execution_endpoints: vec![url],
        secret_files: vec![relay_config.jwt_secret],
        ..Default::default()
    };

    let el = execution_layer::ExecutionLayer::<MainnetEthSpec>::from_config(config, task_executor, null_logger).unwrap();

    let beacon_url = SensitiveUrl::parse(relay_config.beacon_node.as_str())
        .map_err(|e| eyre!(format!("{e:?}")))?;
    let beacon_client = eth2::BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(Duration::from_secs(12)));

    let mock_builder = execution_layer::test_utils::MockBuilder::new(el, beacon_client, ChainSpec::mainnet(), MockBuilderContext::default());

    ApiServer::new(relay_config.address, relay_config.port, mock_builder).run().await;

    tracing::info!("Shutdown complete.");

    Ok(())
}

