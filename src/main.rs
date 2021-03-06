use clap::Parser;
use color_eyre::eyre::eyre;
use eth2::Timeouts;
use execution_layer::test_utils::MockBuilderContext;
use execution_layer::Config;
use mev_build_rs::ApiServer;
use sensitive_url::SensitiveUrl;
use slog::Logger;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;
use task_executor::ShutdownReason;
use tracing::{instrument, Level};
use tracing_core::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber;
use tracing_subscriber::prelude::*;
use types::{ChainSpec, MainnetEthSpec};

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

    // Convert slog logs from the EL to tracing logs.
    let drain = tracing_slog::TracingSlogDrain;
    let log_root = Logger::root(drain, slog::o!());

    let (shutdown_tx, _shutdown_rx) = futures_channel::mpsc::channel::<ShutdownReason>(1);
    let (_signal, exit) = exit_future::signal();
    let task_executor = task_executor::TaskExecutor::new(
        tokio::runtime::Handle::current(),
        exit,
        log_root.clone(),
        shutdown_tx,
    );

    let config = Config {
        execution_endpoints: vec![url],
        secret_files: vec![relay_config.jwt_secret],
        ..Default::default()
    };

    let el = execution_layer::ExecutionLayer::<MainnetEthSpec>::from_config(
        config,
        task_executor,
        log_root,
    )
    .unwrap();

    let beacon_url = SensitiveUrl::parse(relay_config.beacon_node.as_str())
        .map_err(|e| eyre!(format!("{e:?}")))?;
    let beacon_client =
        eth2::BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(Duration::from_secs(12)));

    let config = beacon_client
        .get_config_spec()
        .await
        .map_err(|e| eyre!(format!("{e:?}")))?
        .data
        .config;
    let spec = ChainSpec::from_config::<MainnetEthSpec>(&config).unwrap();
    let mut context = MockBuilderContext::default();
    context.genesis_fork_version = spec.genesis_fork_version;

    let mock_builder =
        execution_layer::test_utils::MockBuilder::new(el, beacon_client, spec, context);

    ApiServer::new(relay_config.address, relay_config.port, mock_builder)
        .run()
        .await;

    tracing::info!("Shutdown complete.");

    Ok(())
}
