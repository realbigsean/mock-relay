use clap::Parser;
use color_eyre::eyre::eyre;
use eth2::Timeouts;
use ethereum_consensus::state_transition::Context;
use execution_layer::Config;
use mev_build_rs::BlindedBlockProviderServer;
use mock_relay::{NoOpBuilder, NoOpConfig};
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
use types::{Address, ChainSpec, MainnetEthSpec};

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
            execution endpoint. Required unless used with `--empty-payloads`."
    )]
    jwt_secret: Option<PathBuf>,
    #[clap(long, help = "Address to listen on", default_value = "127.0.0.1")]
    address: Ipv4Addr,
    #[clap(long, help = "Port to listen on", default_value_t = 8650)]
    port: u16,
    #[clap(long, short = 'l', help = "Set the log level", default_value = "info")]
    log_level: Level,
    #[clap(long, short = 'n', help = "Ethereum network", possible_values = &["mainnet", "goerli", "sepolia"], default_value = "mainnet")]
    network: String,
    #[clap(
        long,
        short = 'e',
        help = "Adding this flag will cause the payload to be populated with \
        the minimal fields to be considered valid by the consensus layer, other fields will be defaulted."
    )]
    empty_payloads: bool,
    #[clap(
        long,
        help = "Fee recipient to use in case of missing registration.",
        requires("empty_payloads")
    )]
    default_fee_recipient: Option<Address>,
    #[clap(
        long,
        help = "0x-prefixed hex encoded bytes representing the `GENESIS_FORK_VERSION` field defined \
            in the consensus specs. Defaults to the correct value based on the provided network flag. \
            In order for valid signatures to be produced on non-default networks (e.g., shadowforks) \
            this flag must be used."
    )]
    genesis_fork_version: Option<String>,
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

    let beacon_url = SensitiveUrl::parse(relay_config.beacon_node.as_str())
        .map_err(|e| eyre!(format!("{e:?}")))?;
    let beacon_client =
        eth2::BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(Duration::from_secs(12)));

    let config = beacon_client
        .get_config_spec::<types::ConfigAndPreset>()
        .await
        .map_err(|e| eyre!(format!("{e:?}")))?;
    let mut spec = ChainSpec::from_config::<MainnetEthSpec>(config.data.config())
        .ok_or(eyre!("unable to parse chain spec from config"))?;
    let mut context = match relay_config.network.as_str() {
        "mainnet" => Context::for_mainnet(),
        "sepolia" => Context::for_sepolia(),
        "goerli" => Context::for_goerli(),
        _ => return Err(eyre!("invalid network")),
    };

    if let Some(genesis_fork_version) = relay_config.genesis_fork_version {
        let stripped = genesis_fork_version
            .strip_prefix("0x")
            .ok_or(eyre!("genesis fork version must be 0x-prefixed"))?;
        let bytes: [u8; 4] = hex::decode(stripped)?
            .try_into()
            .map_err(|_| eyre!("genesis fork version must be four bytes in length"))?;
        context.genesis_fork_version = bytes;
        spec.genesis_fork_version = bytes;
    };
    tracing::info!("Genesis fork version: 0x{}", hex::encode(context.genesis_fork_version));

    if relay_config.empty_payloads {
        let noop_config = NoOpConfig {
            default_fee_recipient: relay_config.default_fee_recipient,
        };
        let noop_builder: NoOpBuilder<MainnetEthSpec> =
            NoOpBuilder::new(beacon_client, spec, context, noop_config);
        tracing::info!("Initialized no-op builder");

        let pubkey = noop_builder.pubkey();
        tracing::info!("Builder pubkey: {pubkey:#x}");

        BlindedBlockProviderServer::new(relay_config.address, relay_config.port, noop_builder)
            .run()
            .await;
    } else {
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
            secret_files: vec![relay_config
                .jwt_secret
                .ok_or(eyre!("jwt secret required"))?],
            ..Default::default()
        };

        let el = execution_layer::ExecutionLayer::<MainnetEthSpec>::from_config(
            config,
            task_executor,
            log_root,
        )
        .map_err(|e| eyre!(format!("{e:?}")))?;

        let mock_builder =
            execution_layer::test_utils::MockBuilder::new(el, beacon_client, spec, context);
        tracing::info!("Initialized mock builder");

        let pubkey = mock_builder.pubkey();
        tracing::info!("Builder pubkey: {pubkey:#x}");

        BlindedBlockProviderServer::new(relay_config.address, relay_config.port, mock_builder)
            .run()
            .await;
    };

    tracing::info!("Shutdown complete.");

    Ok(())
}
