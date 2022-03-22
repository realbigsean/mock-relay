use crate::relay_types::{MEVPayloadHeader, SignedMEVPayloadHeader};
use clap::Parser;
use color_eyre::eyre;
use color_eyre::eyre::eyre;
use execution_layer::auth::{Auth, JwtKey};
use execution_layer::http::{
    ENGINE_FORKCHOICE_UPDATED_TIMEOUT, ENGINE_FORKCHOICE_UPDATED_V1, JSONRPC_VERSION,
};
use execution_layer::json_structures::{
    JsonExecutionPayloadHeaderV1, JsonExecutionPayloadV1, JsonForkchoiceUpdatedV1Response,
    JsonPayloadIdRequest,
};
use execution_layer::EngineApi;
use execution_layer::HttpJsonRpc;
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
use tracing::{instrument, Level};
use tracing_core::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber;
use tracing_subscriber::prelude::*;
use types::{
    BlindedPayload, ExecutionPayload, ExecutionPayloadHeader, Hash256, MainnetEthSpec, Signature,
    SignedBeaconBlock, Uint256,
};
use warp::Filter;

mod relay_types;

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

    // Setup auth for execution layer client.
    let auth_str = std::fs::read_to_string(relay_config.jwt_secret)?;
    let secret =
        JwtKey::from_slice(&hex::decode(strip_prefix(auth_str.as_str()))?).map_err(|e| eyre!(e))?;
    let auth = Auth::new(secret, None, None);
    let url = SensitiveUrl::parse(relay_config.execution_endpoint.as_str())
        .map_err(|e| eyre!(format!("{e:?}")))?;
    let client = HttpJsonRpc::new_with_auth(url, auth).map_err(|e| eyre!(format!("{e:?}")))?;

    let context = Arc::new(Context {
        listen_addr: relay_config.address,
        listen_port: relay_config.port,
        el_client: client,
        payload_cache: RwLock::new(LruCache::new(10)),
    });

    serve(context).await?;

    tracing::info!("Shutdown complete.");

    Ok(())
}

pub struct Context {
    pub listen_addr: Ipv4Addr,
    pub listen_port: u16,
    pub el_client: HttpJsonRpc,
    pub payload_cache: PayloadCache,
}

pub type PayloadCache =
    parking_lot::RwLock<lru::LruCache<Hash256, ExecutionPayload<MainnetEthSpec>>>;

pub async fn serve(ctx: Arc<Context>) -> Result<(), eyre::Error> {
    let inner_ctx = ctx.clone();
    let ctx_filter = warp::any().map(move || inner_ctx.clone());

    let root = warp::path::end()
        .and(warp::body::json())
        .and(ctx_filter.clone())
        .and_then(|body: serde_json::Value, ctx: Arc<Context>| async move {
            let id = body
                .get("id")
                .ok_or_else(|| warp::reject::custom(MissingIdField))?
                .clone();

            let response = match handle_relay_rpc(body, ctx).await {
                Ok(result) => json!({
                    "id": id,
                    "jsonrpc": JSONRPC_VERSION,
                    "result": result
                }),
                Err(message) => json!({
                    "id": id,
                    "jsonrpc": JSONRPC_VERSION,
                    "error": {
                        "code": -1234,   // Junk error code.
                        "message": format!("{message}")
                    }
                }),
            };

            Ok::<_, warp::reject::Rejection>(
                warp::http::Response::builder()
                    .status(200)
                    .body(serde_json::to_string(&response).expect("response must be valid JSON")),
            )
        });

    let routes = warp::post()
        .and(root)
        .recover(warp_utils::reject::handle_rejection)
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", "mock-relay-server"));

    let (listening_socket, server) = warp::serve(routes).try_bind_with_graceful_shutdown(
        SocketAddrV4::new(ctx.listen_addr, ctx.listen_port),
        async {
            tokio::signal::ctrl_c()
                .await
                .expect("Unable to listen for ctrl-c");
            tracing::info!("Shutting down...");
        },
    )?;

    tracing::info!(?listening_socket, "Mock relay HTTP server started");

    Ok(server.await)
}

pub async fn handle_relay_rpc(body: JsonValue, ctx: Arc<Context>) -> eyre::Result<JsonValue> {
    let method = body
        .get("method")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| eyre!("missing/invalid method field"))?;

    let params = body
        .get("params")
        .ok_or_else(|| eyre!("missing/invalid params field"))?;

    match method {
        "relay_getPayloadHeaderV1" => {
            let request: JsonPayloadIdRequest = get_param(params, 0)?;
            let id = request.into();

            let payload = ctx
                .el_client
                .get_payload_v1::<MainnetEthSpec>(id)
                .await
                .map_err(|e| eyre!(format!("{e:?}")))?;
            let payload_header = ExecutionPayloadHeader::<MainnetEthSpec>::from(&payload);

            let ExecutionPayloadHeader {
                parent_hash,
                fee_recipient,
                state_root,
                receipts_root,
                logs_bloom,
                prev_randao,
                block_number,
                gas_limit,
                gas_used,
                timestamp,
                extra_data,
                base_fee_per_gas,
                block_hash,
                transactions_root,
            } = payload_header;

            let json_payload_header = JsonExecutionPayloadHeaderV1::<MainnetEthSpec> {
                parent_hash,
                fee_recipient,
                state_root,
                receipts_root,
                logs_bloom,
                prev_randao,
                block_number,
                gas_limit,
                gas_used,
                timestamp,
                extra_data,
                base_fee_per_gas,
                block_hash,
                transactions_root,
            };

            let mev_payload_header = MEVPayloadHeader {
                payload_header: json_payload_header,
                fee_recipient_diff: Uint256::zero(),
            };

            let signed_mev_payload_header = SignedMEVPayloadHeader {
                message: mev_payload_header,
                signature: Signature::empty(),
            };

            // Cache the payload.
            ctx.payload_cache.write().put(transactions_root, payload);

            Ok(serde_json::to_value(signed_mev_payload_header)?)
        }
        "relay_proposeBlindedBlockV1" => {
            // Reveal the cached payload.
            let request_block: SignedBeaconBlock<MainnetEthSpec, BlindedPayload<MainnetEthSpec>> =
                get_param(params, 0)?;
            let _request_header: SignedMEVPayloadHeader<MainnetEthSpec> = get_param(params, 1)?;

            let tx_root = request_block
                .message()
                .body()
                .execution_payload()
                .map_err(|e| eyre!(format!("{e:?}")))?
                .execution_payload_header
                .transactions_root;
            let payload = ctx
                .payload_cache
                .write()
                .pop(&tx_root)
                .ok_or(eyre!("Missing payload for blinded block {request_block:?}"))?;

            Ok(serde_json::to_value(JsonExecutionPayloadV1::<
                MainnetEthSpec,
            >::from(payload))?)
        }
        ENGINE_FORKCHOICE_UPDATED_V1 => {
            let response: JsonForkchoiceUpdatedV1Response = ctx
                .el_client
                .rpc_request(
                    ENGINE_FORKCHOICE_UPDATED_V1,
                    params.clone(),
                    ENGINE_FORKCHOICE_UPDATED_TIMEOUT,
                )
                .await
                .map_err(|e| eyre!("{e:?}"))?;

            Ok(serde_json::to_value(response)?)
        }
        other => Err(eyre!(
            "The method {} does not exist/is not available",
            other
        )),
    }
}

fn get_param<T: DeserializeOwned>(params: &JsonValue, index: usize) -> eyre::Result<T> {
    params
        .get(index)
        .ok_or_else(|| eyre!("missing/invalid params[{}] value", index))
        .and_then(|param| {
            serde_json::from_value(param.clone())
                .map_err(|e| eyre!("failed to deserialize param[{}]: {:?}", index, e))
        })
}

#[derive(Debug)]
struct MissingIdField;

impl warp::reject::Reject for MissingIdField {}

fn strip_prefix(s: &str) -> &str {
    if let Some(stripped) = s.strip_prefix("0x") {
        stripped
    } else {
        s
    }
}
