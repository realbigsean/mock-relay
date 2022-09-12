use crate::{convert_err, from_ssz_rs, to_ssz_rs};
use async_trait::async_trait;
use eth2::types::{ExecPayload, ExecutionPayload, ExecutionPayloadHeader, FullPayload};
use eth2::BeaconNodeHttpClient;
use ethereum_consensus::crypto::SecretKey;
use ethereum_consensus::primitives::BlsPublicKey;
pub use ethereum_consensus::state_transition::Context;
use execution_layer::payload_cache::PayloadCache;
use execution_layer::test_utils::get_params;
use mev_build_rs::{
    sign_builder_message, verify_signed_builder_message, BidRequest, BlindedBlockProvider,
    BlindedBlockProviderError, BuilderBid, ExecutionPayload as ServerPayload,
    SignedBlindedBeaconBlock, SignedBuilderBid, SignedValidatorRegistration,
};
use parking_lot::RwLock;
use ssz_rs::Merkleized;
use std::collections::HashMap;
use std::sync::Arc;
use types::{Address, ChainSpec, EthSpec};

const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

#[derive(Clone)]
pub struct NoOpBuilder<E: EthSpec> {
    beacon_client: BeaconNodeHttpClient,
    spec: ChainSpec,
    context: Arc<Context>,
    payload_cache: Arc<PayloadCache<E>>,
    val_registration_cache: Arc<RwLock<HashMap<BlsPublicKey, SignedValidatorRegistration>>>,
    builder_sk: SecretKey,
    config: NoOpConfig,
}

#[derive(Clone)]
pub struct NoOpConfig {
    pub default_fee_recipient: Option<Address>,
}

impl<E: EthSpec> NoOpBuilder<E> {
    pub fn new(
        beacon_client: BeaconNodeHttpClient,
        spec: ChainSpec,
        context: Context,
        config: NoOpConfig,
    ) -> Self {
        let sk = SecretKey::random(&mut rand::thread_rng()).unwrap();
        Self {
            beacon_client,
            spec,
            context: Arc::new(context),
            val_registration_cache: Arc::new(RwLock::new(HashMap::new())),
            payload_cache: Arc::new(PayloadCache::default()),
            builder_sk: sk,
            config,
        }
    }

    pub fn pubkey(&self) -> BlsPublicKey {
        self.builder_sk.public_key()
    }
}

#[async_trait]
impl<E: EthSpec> BlindedBlockProvider for NoOpBuilder<E> {
    async fn register_validators(
        &self,
        registrations: &mut [SignedValidatorRegistration],
    ) -> Result<(), BlindedBlockProviderError> {
        for registration in registrations {
            let pubkey = registration.message.public_key.clone();
            let message = &mut registration.message;
            verify_signed_builder_message(
                message,
                &registration.signature,
                &pubkey,
                &self.context,
            )?;
            self.val_registration_cache.write().insert(
                registration.message.public_key.clone(),
                registration.clone(),
            );
        }

        Ok(())
    }

    async fn fetch_best_bid(
        &self,
        bid_request: &BidRequest,
    ) -> Result<SignedBuilderBid, BlindedBlockProviderError> {
        let (fee_recipient, gas_limit) = self
            .val_registration_cache
            .read()
            .get(&bid_request.public_key)
            .map_or_else(
                || {
                    self.config
                        .default_fee_recipient
                        .map(|fee_recipient| (fee_recipient, DEFAULT_GAS_LIMIT))
                        .ok_or_else(|| {
                            BlindedBlockProviderError::Custom(format!(
                                "missing registration and no default fee recipient set"
                            ))
                        })
                },
                |registration| {
                    let fee_recipient = from_ssz_rs(&registration.message.fee_recipient)?;
                    let gas_limit = registration.message.gas_limit;
                    Ok((fee_recipient, gas_limit))
                },
            )?;

        // FIXME(sproul): this takes 2s+ on Goerli
        //
        // really we just need:
        // - prev_randao (from head state)
        // - block_number (parent block + 1)
        tracing::info!("requesting parameters from BN");
        let (payload_attributes, _, block_number) =
            get_params::<E>(&self.beacon_client, bid_request, fee_recipient, &self.spec).await?;
        tracing::info!("obtained parameters from BN");

        let payload = FullPayload {
            execution_payload: ExecutionPayload {
                parent_hash: from_ssz_rs(&bid_request.parent_hash)?,
                timestamp: payload_attributes.timestamp,
                fee_recipient: fee_recipient,
                prev_randao: payload_attributes.prev_randao,
                block_number,
                gas_limit,
                ..Default::default()
            },
        };

        self.payload_cache.put(payload.execution_payload.clone());

        let header: ExecutionPayloadHeader<_> = payload.to_execution_payload_header();

        let mut message = BuilderBid {
            header: to_ssz_rs(&header)?,
            value: ssz_rs::U256::default(),
            public_key: self.builder_sk.public_key(),
        };

        let signature =
            sign_builder_message(&mut message, &self.builder_sk, self.context.as_ref())?;

        let signed_bid = SignedBuilderBid { message, signature };
        Ok(signed_bid)
    }

    async fn open_bid(
        &self,
        signed_block: &mut SignedBlindedBeaconBlock,
    ) -> Result<ServerPayload, BlindedBlockProviderError> {
        let root = from_ssz_rs(
            &signed_block
                .message
                .body
                .execution_payload_header
                .hash_tree_root()
                .map_err(convert_err)?,
        )?;
        let payload = self
            .payload_cache
            .pop(&root)
            .ok_or(convert_err("payload cache miss"))?;
        to_ssz_rs(&payload)
    }
}
