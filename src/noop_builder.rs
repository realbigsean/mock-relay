use crate::{convert_err, from_ssz_rs, to_ssz_rs};
use async_trait::async_trait;
use eth2::types::{
    BlockId, ExecPayload, ExecutionPayload, ExecutionPayloadHeader, FullPayload, StateId,
};
use eth2::BeaconNodeHttpClient;
use ethereum_consensus::crypto::SecretKey;
use ethereum_consensus::primitives::BlsPublicKey;
pub use ethereum_consensus::state_transition::Context;
use execution_layer::payload_cache::PayloadCache;
use futures::future;
use mev_build_rs::{
    sign_builder_message, verify_signed_builder_message, BidRequest, BlindedBlockProvider,
    BlindedBlockProviderError as Error, BuilderBid, ExecutionPayload as ServerPayload,
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
    ) -> Result<(), Error> {
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

    async fn fetch_best_bid(&self, bid_request: &BidRequest) -> Result<SignedBuilderBid, Error> {
        let slot = bid_request.slot;
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
                            Error::Custom(format!(
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

        // This is a bit racey because we might fetch the RANDAO from a different parent block,
        // however it is fast. With more states cached in memory we could use the state root
        // of the parent block for the RANDAO lookup, but right now with Lighthouse at least
        // this is too slow.
        tracing::info!("slot {slot}: requesting parameters from BN");

        let (prev_randao_res, parent_block_res) = future::join(
            async {
                self.beacon_client
                    .get_beacon_states_randao(StateId::Head, None)
                    .await
                    .map(|res| res.data.randao)
                    .map_err(|e| {
                        Error::Custom(format!("unable to fetch prev_randao from BN: {e:?}"))
                    })
            },
            async {
                self.beacon_client
                    .get_beacon_blinded_blocks_ssz::<E>(BlockId::Head, &self.spec)
                    .await
                    .map_err(|e| {
                        Error::Custom(format!("unable to get previous block from BN: {e:?}"))
                    })?
                    .ok_or_else(|| Error::Custom(format!("head block missing from BN")))
            },
        )
        .await;
        let prev_randao = prev_randao_res?;
        let parent_block = parent_block_res?;
        tracing::info!("slot {slot}: obtained parameters from BN");

        let parent_hash = from_ssz_rs(&bid_request.parent_hash)?;
        let parent_payload_header = parent_block.message().body().execution_payload().unwrap();

        if parent_payload_header.block_hash() != parent_hash {
            return Err(Error::Custom(format!(
                "parent hash mismatch, BN: {:?} vs request: {:?}",
                parent_payload_header.block_hash(),
                parent_hash
            )));
        }

        if parent_block.slot() >= slot {
            return Err(Error::Custom(format!(
                "incompatible parent slot, BN: {} vs request: {}",
                parent_block.slot(),
                slot
            )));
        }

        // Increment block number.
        let block_number = parent_payload_header.block_number() + 1;

        // Use the parent payload's timestamp to compute the new timestamp.
        let timestamp = parent_payload_header.timestamp()
            + (slot - parent_block.slot().as_u64()) * self.context.seconds_per_slot;

        let payload = FullPayload {
            execution_payload: ExecutionPayload {
                parent_hash,
                timestamp,
                fee_recipient,
                prev_randao,
                block_number,
                gas_limit,
                ..Default::default()
            },
        };

        self.payload_cache.put(payload.execution_payload.clone());

        let header: ExecutionPayloadHeader<_> = payload.to_execution_payload_header();

        let mut message = BuilderBid {
            header: to_ssz_rs(&header)?,
            value: ssz_rs::U256::from(1u64),
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
    ) -> Result<ServerPayload, Error> {
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
