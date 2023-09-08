use crate::payload_cache::PayloadCache;
use crate::{convert_err, custom_err, from_ssz_rs, to_ssz_rs};
use async_trait::async_trait;
use eth2::types::{
    BlindedPayloadCapella, BlindedPayloadDeneb, BlindedPayloadMerge, BlockId, ExecutionPayload,
    ExecutionPayloadAndBlobs, FullPayloadContents, StateId,
};
use eth2::BeaconNodeHttpClient;
use ethereum_consensus::crypto::SecretKey;
use ethereum_consensus::primitives::BlsPublicKey;
pub use ethereum_consensus::state_transition::Context;
use execution_layer::ExecutionLayer;
use futures::future;
use mev_rs::{
    signing::{sign_builder_message, verify_signed_builder_message},
    types::{
        BidRequest, ExecutionPayload as ServerPayload, SignedBlindedBeaconBlock, SignedBuilderBid,
        SignedValidatorRegistration,
    },
    {BlindedBlockProvider, Error as MevError},
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use types::{
    map_blinded_payload_ref, Address, BlindedPayloadRef, ChainSpec, EthSpec, ExecPayload,
    ExecutionPayloadCapella, ExecutionPayloadDeneb, ExecutionPayloadHeaderCapella,
    ExecutionPayloadHeaderDeneb, ExecutionPayloadHeaderMerge, ExecutionPayloadMerge,
    ExecutionPayloadRef, ForkName, Uint256,
};

const DEFAULT_GAS_LIMIT: u64 = 30_000_000;
const DEFAULT_BUILDER_PAYLOAD_VALUE_WEI: u64 = 20_000_000_000_000_000;

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
    ) -> Result<(), MevError> {
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

    async fn fetch_best_bid(&self, bid_request: &BidRequest) -> Result<SignedBuilderBid, MevError> {
        let slot = bid_request.slot;

        let fork_name = self.spec.fork_name_at_slot::<E>(slot.into());
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
                            custom_err(
                                "missing registration and no default fee recipient set".to_string(),
                            )
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

        let (prev_randao_res, parent_block_res, withdrawals_res) = future::join3(
            async {
                self.beacon_client
                    .get_beacon_states_randao(StateId::Head, None)
                    .await
                    .map(|res| {
                        Ok::<_, MevError>(
                            res.ok_or_else(|| {
                                custom_err("no prev_randao returned from BN".to_string())
                            })?
                            .data
                            .randao,
                        )
                    })
                    .map_err(|e| custom_err(format!("unable to fetch prev_randao from BN: {e:?}")))
            },
            async {
                self.beacon_client
                    .get_beacon_blinded_blocks_ssz::<E>(BlockId::Head, &self.spec)
                    .await
                    .map_err(|e| {
                        custom_err(format!("unable to get previous block from BN: {e:?}"))
                    })?
                    .ok_or_else(|| custom_err("head block missing from BN".to_string()))
            },
            async {
                match fork_name {
                    ForkName::Base | ForkName::Altair | ForkName::Merge => Ok(None),
                    ForkName::Capella | ForkName::Deneb => self
                        .beacon_client
                        .get_expected_withdrawals(&StateId::Head)
                        .await
                        .map_err(|e| {
                            custom_err(format!("unable to get withdrawals from BN: {e:?}"))
                        })
                        .map(Some),
                }
            },
        )
        .await;
        let prev_randao = prev_randao_res??;
        let parent_block = parent_block_res?;
        let withdrawals_opt = withdrawals_res?;

        tracing::info!("slot {slot}: obtained parameters from BN");

        let parent_hash = from_ssz_rs(&bid_request.parent_hash)?;
        let parent_payload_header = parent_block.message().body().execution_payload().unwrap();

        if parent_payload_header.block_hash() != parent_hash {
            return Err(custom_err(format!(
                "parent hash mismatch, BN: {:?} vs request: {:?}",
                parent_payload_header.block_hash(),
                parent_hash
            )));
        }

        if parent_block.slot() >= slot {
            return Err(custom_err(format!(
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

        // Use the base fee from the previous block as it should remain unchanged (no transactions).
        let base_fee_per_gas = get_base_fee_per_gas(parent_payload_header);

        match fork_name {
            ForkName::Merge => {
                let mut payload = ExecutionPayloadMerge {
                    parent_hash,
                    timestamp,
                    fee_recipient,
                    prev_randao,
                    block_number,
                    gas_limit,
                    base_fee_per_gas,
                    ..Default::default()
                };

                payload.block_hash = ExecutionLayer::calculate_execution_block_hash(
                    ExecutionPayloadRef::Merge(&payload),
                    parent_block.canonical_root(),
                )
                .0;

                self.payload_cache
                    .put(FullPayloadContents::Payload(ExecutionPayload::Merge(
                        payload.clone(),
                    )));

                let header: ExecutionPayloadHeaderMerge<E> = (&payload).into();

                let mut message = mev_rs::types::bellatrix::BuilderBid {
                    header: to_ssz_rs(&header)?,
                    value: ssz_rs::U256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI),
                    public_key: self.builder_sk.public_key(),
                };

                let signature =
                    sign_builder_message(&mut message, &self.builder_sk, self.context.as_ref())?;
                let signed_bid =
                    SignedBuilderBid::Bellatrix(mev_rs::types::bellatrix::SignedBuilderBid {
                        message,
                        signature,
                    });
                Ok(signed_bid)
            }
            ForkName::Capella => {
                let mut payload = ExecutionPayloadCapella {
                    parent_hash,
                    timestamp,
                    fee_recipient,
                    prev_randao,
                    block_number,
                    gas_limit,
                    base_fee_per_gas,
                    withdrawals: withdrawals_opt
                        .ok_or(custom_err(
                            "withdrawals required during capella".to_string(),
                        ))?
                        .data
                        .into(),
                    ..Default::default()
                };

                payload.block_hash = ExecutionLayer::calculate_execution_block_hash(
                    ExecutionPayloadRef::Capella(&payload),
                    parent_block.canonical_root(),
                )
                .0;

                self.payload_cache
                    .put(FullPayloadContents::Payload(ExecutionPayload::Capella(
                        payload.clone(),
                    )));

                let header: ExecutionPayloadHeaderCapella<E> = (&payload).into();

                let mut message = mev_rs::types::capella::BuilderBid {
                    header: to_ssz_rs(&header)?,
                    value: ssz_rs::U256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI),
                    public_key: self.builder_sk.public_key(),
                };

                let signature =
                    sign_builder_message(&mut message, &self.builder_sk, self.context.as_ref())?;
                let signed_bid =
                    SignedBuilderBid::Capella(mev_rs::types::capella::SignedBuilderBid {
                        message,
                        signature,
                    });
                Ok(signed_bid)
            }
            ForkName::Deneb => {
                let mut payload = ExecutionPayloadDeneb {
                    parent_hash,
                    timestamp,
                    fee_recipient,
                    prev_randao,
                    block_number,
                    gas_limit,
                    base_fee_per_gas,
                    withdrawals: withdrawals_opt
                        .ok_or(custom_err("withdrawals required during deneb".to_string()))?
                        .data
                        .into(),
                    ..Default::default()
                };

                payload.block_hash = ExecutionLayer::calculate_execution_block_hash(
                    ExecutionPayloadRef::Deneb(&payload),
                    parent_block.canonical_root(),
                )
                .0;

                self.payload_cache.put(FullPayloadContents::PayloadAndBlobs(
                    ExecutionPayloadAndBlobs {
                        execution_payload: ExecutionPayload::Deneb(payload.clone()),
                        blobs_bundle: <_>::default(),
                    },
                ));

                let header: ExecutionPayloadHeaderDeneb<E> = (&payload).into();

                let mut message = mev_rs::types::deneb::BuilderBid {
                    header: to_ssz_rs(&header)?,
                    blinded_blobs_bundle: <_>::default(),
                    value: ssz_rs::U256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI),
                    public_key: self.builder_sk.public_key(),
                };

                let signature =
                    sign_builder_message(&mut message, &self.builder_sk, self.context.as_ref())?;
                let signed_bid = SignedBuilderBid::Deneb(mev_rs::types::deneb::SignedBuilderBid {
                    message,
                    signature,
                });
                Ok(signed_bid)
            }
            _ => return Err(custom_err("fork not supported".to_string())),
        }
    }

    async fn open_bid(
        &self,
        signed_block: &mut SignedBlindedBeaconBlock,
    ) -> Result<ServerPayload, MevError> {
        let root = from_ssz_rs(signed_block.block_hash())?;
        let full_payload_contents = self
            .payload_cache
            .pop(&root)
            .ok_or(convert_err("payload cache miss"))?;
        match full_payload_contents.payload_ref() {
            ExecutionPayload::Merge(_) => {
                Ok(ServerPayload::Bellatrix(to_ssz_rs(&full_payload_contents)?))
            }
            ExecutionPayload::Capella(_) => {
                Ok(ServerPayload::Capella(to_ssz_rs(&full_payload_contents)?))
            }
            ExecutionPayload::Deneb(_) => {
                Ok(ServerPayload::Deneb(to_ssz_rs(&full_payload_contents)?))
            }
        }
    }
}

fn get_base_fee_per_gas<'a, E: EthSpec>(payload_header: BlindedPayloadRef<'a, E>) -> Uint256 {
    map_blinded_payload_ref!(&'a _, payload_header, |payload, cons| {
        cons(payload);
        payload.execution_payload_header.base_fee_per_gas
    })
}
