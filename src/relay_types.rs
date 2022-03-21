use execution_layer::json_structures::JsonExecutionPayloadHeaderV1;
use serde_derive::{Deserialize, Serialize};
use types::{EthSpec, Signature, Uint256};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec", rename_all = "camelCase")]
pub struct SignedMEVPayloadHeader<T: EthSpec> {
    pub message: MEVPayloadHeader<T>,
    pub signature: Signature,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec", rename_all = "camelCase")]
pub struct MEVPayloadHeader<T: EthSpec> {
    pub payload_header: JsonExecutionPayloadHeaderV1<T>,
    pub fee_recipient_diff: Uint256,
}
