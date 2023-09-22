use candid::{CandidType, Deserialize, Nat, Principal};

use crate::types::icrc7::MintArgs;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateTransferNft {
    pub token_url: String,
    pub mint_with: Principal,
    pub id: u128,
    pub mint_args: MintArgs,
    pub to: Principal,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateTransferNftBatch {
    pub mint_with: Vec<Principal>,
    pub ids: Vec<u128>,
    pub mint_args: Vec<MintArgs>,
    pub to: Principal,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateSetPause {
    pub pause: bool,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateSetGroupKey {
    pub group_key: [u8; 32],
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateWithdrawFees {
    pub to: Principal,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateUnfreezeNft {
    pub to: Principal,
    pub dip_contract: Principal,
    pub token_id: u128,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateUnfreezeNftBatch {
    pub to: Principal,
    pub dip_contracts: Vec<Principal>,
    pub token_ids: Vec<u128>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateWhitelistDip721 {
    pub dip_contract: Principal,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateCleanLogs {
    pub action_id: Nat,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct BridgeAction<T: CandidType> {
    pub chain_nonce: u64,
    pub sc_addr: Principal,
    pub action_id: Nat,
    pub inner: T,
}
