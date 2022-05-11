use candid::{Deserialize, CandidType, Principal, Nat};

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateTransferNft {
    pub token_url: String,
    pub mint_with: Principal,
    pub to: Principal
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateTransferNftBatch {
    pub token_urls: Vec<String>,
    pub mint_with: Vec<Principal>,
    pub to: Principal
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateSetPause {
    pub pause: bool
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateSetGroupKey {
    pub group_key: [u8; 32]
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateWithdrawFees {
    pub to: Principal
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateUnfreezeNft {
    pub to: Principal,
    pub dip_contract: Principal,
    pub token_id: Nat
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateUnfreezeNftBatch {
    pub to: Principal,
    pub dip_contracts: Vec<Principal>,
    pub token_ids: Vec<Nat>
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ValidateWhitelistDip721 {
    pub dip_contract: Principal
}

#[derive(Clone, Debug, CandidType)]
pub struct BridgeAction<T: CandidType> {
    pub chain_nonce: u64,
    pub sc_addr: Principal,
    pub action_id: Nat,
    pub inner: T
}