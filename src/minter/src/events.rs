use candid::{CandidType, Nat, Principal};

#[derive(Debug, Clone, CandidType, PartialEq)]
pub struct BridgeEventCtx {
    pub action_id: Nat,
    pub chain_nonce: u64,
    pub tx_fee: u64,
    pub to: String,
}

#[derive(Debug, Clone, CandidType, PartialEq)]
pub struct TransferNft {
    pub token_id: Nat,
    pub dip721_contract: Principal,
    pub token_data: String,
    pub mint_with: String,
    pub caller: Principal,
}

#[derive(Debug, Clone, CandidType, PartialEq)]
pub struct UnfreezeNft {
    pub token_id: Nat,
    pub burner: Principal,
    pub uri: String,
    pub caller: Principal,
}

#[derive(Debug, Clone, CandidType, PartialEq)]
pub struct TransferNftBatch {
    pub token_ids: Vec<Nat>,
    pub dip721_contract: Principal,
    pub token_datas: Vec<String>,
    pub mint_with: String,
    pub caller: Principal,
}

#[derive(Debug, Clone, CandidType, PartialEq)]
pub struct UnfreezeNftBatch {
    pub token_ids: Vec<Nat>,
    pub burner: Principal,
    pub uris: Vec<String>,
    pub caller: Principal,
}

#[derive(Debug, Clone, CandidType, PartialEq)]
pub enum BridgeEvent {
    TransferNft(TransferNft),
    TransferNftBatch(TransferNftBatch),
    UnfreezeNft(UnfreezeNft),
    UnfreezeNftBatch(UnfreezeNftBatch),
}
