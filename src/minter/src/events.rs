use candid::{Nat, Principal, CandidType};


#[derive(CandidType)]
pub struct BridgeEventCtx {
    pub action_id: Nat,
    pub chain_nonce: u64,
    pub tx_fees: Nat,
    pub to: String
}

#[derive(CandidType)]
pub struct TransferNft {
    pub token_id: Nat,
    pub dip721_contract: Principal,
    pub token_data: String,
    pub mint_with: String
}

#[derive(CandidType)]
pub struct UnfreezeNft {
    pub token_id: Nat,
    pub burner: Principal,
    pub uri: String
}

#[derive(CandidType)]
pub struct TransferNftBatch {
    pub token_ids: Vec<Nat>,
    pub dip721_contract: Principal,
    pub token_datas: Vec<String>,
    pub mint_with: String
}

#[derive(CandidType)]
pub struct UnfreezeNftBatch {
    pub token_ids: Vec<Nat>,
    pub burner: Principal,
    pub uris: Vec<String>
}

#[derive(CandidType)]
pub enum BridgeEvent {
    TransferNft(TransferNft),
    TransferNftBatch(TransferNftBatch),
    UnfreezeNft(UnfreezeNft),
    UnfreezeNftBatch(UnfreezeNftBatch)
}