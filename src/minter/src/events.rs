use std::{fmt, path::Display};

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

#[derive(Debug, Clone, CandidType)]
pub enum KeyType {
    FeeKey,
    BridgeGroupKey,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::FeeKey => write!(f, "fee_key"),
            KeyType::BridgeGroupKey => write!(f, "bridge_group_key"),
        }
    }
}

#[derive(Debug, Clone, CandidType)]
pub enum ValidatedEvent {
    ValidatedMint {
        mint_with: Principal,
        token_id: u32,
    },
    ValidatedUnfreeze {
        contract: Principal,
        token_id: Nat,
        to: Principal,
    },
    ValidatedMintBatch {
        mint_with: Vec<Principal>,
        token_ids: Vec<u32>,
    },
    ValidatedUnfreezeBatch {
        contracts: Vec<Principal>,
        token_ids: Vec<Nat>,
        to: Principal,
    },
    ValidatedPause {
        paused: bool,
    },
    ValidatedUpdateKey {
        key: [u8; 32],
        key_type: KeyType,
    },
    ValidatedFeeWithdraw {
        to: Principal,
        block_index: u64,
    },
}
