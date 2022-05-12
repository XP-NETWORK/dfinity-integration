use candid::{CandidType, Principal, Deserialize};
use ic_cdk::api::call::CallResult;
use ic_ledger_types::{BlockIndex, Timestamp, Memo, AccountIdentifier, Tokens};

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum Operation {
    Mint {
        to: AccountIdentifier,
        amount: Tokens
    },
    Burn {
        from: AccountIdentifier,
        amount: Tokens
    },
    Transfer {
        from: AccountIdentifier,
        to: AccountIdentifier,
        amount: Tokens,
        fee: Tokens
    }
}


#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Transaction {
    pub memo: Memo,
    pub operation: Option<Operation>,
    pub created_at_time: Timestamp
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Block {
    pub parent_hash: Option<Vec<u8>>,
    pub transaction: Transaction,
    pub timestamp: Timestamp
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetBlockArgs {
    pub start: BlockIndex,
    pub length: u64
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ArchivedBlock {
    pub start: BlockIndex,
    pub length: u64,
    callback: usize, // This is a callback. I don't know the corresponding type in rust so I am reserving enough space for a function pointer
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct QueryBlocksResponse {
    pub chain_length: u64,
    pub certificate: Option<Vec<u8>>,
    pub blocks: Vec<Block>,
    pub first_block_index: BlockIndex,
    pub archived_blocks: Vec<ArchivedBlock>
}

pub async fn query_blocks(ledger_canister_id: Principal, args: GetBlockArgs) -> CallResult<QueryBlocksResponse> {
    let (blocks,) = ic_cdk::call(ledger_canister_id, "query_blocks", (args,)).await?;
    Ok(blocks)
}