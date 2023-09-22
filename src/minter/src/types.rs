pub mod icrc7 {
    use candid::{CandidType, Int, Nat, Principal};
    use ic_ledger_types::Subaccount;
    use serde::{Deserialize, Serialize};
    use serde_bytes::ByteBuf;

    // Account representation of ledgers supporting the ICRC1 standard
    #[derive(Serialize, CandidType, Deserialize, Clone, Debug, Copy)]
    pub struct Account {
        pub owner: Principal,
        pub subaccount: Option<Subaccount>,
    }

    #[derive(CandidType, Clone)]
    pub enum TransferError {
        Unauthorized { tokens_ids: Vec<u128> },
        TooOld,
        CreatedInFuture { ledger_time: u64 },
        Duplicate { duplicate_of: u128 },
        TemporaryUnavailable,
        GenericError { error_code: u128, msg: String },
    }

    #[derive(CandidType, Deserialize)]
    pub struct TransferArgs {
        pub spender_subaccount: Option<Subaccount>,
        pub from: Account,
        pub to: Account,
        pub token_ids: Vec<u128>,
        pub memo: Option<Vec<u8>>,
        pub created_at_time: Option<u64>,
        pub is_atomic: Option<bool>,
    }

    #[derive(CandidType, Deserialize)]
    pub struct MintArgs {
        pub id: u128,
        pub name: String,
        pub description: Option<String>,
        pub image: Option<Vec<u8>>,
        pub to: Account,
        pub xp_metadata: Option<String>,
    }
    /// Variant type for the `metadata` endpoint values.
    #[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub enum MetadataValue {
        Nat(Nat),
        Int(Int),
        Text(String),
        Blob(ByteBuf),
    }

    pub struct ICRC7Metadata {
        pub id: u128,
        pub name: String,
        pub image: Option<ByteBuf>,
        pub description: Option<String>,
        pub xp_metadata: Option<String>,
    }
}
