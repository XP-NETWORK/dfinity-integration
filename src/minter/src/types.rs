pub mod motoko_types {
    use candid::CandidType;
    use serde::Deserialize;
    #[derive(Clone, Debug, CandidType, Deserialize)]
    pub enum MotokoResult<O, E> {
        #[serde(rename = "ok")]
        Ok(O),
        #[serde(rename = "err")]
        Err(E),
    }
}

pub mod ext_types {

    use candid::CandidType;
    use candid::Nat;
    use candid::Principal;
    use ic_ledger_types::Subaccount;
    use serde::Deserialize;
    use serde::Serialize;

    #[derive(Clone, Debug, CandidType)]
    pub struct MintRequest {
        pub to: User,
        pub metadata: Option<Vec<u8>>,
    }
    #[derive(Clone, Debug, CandidType)]
    pub struct TransferRequest {
        pub to: User,
        pub from: User,
        pub token: String,
        pub amount: Nat,
        pub memo: Vec<u8>,
        pub notify: bool,
        pub subaccount: Option<Subaccount>,
    }

    #[derive(Clone, Debug, CandidType, Deserialize)]
    pub enum TransferResponseErrors {
        Unauthorized(String),
        InsufficientBalance,
        Rejected, //Rejected by canister
        InvalidToken(String),
        CannotNotify(String),
        Other(String),
    }

    #[derive(Clone, Debug, CandidType, Deserialize)]
    pub enum User {
        #[serde(rename = "address")]
        Address(String),
        #[serde(rename = "principal")]
        Principal(Principal),
    }

    #[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
    pub enum Metadata {
        #[serde(rename = "nonfungible")]
        NonFungible { metadata: Option<Vec<u8>> },
        #[serde(rename = "fungible")]
        Fungible {
            decimals: u8,
            metadata: Option<Vec<u8>>,
            name: String,
            symbol: String,
        },
    }
    #[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
    pub enum CommonError {
        InvalidToken(String),
        Other(String),
    }
}
