use std::collections::{HashMap};

use candid::{CandidType, Deserialize, Nat};

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct BridgeAction<T: CandidType> {
    pub action_id: Nat,
    pub inner: T,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UpdatePrice {
    pub new_data: HashMap<u16, Nat>,
}


#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UpdateGroupKey {
    pub gk: [u8; 32]
}