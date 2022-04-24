use ic_cdk::{
    export::{
        candid::{CandidType, Deserialize, Nat, Encode, types::{Type, Compound}},
        Principal
    }
};
use serde_big_array::BigArray;
use sha2::{Sha512, Digest};
use ed25519_compact::{PublicKey, Signature};
use std::cell::RefCell;
use std::collections::BTreeSet;

#[ic_cdk_macros::import(canister = "xpnft")]
struct XpWrapNft;

type ActionIdStore = BTreeSet<Nat>;


#[derive(Deserialize, Clone, Debug, PartialEq)]
struct Sig(
    #[serde(with = "BigArray")]
    [u8; 64]
);

impl CandidType for Sig {
    fn _ty() -> Type { Type::Vec(Box::new(u8::ty())) }
    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
            S: candid::types::Serializer {
        let mut ser = serializer.serialize_vec(64)?;
        for e in self.0.iter() {
            Compound::serialize_element(&mut ser, &e)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct ValidateTransferNft {
    pub token_url: String,
    pub to: Principal
}

#[derive(Clone, Debug, CandidType)]
struct BridgeAction<T: CandidType> {
    pub chain_nonce: u64,
    pub sc_addr: Principal,
    pub action_id: Nat,
    pub inner: T
}

impl<T: CandidType> BridgeAction<T> {
    pub fn new(action_id: Nat, inner: T) -> Self {
        let conf = unsafe { CONFIG.as_ref().unwrap() };
        Self {
            chain_nonce: conf.chain_nonce,
            sc_addr: ic_cdk::id(),
            action_id,
            inner
        }
    } 
}

#[derive(Clone, Debug, CandidType)]
struct Config {
    group_key: [u8; 32],
    event_cnt: Nat,
    paused: bool,
    chain_nonce: u64
}

#[derive(CandidType)]
pub enum BridgeError {
    DuplicateAction,
    InvalidSignature,
    BridgePaused
}

static mut CONFIG: Option<Config> = None;

thread_local! {
    static ACTIONID_STORE: RefCell<ActionIdStore> = RefCell::default();
}

fn require_sig(
    action_id: Nat,
    sig: [u8; 64],
    context: &[u8],
    inner: impl CandidType
) -> Result<(), BridgeError> {
    ACTIONID_STORE.with(|action_store| {
        if !action_store
            .borrow_mut()
            .insert(action_id.clone()) {
                return Err(BridgeError::DuplicateAction);
        }
        Ok(())
    })?;
    let raw_act = Encode!(&BridgeAction::new(action_id, inner)).unwrap();

    let mut hasher = Sha512::new();
    hasher.update(context);
    hasher.update(&raw_act);
    let hash = hasher.finalize();

    let sig = Signature::new(sig);
    let key = PublicKey::new(unsafe { CONFIG.as_ref().unwrap().group_key.clone() });
    key.verify(hash, &sig).map_err(|_| BridgeError::InvalidSignature)?;

    Ok(())
}

fn require_unpause() -> Result<(), BridgeError> {
    if unsafe{
        CONFIG.as_ref().unwrap()
        .paused
    } {
        return Err(BridgeError::BridgePaused);
    }

    return Ok(());
}

#[ic_cdk_macros::init]
fn init(
    group_key: [u8; 32],
    chain_nonce: u64
) {
    unsafe {
        CONFIG = Some(Config {
            group_key,
            chain_nonce,
            paused: false,
            event_cnt: Nat::from(0)
        });
    }
}

#[ic_cdk_macros::update]
async fn validate_transfer_nft(action_id: Nat, action: ValidateTransferNft, sig: Sig) -> Result<Nat, BridgeError> {
    require_unpause()?;
    require_sig(action_id, sig.0, b"ValidateTransferNft", action.clone())?;

    Ok(XpWrapNft::mint(action.token_url, action.to.to_string()).await.0)
}
