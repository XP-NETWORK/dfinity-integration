mod actions;
use crate::actions::*;

use ic_cdk::{
    export::{
        candid::{CandidType, Deserialize, Nat, Encode, types::{Type, Compound}},
        Principal
    }
};
//use ic_ledger_types::{TransferArgs, Memo};
use serde_big_array::BigArray;
use sha2::{Sha512, Digest};
use ed25519_compact::{PublicKey, Signature};
use std::{cell::RefCell, thread::LocalKey};
use std::collections::BTreeSet;

#[ic_cdk_macros::import(canister = "xpnft")]
struct XpWrapNft;

type ActionIdStore = BTreeSet<Nat>;
type WhitelistStore = BTreeSet<Principal>;

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
    BridgePaused,
    FeeTransferFailure
}

static mut CONFIG: Option<Config> = None;

fn config_mut() -> &'static mut Config {
    return unsafe {
        CONFIG.as_mut().unwrap()
    }
}

fn config_ref() -> &'static Config {
    return unsafe {
        CONFIG.as_ref().unwrap()
    }
}

thread_local! {
    static ACTIONID_STORE: RefCell<ActionIdStore> = RefCell::default();
    static ACTIONID_STORE_CONFIG: RefCell<ActionIdStore> = RefCell::default();
}

fn require_sig_i(
    store: &'static LocalKey<RefCell<ActionIdStore>>,
    action_id: Nat,
    sig: [u8; 64],
    context: &[u8],
    inner: impl CandidType
) -> Result<(), BridgeError> {
    store.with(|action_store| {
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
    let key = PublicKey::new(config_ref().group_key.clone());
    key.verify(hash, &sig).map_err(|_| BridgeError::InvalidSignature)?;

    Ok(())
}

fn require_sig(
    action_id: Nat,
    sig: [u8; 64],
    context: &[u8],
    inner: impl CandidType
) -> Result<(), BridgeError> {
    require_sig_i(&ACTIONID_STORE, action_id, sig, context, inner)
}

fn require_sig_config(
    action_id: Nat,
    sig: [u8; 64],
    context: &[u8],
    inner: impl CandidType
) -> Result<(), BridgeError> {
    require_sig_i(&ACTIONID_STORE_CONFIG, action_id, sig, context, inner)
}

fn require_unpause() -> Result<(), BridgeError> {
    if config_ref().paused {
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
fn set_pause(action_id: Nat, action: ValidateSetPause, sig: Sig) -> Result<(), BridgeError> {
    require_sig_config(action_id, sig.0, b"ValidateSetPause", action.clone())?;
    config_mut().paused = action.pause;
    Ok(())
}

#[ic_cdk_macros::update]
fn set_group_key(action_id: Nat, action: ValidateSetGroupKey, sig: Sig) -> Result<(), BridgeError> {
    require_unpause()?;
    require_sig_config(action_id, sig.0, b"ValidateSetGroupKey", action.clone())?;

    config_mut().group_key = action.group_key;
    Ok(())

}

#[ic_cdk_macros::update]
async fn withdraw_fees(action_id: Nat, action: ValidateWithdrawFees, sig: Sig) -> Result<(), BridgeError> {
    require_unpause()?;
    require_sig_config(action_id, sig.0, b"ValidateWithdrawFees", action.clone())?;

    // TODO
    // let args = TransferArgs {
    //     memo: Memo(0),
    //     amount: Default::default(), // TODO
    //     fee: Default::default(), // TODO
    //     from_subaccount: None,
    //     to: action.to,
    //     created_at_time: None
    // };
    // ic_ledger_types::transfer(
    //     Default::default(), // TODO
    //     args
    // ).await.map_err(|_| BridgeError::FeeTransferFailure)?;

    Ok(())
}

#[ic_cdk_macros::update]
async fn validate_transfer_nft(action_id: Nat, action: ValidateTransferNft, sig: Sig) -> Result<Nat, BridgeError> {
    require_unpause()?;
    require_sig(action_id, sig.0, b"ValidateTransferNft", action.clone())?;

    Ok(XpWrapNft::mint(action.token_url, action.to.to_string()).await.0)
}

#[ic_cdk_macros::update]
async fn validate_unfreeze_nft(action_id: Nat, action: ValidateUnfreezeNft, sig: Sig) -> Result<(), BridgeError> {
    require_unpause()?;
    require_sig(action_id, sig.0, b"ValidateUnfreezeNft", action.clone())?;

    Ok(XpWrapNft::transferFrom(ic_cdk::id().as_slice().into(), action.to.as_slice().into(), action.token_id).await)
}

#[ic_cdk_macros::update]
async fn validate_transfer_nft_batch(action_id: Nat, action: ValidateTransferNftBatch, sig: Sig) -> Result<(), BridgeError> {
    require_unpause()?;
    require_sig(action_id, sig.0, b"ValidateTransferNftBatch", action.clone())?;

    for token_url in action.token_urls {
        XpWrapNft::mint(token_url, action.to.to_string()).await;
    }

    Ok(())
}

#[ic_cdk_macros::update]
async fn validate_unfreeze_nft_batch(action_id: Nat, action: ValidateUnfreezeNftBatch, sig: Sig) -> Result<(), BridgeError> {
    require_unpause()?;
    require_sig(action_id, sig.0, b"ValidateUnfreezeNftBatch", action.clone())?;

    let canister_id = ic_cdk::id().as_slice().to_owned();
    for token_id in action.token_ids {
        XpWrapNft::transferFrom(canister_id.clone(), action.to.as_slice().into(), token_id).await
    }

    Ok(())
}