mod actions;
mod events;
use actions::*;
use events::*;

use ic_cdk::{
    export::{
        candid::{CandidType, Deserialize, Nat, Encode, types::{Type, Compound}},
        Principal
    }, api::call::{CallResult, RejectionCode}
};
//use ic_ledger_types::{TransferArgs, Memo};
use serde_big_array::BigArray;
use sha2::{Sha512, Digest};
use ed25519_compact::{PublicKey, Signature};
use std::{cell::RefCell, thread::LocalKey, collections::BTreeMap};
use std::collections::BTreeSet;

type ActionIdStore = BTreeSet<Nat>;
type WhitelistStore = BTreeSet<Principal>;
type EventStore = BTreeMap<Nat, (BridgeEventCtx, BridgeEvent)>;

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

impl BridgeEventCtx {
    pub fn new(chain_nonce: u64, to: String) -> Self {
        let conf = config_mut();
        let action_id = conf.event_cnt.clone();
        conf.event_cnt += Nat::from(1u32);

        // TODO: derive from cycles
        let tx_fees: Nat = 0u32.into();

        Self {
            action_id,
            chain_nonce,
            tx_fees,
            to
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
    FeeTransferFailure,
    NotWhitelisted,
    ExternalCall(i32, String)
}

impl From<(RejectionCode, String)> for BridgeError {
    fn from(e: (RejectionCode, String)) -> Self {
        return Self::ExternalCall(e.0 as i32, e.1)
    }
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
    static WHITELIST_STORE: RefCell<WhitelistStore> = RefCell::default();
    static EVENT_STORE: RefCell<EventStore> = RefCell::default();
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

fn require_whitelist(contract: Principal) -> Result<(), BridgeError> {
    if !WHITELIST_STORE.with(|whitelist| whitelist.borrow().contains(&contract)) {
        return Err(BridgeError::NotWhitelisted);
    }

    return Ok(());
}

fn add_event(ctx: BridgeEventCtx, ev: BridgeEvent) {
    EVENT_STORE.with(|store| store.borrow_mut().insert(ctx.action_id.clone(), (ctx, ev)));
}

async fn xpnft_mint(id: Principal, url: String, to: Principal) -> CallResult<(Nat,)> {
    ic_cdk::call(id, "mint", (url, to.to_string())).await
}

async fn xpnft_burn_for(id: Principal, for_acc: Principal, token_id: Nat) -> CallResult<()> {
    ic_cdk::call(id, "burn", (for_acc, token_id,)).await // TODO: add burn to xpnft
}

async fn dip721_token_uri(id: Principal, token_id: Nat) -> CallResult<(Option<String>,)> {
    ic_cdk::call(id, "tokenURI", (token_id,)).await
}

async fn dip721_transfer(id: Principal, from: Principal, to: Principal, token_id: Nat) -> CallResult<()> {
    ic_cdk::call(id, "transferFrom", 
    (
        from.as_slice().to_owned(),
        to.as_slice().to_owned(),
        token_id   
    )).await
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

    Ok(xpnft_mint(action.mint_with, action.token_url, action.to).await?.0)
}

#[ic_cdk_macros::update]
async fn validate_unfreeze_nft(action_id: Nat, action: ValidateUnfreezeNft, sig: Sig) -> Result<(), BridgeError> {
    require_unpause()?;
    require_sig(action_id, sig.0, b"ValidateUnfreezeNft", action.clone())?;

    Ok(dip721_transfer(action.dip_contract, ic_cdk::id(), action.to, action.token_id).await?)
}

#[ic_cdk_macros::update]
async fn validate_transfer_nft_batch(action_id: Nat, action: ValidateTransferNftBatch, sig: Sig) -> Result<(), BridgeError> {
    require_unpause()?;
    require_sig(action_id, sig.0, b"ValidateTransferNftBatch", action.clone())?;

    for (i, token_url) in action.token_urls.into_iter().enumerate() {
        xpnft_mint(action.mint_with[i], token_url, action.to).await?;
    }

    Ok(())
}

#[ic_cdk_macros::update]
async fn validate_unfreeze_nft_batch(action_id: Nat, action: ValidateUnfreezeNftBatch, sig: Sig) -> Result<(), BridgeError> {
    require_unpause()?;
    require_sig(action_id, sig.0, b"ValidateUnfreezeNftBatch", action.clone())?;

    let canister_id = ic_cdk::id();
    for (i, token_id) in action.token_ids.into_iter().enumerate() {
        dip721_transfer(action.dip_contracts[i], canister_id, action.to, token_id).await?;
    }

    Ok(())
}

#[ic_cdk_macros::update]
async fn freeze_nft(dip721_contract: Principal, token_id: Nat, chain_nonce: u64, to: String, mint_with: String) -> Result<(), BridgeError> {
    require_unpause()?;
    require_whitelist(dip721_contract)?;

    dip721_transfer(dip721_contract, ic_cdk::caller(), ic_cdk::id(), token_id.clone()).await?;
    let url = dip721_token_uri(dip721_contract, token_id.clone()).await?.0.unwrap();


    let ctx = BridgeEventCtx::new(chain_nonce, to);
    let ev = BridgeEvent::TransferNft(TransferNft {
        token_id,
        dip721_contract,
        token_data: url,
        mint_with
    });

    add_event(ctx, ev);

    Ok(())
}

#[ic_cdk_macros::update]
async fn freeze_nft_batch(dip721_contract: Principal, token_ids: Vec<Nat>, chain_nonce: u64, to: String, mint_with: String) -> Result<(), BridgeError> {
    require_unpause()?;
    require_whitelist(dip721_contract)?;

    let caller = ic_cdk::caller();
    let canister_id = ic_cdk::id();
    let mut urls = Vec::with_capacity(token_ids.len());
    for token_id in token_ids.clone() {
        urls.push(dip721_token_uri(dip721_contract, token_id.clone()).await?.0.unwrap());
        dip721_transfer(dip721_contract, caller, canister_id, token_id).await?;
    }

    let ctx = BridgeEventCtx::new(chain_nonce, to);
    let ev = BridgeEvent::TransferNftBatch(TransferNftBatch {
        token_ids,
        dip721_contract,
        token_datas: urls,
        mint_with
    });

    add_event(ctx, ev);

    Ok(())
}

#[ic_cdk_macros::update]
async fn withdraw_nft(burner: Principal, token_id: Nat, chain_nonce: u64, to: String) -> Result<(), BridgeError> {
    require_unpause()?;

    let url = dip721_token_uri(burner, token_id.clone()).await?.0.unwrap();
    xpnft_burn_for(burner, ic_cdk::caller(), token_id.clone()).await?;

    let ctx = BridgeEventCtx::new(chain_nonce, to);
    let ev = BridgeEvent::UnfreezeNft(UnfreezeNft {
        token_id,
        burner,
        uri: url
    });

    add_event(ctx, ev);

    Ok(())
}

#[ic_cdk_macros::update]
async fn withdraw_nft_batch(burner: Principal, token_ids: Vec<Nat>, chain_nonce: u64, to: String) -> Result<(), BridgeError> {
    require_unpause()?;

    let caller = ic_cdk::caller();
    let mut urls = Vec::with_capacity(token_ids.len());

    for token_id in token_ids.clone() {
        urls.push(dip721_token_uri(burner, token_id.clone()).await?.0.unwrap());
        xpnft_burn_for(burner, caller, token_id).await?;
    }

    let ctx = BridgeEventCtx::new(chain_nonce, to);
    let ev = BridgeEvent::UnfreezeNftBatch(UnfreezeNftBatch {
        token_ids,
        burner,
        uris: urls
    });

    add_event(ctx, ev);

    Ok(())
}