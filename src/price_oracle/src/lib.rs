#![feature(local_key_cell_methods)]
mod types;
use types::{BridgeAction, UpdatePrice, UpdateGroupKey};


use candid::{candid_method};

use ed25519_compact::{PublicKey, Signature};
use ic_kit::{
    candid::{
        types::{Compound, Type},
        CandidType, Deserialize, Encode, Nat,
    },
};
use serde_big_array::BigArray;
use sha2::{Digest, Sha512};
use std::{cell::RefCell, collections::BTreeMap};

type DataStore = BTreeMap<u16, Nat>;

#[derive(Deserialize, Clone, Debug, PartialEq)]
struct Sig(#[serde(with = "BigArray")] [u8; 64]);

impl CandidType for Sig {
    fn _ty() -> Type {
        Type::Vec(Box::new(u8::ty()))
    }
    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        let mut ser = serializer.serialize_vec(64)?;
        for e in self.0.iter() {
            Compound::serialize_element(&mut ser, &e)?;
        }
        Ok(())
    }
}

impl<T: CandidType> BridgeAction<T> {
    pub fn new(action_id: Nat, inner: T) -> Self {
        Self { action_id, inner }
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct Config {
    group_key: [u8; 32],
}

#[derive(Debug, CandidType)]
pub enum BridgeError {
    DuplicateAction,
    InvalidSignature,
    BridgePaused,
    FeeTransferFailure,
    FailedToQueryFee(String),
    NotWhitelisted,
    InvalidFee,
    ExternalCall(i32, String),
}

static mut CONFIG: Option<Config> = None;

/// Gets a mutable reference to {Config}
fn config_mut() -> &'static mut Config {
    return unsafe { CONFIG.as_mut().unwrap() };
}

/// Gets a unreadable reference to {Config}
fn config_ref() -> &'static Config {
    return unsafe { CONFIG.as_ref().unwrap() };
}

thread_local! {
    static PRICE_DATA_STORE: RefCell<DataStore> = RefCell::default();
    static DECIMAL_DATA_STORE: RefCell<DataStore> = RefCell::default();
    static TX_FEE_DATA_STORE: RefCell<DataStore> = RefCell::default();
    static OTHER_FEE_DATA_STORE: RefCell<DataStore> = RefCell::default();
}

/// Checks if the signature is correctly signed by the correct
/// private key and makes sure the action id is not a duplicate.
fn require_sig_i(
    action_id: Nat,
    sig: [u8; 64],
    context: &[u8],
    inner: impl CandidType,
) -> Result<(), BridgeError> {
    let raw_act = Encode!(&BridgeAction::new(action_id, inner)).unwrap();

    let mut hasher = Sha512::new();
    hasher.update(context);
    hasher.update(&raw_act);
    let hash = hasher.finalize();

    let sig = Signature::new(sig);
    let key = PublicKey::new(config_ref().group_key);
    key.verify(hash, &sig)
        .map_err(|_| BridgeError::InvalidSignature)?;

    Ok(())
}

fn require_sig(
    action_id: Nat,
    sig: [u8; 64],
    context: &[u8],
    inner: impl CandidType,
) -> Result<(), BridgeError> {
    require_sig_i(action_id, sig, context, inner)
}

#[ic_kit::macros::init]
#[candid_method(init)]
pub(crate) fn init(group_key: [u8; 32]) {
    unsafe {
        CONFIG = Some(Config { group_key });
    }
}

#[ic_kit::macros::update]
#[candid_method(update)]
pub(crate) fn validate_update_price(data: BridgeAction<UpdatePrice>, sig: Sig) {
    require_sig(
        data.action_id.clone(),
        sig.0,
        b"UpdateData",
        data.inner.clone(),
    )
    .unwrap();

    PRICE_DATA_STORE.with(|v| {
        let mut store = v.borrow_mut();
        store.extend(data.inner.new_data)
    });
}

#[ic_kit::macros::update]
#[candid_method(update)]
pub(crate) fn validate_update_decimal(data: BridgeAction<UpdatePrice>, sig: Sig) {
    require_sig(
        data.action_id.clone(),
        sig.0,
        b"UpdateData",
        data.inner.clone(),
    )
    .unwrap();

    DECIMAL_DATA_STORE.with(|v| {
        let mut store = v.borrow_mut();
        store.extend(data.inner.new_data)
    });
}

#[ic_kit::macros::update]
#[candid_method(update)]
pub(crate) fn validate_update_tx_fee(data: BridgeAction<UpdatePrice>, sig: Sig) {
    require_sig(
        data.action_id.clone(),
        sig.0,
        b"UpdateData",
        data.inner.clone(),
    )
    .unwrap();

    TX_FEE_DATA_STORE.with(|v| {
        let mut store = v.borrow_mut();
        store.extend(data.inner.new_data)
    });
}

#[ic_kit::macros::update]
#[candid_method(update)]
pub(crate) fn validate_update_group_key(data: BridgeAction<UpdateGroupKey>, sig: Sig) {
    require_sig(
        data.action_id.clone(),
        sig.0,
        b"UpdateGroupKey",
        data.inner.clone(),
    )
    .unwrap();

    config_mut().group_key = data.inner.gk;
}

#[ic_kit::macros::update]
#[candid_method(update)]
pub(crate) fn validate_update_other_fee(data: BridgeAction<UpdatePrice>, sig: Sig) {
    require_sig(
        data.action_id.clone(),
        sig.0,
        b"UpdateData",
        data.inner.clone(),
    )
    .unwrap();

    OTHER_FEE_DATA_STORE.with(|v| {
        let mut store = v.borrow_mut();
        store.extend(data.inner.new_data)
    });
}

#[ic_kit::macros::query]
#[candid_method(query)]
pub(crate) fn estimate_gas(from: u16, to: u16) -> Option<Nat> {
    let from_dec = DECIMAL_DATA_STORE.with_borrow(|dec_store| {
        dec_store
            .get(&from)
            .expect("Failed to get decimal data for from chain")
            .clone()
    });
    let to_dec = DECIMAL_DATA_STORE.with_borrow(|dec_store| {
        dec_store
            .get(&to)
            .expect("Failed to get decimal data for to chain")
            .clone()
    });

    let from_conv_rate = TX_FEE_DATA_STORE.with_borrow(|dec_store| {
        dec_store
            .get(&from)
            .expect("Failed to get conv data for from chain")
            .clone()
    });

    let to_conv_rate = TX_FEE_DATA_STORE.with_borrow(|dec_store| {
        dec_store
            .get(&to)
            .expect("Failed to get conv data for to chain")
            .clone()
    });

    let tx_fee = TX_FEE_DATA_STORE.with_borrow(|store| {
        store
            .get(&to)
            .expect("Failed to get tx fee for the to chain")
            .clone()
    });

    let other_fee =
        OTHER_FEE_DATA_STORE.with_borrow(|store| store.get(&to).unwrap_or(&Nat::from(0)).clone());

    let to_tx_fee = tx_fee + other_fee;

    let fee_in_usd = (to_tx_fee * to_conv_rate) / to_dec.clone();
    let fee_in_usd_with_commission = fee_in_usd + (to_dec.clone() / 2); // + 0.5 USD

    let fee_in_from_currency = (fee_in_usd_with_commission * from_dec.clone()) / from_conv_rate
        * (from_dec.clone() / to_dec.clone());

    Some(fee_in_from_currency)
}

#[ic_kit::macros::query(name = "get_price_data")]
pub(crate) fn get_price_data() -> DataStore {
    PRICE_DATA_STORE.with(|v| v.borrow().clone())
}

#[ic_kit::macros::query(name = "get_decimal_data")]
pub(crate) fn get_decimal_data() -> DataStore {
    DECIMAL_DATA_STORE.with(|v| v.borrow().clone())
}

#[ic_kit::macros::query(name = "get_tx_fee_data")]
pub(crate) fn get_tx_fee_data() -> DataStore {
    TX_FEE_DATA_STORE.with(|v| v.borrow().clone())
}

#[ic_kit::macros::query(name = "get_other_fee_data")]
pub(crate) fn get_other_fee_data() -> DataStore {
    OTHER_FEE_DATA_STORE.with(|v| v.borrow().clone())
}

#[ic_kit::macros::query(name = "get_group_key")]
pub(crate) fn get_group_key() -> [u8; 32] {
    config_ref().group_key.clone()
}

mod export_candid;