mod actions;
mod events;
mod ledger;
mod types;
use actions::*;
use events::*;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use types::ext_types::*;
use types::motoko_types::*;

use ed25519_compact::{PublicKey, Signature};
use ic_kit::{
    candid::{
        types::{Compound, Type},
        CandidType, Deserialize, Encode, Nat,
    },
    CallResult, Principal, RejectionCode,
};
use ic_ledger_types::{
    AccountBalanceArgs, AccountIdentifier, BlockIndex, Memo, TransferArgs, DEFAULT_FEE,
    DEFAULT_SUBACCOUNT, MAINNET_LEDGER_CANISTER_ID,
};

use ledger::GetBlockArgs;
use serde_big_array::BigArray;
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;
use std::{cell::RefCell, collections::BTreeMap, thread::LocalKey};

type ActionIdStore = BTreeSet<Nat>;
type WhitelistStore = BTreeSet<Principal>;
type EventStore = BTreeMap<Nat, (BridgeEventCtx, BridgeEvent)>;
type FeeBlockStore = BTreeSet<BlockIndex>;

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
        let conf = unsafe { CONFIG.as_ref().unwrap() };
        Self {
            chain_nonce: conf.chain_nonce,
            sc_addr: ic_kit::ic::id(),
            action_id,
            inner,
        }
    }
}

impl BridgeEventCtx {
    pub fn new(tx_fee: u64, chain_nonce: u64, to: String) -> Self {
        let conf = config_mut();
        let action_id = conf.event_cnt.clone();
        conf.event_cnt += Nat::from(1u32);

        Self {
            action_id,
            chain_nonce,
            tx_fee,
            to,
        }
    }
}
#[derive(Clone, Debug, CandidType, Deserialize)]
struct Config {
    group_key: [u8; 32],
    event_cnt: Nat,
    paused: bool,
    chain_nonce: u64,
}

#[derive(Debug, CandidType)]
pub enum BridgeError {
    DuplicateAction,
    InvalidSignature,
    BridgePaused,
    FeeTransferFailure,
    NotWhitelisted,
    InvalidFee,
    ExternalCall(i32, String),
}

impl From<(RejectionCode, String)> for BridgeError {
    fn from(e: (RejectionCode, String)) -> Self {
        return Self::ExternalCall(e.0 as i32, e.1);
    }
}

static mut CONFIG: Option<Config> = None;

fn config_mut() -> &'static mut Config {
    return unsafe { CONFIG.as_mut().unwrap() };
}

fn config_ref() -> &'static Config {
    return unsafe { CONFIG.as_ref().unwrap() };
}

thread_local! {
    static ACTIONID_STORE: RefCell<ActionIdStore> = RefCell::default();
    static ACTIONID_STORE_CONFIG: RefCell<ActionIdStore> = RefCell::default();
    static WHITELIST_STORE: RefCell<WhitelistStore> = RefCell::default();
    static EVENT_STORE: RefCell<EventStore> = RefCell::default();
    static FEEBLOCK_STORE: RefCell<FeeBlockStore> = RefCell::default();
}

fn require_sig_i(
    store: &'static LocalKey<RefCell<ActionIdStore>>,
    action_id: Nat,
    sig: [u8; 64],
    context: &[u8],
    inner: impl CandidType,
) -> Result<(), BridgeError> {
    store.with(|action_store| {
        if !action_store.borrow_mut().insert(action_id.clone()) {
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
    require_sig_i(&ACTIONID_STORE, action_id, sig, context, inner)
}

fn require_sig_config(
    action_id: Nat,
    sig: [u8; 64],
    context: &[u8],
    inner: impl CandidType,
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

async fn require_tx_fee(
    canister_id: &Principal,
    caller: &Principal,
    fee_block: BlockIndex,
) -> Result<u64, BridgeError> {
    if FEEBLOCK_STORE.with(|store| store.borrow().contains(&fee_block)) {
        return Err(BridgeError::InvalidFee);
    }

    let caller_acc = AccountIdentifier::new(&caller, &DEFAULT_SUBACCOUNT);
    let canister_acc = AccountIdentifier::new(&canister_id, &DEFAULT_SUBACCOUNT);
    let query = GetBlockArgs {
        start: fee_block,
        length: 1,
    };
    let block_info = ledger::query_blocks(MAINNET_LEDGER_CANISTER_ID, query).await?;
    match block_info.blocks[0].transaction.operation {
        Some(ledger::Operation::Transfer {
            from, to, amount, ..
        }) if from == caller_acc && to == canister_acc => Ok(amount.e8s()),
        _ => Err(BridgeError::InvalidFee),
    }
}

fn add_event(ctx: BridgeEventCtx, ev: BridgeEvent) -> Nat {
    let action_id = ctx.action_id.clone();
    EVENT_STORE.with(|store| store.borrow_mut().insert(ctx.action_id.clone(), (ctx, ev)));
    action_id
}
/// It makes an external call to mint an nft (ext standard) to the given contract.
async fn xpnft_mint(id: Principal, url: String, to: Principal) -> CallResult<(u32,)> {
    ic_kit::ic::call(
        id,
        "mintNFT",
        (MintRequest {
            metadata: Some(url.as_bytes().to_vec()),
            to: User::Principal(to),
        },),
    )
    .await
}
/// It combines the token id and canister id to generate a token identifier for the ext standard.
fn token_id_to_principal(token: BigUint, id: Principal) -> Principal {
    let mut to32_bytes = token.to_u32().unwrap().to_le_bytes();
    to32_bytes.reverse();
    let vec = &[b"\x0Atid", id.as_slice(), &to32_bytes].concat();
    Principal::from_slice(vec)
}

/// It makes an external call to burn an nft (ext standard) to the given contract.
async fn xpnft_burn_for(id: Principal, token_id: Nat) -> CallResult<()> {
    ic_kit::ic::call(id, "burnNFT", (token_id,)).await
}

/// It makes an external call to get the metadata of nft (ext standard) to the given contract.
async fn dip721_token_uri(id: Principal, token_id: Nat) -> CallResult<(Option<String>,)> {
    let principal = token_id_to_principal(token_id.0, id);

    let result: (MotokoResult<Metadata, CommonError>,) =
        ic_kit::ic::call(id, "metadata", (principal.to_text(),))
            .await
            .unwrap();
    if let MotokoResult::Ok(metadata) = result.0 {
        if let Metadata::NonFungible { metadata } = metadata {
            return Ok((metadata.map(|m| {
                let url = String::from_utf8(m).unwrap();
                url
            }),));
        }
    }
    return Ok((None,));
}

/// It makes an external call to get the transfer an nft (ext standard) to the given contract.
async fn dip721_transfer(
    id: Principal,
    from: Principal,
    to: Principal,
    token_id: Nat,
) -> CallResult<()> {
    let principal = token_id_to_principal(token_id.0, id);
    let _result: (MotokoResult<Nat, TransferResponseErrors>,) = ic_kit::ic::call(
        id,
        "transfer",
        (TransferRequest {
            from: User::Principal(from),
            to: User::Principal(to),
            token: principal.to_string(),
            amount: Nat::from(1),
            memo: vec![],
            notify: true,
            subaccount: Option::None,
        },),
    )
    .await
    .unwrap();
    Ok(())
}
/// This is the function that is called when the bridge is initialized/contract is deployed.
#[ic_kit::macros::init]
pub(crate) fn init(group_key: [u8; 32], chain_nonce: u64) {
    unsafe {
        CONFIG = Some(Config {
            group_key,
            chain_nonce,
            paused: false,
            event_cnt: Nat::from(0),
        });
    }
}
/// This is the function that can be used to toggle the bridge's pause state.
#[ic_kit::macros::update]
pub(crate) fn set_pause(action_id: Nat, action: ValidateSetPause, sig: Sig) {
    require_sig_config(action_id, sig.0, b"ValidateSetPause", action.clone()).unwrap();
    config_mut().paused = action.pause;
}

/// This is the function that can be used to set the bridge's group key.
#[ic_kit::macros::update]
pub(crate) fn set_group_key(action_id: Nat, action: ValidateSetGroupKey, sig: Sig) {
    require_unpause().unwrap();
    require_sig_config(action_id, sig.0, b"ValidateSetGroupKey", action.clone()).unwrap();

    config_mut().group_key = action.group_key;
}
/// This is the function that can be used to withdraw the fees from the minter smart contract.
#[ic_kit::macros::update]
pub(crate) async fn withdraw_fees(
    action_id: Nat,
    action: ValidateWithdrawFees,
    sig: Sig,
) -> BlockIndex {
    require_unpause().unwrap();
    require_sig_config(action_id, sig.0, b"ValidateWithdrawFees", action.clone()).unwrap();

    let id = ic_kit::ic::id();

    let bal = ledger::account_balance(
        MAINNET_LEDGER_CANISTER_ID,
        AccountBalanceArgs {
            account: AccountIdentifier::new(&id, &DEFAULT_SUBACCOUNT),
        },
    )
    .await
    .unwrap();

    let args = TransferArgs {
        memo: Memo(0),
        amount: bal,
        fee: DEFAULT_FEE,
        from_subaccount: None,
        to: AccountIdentifier::new(&action.to, &DEFAULT_SUBACCOUNT),
        created_at_time: None,
    };

    ledger::transfer(MAINNET_LEDGER_CANISTER_ID, args)
        .await
        .unwrap()
        .unwrap()
}

/// This is the function that can be used to whitelist a smart contract so that it can be used for transfer.
#[ic_kit::macros::update]
pub(crate) fn add_whitelist(action_id: Nat, action: ValidateWhitelistDip721, sig: Sig) {
    require_unpause().unwrap();

    require_sig_config(action_id, sig.0, b"ValidateWhitelistNft", action.clone()).unwrap();

    WHITELIST_STORE.with(|store| store.borrow_mut().insert(action.dip_contract));
}

/// This is the function that can be used to clean the event store of the contract.
#[ic_kit::macros::update]
pub(crate) fn clean_logs(action_id: Nat, mut action: ValidateCleanLogs, sig: Sig) {
    require_unpause().unwrap();
    require_sig_config(action_id, sig.0, b"ValidateCleanLogs", action.clone()).unwrap();

    EVENT_STORE.with(|store| {
        let mut bmap = store.borrow_mut();
        while action.from_action != action.to_action {
            bmap.remove(&action.from_action);
            action.from_action += Nat::from(1u32);
        }
    });
}
// This is the function that will be called by a validator to mint a new nft which acts as a pointer to the original NFT on some other chain.
#[ic_kit::macros::update]
pub(crate) async fn validate_transfer_nft(
    action_id: Nat,
    action: ValidateTransferNft,
    sig: Sig,
) -> u32 {
    require_unpause().unwrap();
    require_sig(action_id, sig.0, b"ValidateTransferNft", action.clone()).unwrap();

    xpnft_mint(action.mint_with, action.token_url, action.to)
        .await
        .unwrap()
        .0
}
// This is the function that will be called by a validator to transfer an nft that is owned by this smart contract to the given address.
#[ic_kit::macros::update]
pub(crate) async fn validate_unfreeze_nft(action_id: Nat, action: ValidateUnfreezeNft, sig: Sig) {
    require_unpause().unwrap();
    require_sig(action_id, sig.0, b"ValidateUnfreezeNft", action.clone()).unwrap();

    dip721_transfer(
        action.dip_contract,
        ic_kit::ic::id(),
        action.to,
        action.token_id,
    )
    .await
    .unwrap();
}
/// Basically the same as validate_transfer_nf but for multiple nfts.
#[ic_kit::macros::update]
pub(crate) async fn validate_transfer_nft_batch(
    action_id: Nat,
    action: ValidateTransferNftBatch,
    sig: Sig,
) {
    require_unpause().unwrap();
    require_sig(
        action_id,
        sig.0,
        b"ValidateTransferNftBatch",
        action.clone(),
    )
    .unwrap();

    for (i, token_url) in action.token_urls.into_iter().enumerate() {
        xpnft_mint(action.mint_with[i], token_url, action.to)
            .await
            .unwrap();
    }
}
/// Basically the same as validate_unfreeze_nft but for multiple nfts.
#[ic_kit::macros::update]
pub(crate) async fn validate_unfreeze_nft_batch(
    action_id: Nat,
    action: ValidateUnfreezeNftBatch,
    sig: Sig,
) {
    require_unpause().unwrap();
    require_sig(
        action_id,
        sig.0,
        b"ValidateUnfreezeNftBatch",
        action.clone(),
    )
    .unwrap();

    let canister_id = ic_kit::ic::id();
    for (i, token_id) in action.token_ids.into_iter().enumerate() {
        dip721_transfer(action.dip_contracts[i], canister_id, action.to, token_id)
            .await
            .unwrap();
    }
}
/// THis function is used to freeze an nft (ie transfer it to this SC) so that it can be transferred.
#[ic_kit::macros::update]
pub(crate) async fn freeze_nft(
    tx_fee_block: BlockIndex,
    dip721_contract: Principal,
    token_id: Nat,
    chain_nonce: u64,
    to: String,
    mint_with: String,
) -> Nat {
    require_unpause().unwrap();
    require_whitelist(dip721_contract).unwrap();

    let caller = ic_kit::ic::caller();
    let canister_id = ic_kit::ic::id();
    let fee = require_tx_fee(&canister_id, &caller, tx_fee_block)
        .await
        .unwrap();

    dip721_transfer(dip721_contract, caller, canister_id, token_id.clone())
        .await
        .unwrap();
    let url = dip721_token_uri(dip721_contract, token_id.clone())
        .await
        .unwrap()
        .0
        .unwrap_or_default();

    let ctx = BridgeEventCtx::new(fee, chain_nonce, to);
    let ev = BridgeEvent::TransferNft(TransferNft {
        token_id,
        dip721_contract,
        token_data: url,
        mint_with,
    });

    add_event(ctx, ev)
}

/// Performs the same function as freeze_nft but for multiple nfts.
#[ic_kit::macros::update]
pub(crate) async fn freeze_nft_batch(
    tx_fee_block: BlockIndex,
    dip721_contract: Principal,
    token_ids: Vec<Nat>,
    chain_nonce: u64,
    to: String,
    mint_with: String,
) -> Nat {
    require_unpause().unwrap();
    require_whitelist(dip721_contract).unwrap();

    let caller = ic_kit::ic::caller();
    let canister_id = ic_kit::ic::id();

    let fee = require_tx_fee(&canister_id, &caller, tx_fee_block)
        .await
        .unwrap();

    let mut urls = Vec::with_capacity(token_ids.len());
    for token_id in token_ids.clone() {
        urls.push(
            dip721_token_uri(dip721_contract, token_id.clone())
                .await
                .unwrap()
                .0
                .unwrap(),
        );
        dip721_transfer(dip721_contract, caller, canister_id, token_id)
            .await
            .unwrap();
    }

    let ctx = BridgeEventCtx::new(fee, chain_nonce, to);
    let ev = BridgeEvent::TransferNftBatch(TransferNftBatch {
        token_ids,
        dip721_contract,
        token_datas: urls,
        mint_with,
    });

    add_event(ctx, ev)
}

/// Burns the minted NFT with the given token_id.
#[ic_kit::macros::update]
pub(crate) async fn withdraw_nft(
    tx_fee_block: BlockIndex,
    burner: Principal,
    token_id: Nat,
    chain_nonce: u64,
    to: String,
) -> Nat {
    require_unpause().unwrap();

    let caller = ic_kit::ic::caller();
    let canister_id = ic_kit::ic::id();
    let fee = require_tx_fee(&canister_id, &caller, tx_fee_block)
        .await
        .unwrap();

    let url = dip721_token_uri(burner, token_id.clone())
        .await
        .unwrap()
        .0
        .unwrap();
    xpnft_burn_for(burner, token_id.clone()).await.unwrap();

    let ctx = BridgeEventCtx::new(fee, chain_nonce, to);
    let ev = BridgeEvent::UnfreezeNft(UnfreezeNft {
        token_id,
        burner,
        uri: url,
    });

    add_event(ctx, ev)
}
/// Performs the same function as withdraw_nft but for multiple nfts.
#[ic_kit::macros::update]
pub(crate) async fn withdraw_nft_batch(
    tx_fee_block: BlockIndex,
    burner: Principal,
    token_ids: Vec<Nat>,
    chain_nonce: u64,
    to: String,
) -> Nat {
    require_unpause().unwrap();

    let caller = ic_kit::ic::caller();
    let canister_id = ic_kit::ic::id();
    let fee = require_tx_fee(&canister_id, &caller, tx_fee_block)
        .await
        .unwrap();

    let mut urls = Vec::with_capacity(token_ids.len());

    for token_id in token_ids.clone() {
        urls.push(
            dip721_token_uri(burner, token_id.clone())
                .await
                .unwrap()
                .0
                .unwrap(),
        );
        xpnft_burn_for(burner, token_id).await.unwrap();
    }

    let ctx = BridgeEventCtx::new(fee, chain_nonce, to);
    let ev = BridgeEvent::UnfreezeNftBatch(UnfreezeNftBatch {
        token_ids,
        burner,
        uris: urls,
    });

    add_event(ctx, ev)
}
/// Gets an event from the event storage of the contract.
#[ic_kit::macros::query]
pub(crate) fn get_event(action_id: Nat) -> Option<(BridgeEventCtx, BridgeEvent)> {
    EVENT_STORE.with(|store| store.borrow().get(&action_id).cloned())
}

/// Gets the config of the contract.
#[ic_kit::macros::query]
pub(crate) fn get_config() -> Config {
    config_ref().clone()
}
/// Checks if the contract is whitelisted or not
#[ic_kit::macros::query]
pub(crate) fn is_whitelisted(contract: Principal) -> bool {
    require_whitelist(contract).is_ok()
}

#[cfg(test)]
mod tests;
