mod actions;
mod events;

mod types;
use actions::*;
use candid::candid_method;
use candid::types::Compound;
use candid::types::Type;
use candid::CandidType;
use candid::Deserialize;
use candid::Encode;
use candid::Nat;
use candid::Principal;
use events::*;
use ic_cdk::api::call::CallResult;
use ic_cdk::api::call::RejectionCode;
use ic_ledger_types::{account_balance, query_blocks, transfer, GetBlocksArgs, Operation};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde::Serialize;
use serde_big_array::BigArray;
use types::ext_types::*;
use types::motoko_types::*;

use ed25519_compact::{PublicKey, Signature};

use ic_ledger_types::{
    AccountBalanceArgs, AccountIdentifier, BlockIndex, Memo, TransferArgs, DEFAULT_FEE,
    DEFAULT_SUBACCOUNT, MAINNET_LEDGER_CANISTER_ID,
};

use sha2::{Digest, Sha512};
use std::collections::BTreeSet;
use std::{cell::RefCell, collections::BTreeMap, thread::LocalKey};

type ActionIdStore = BTreeSet<Nat>;
type WhitelistStore = BTreeSet<Principal>;
type EventStore = BTreeMap<Nat, (BridgeEventCtx, BridgeEvent)>;
type ValidatedEventStore = BTreeMap<Nat, ValidatedEvent>;
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
        let conf = config_ref();
        Self {
            chain_nonce: conf.chain_nonce,
            sc_addr: ic_cdk::id(),
            action_id,
            inner,
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, CandidType)]
pub struct TransferTx {
    value: u128,
    from_chain: u8,
    to_chain: u8,
    to: String,
    num: u128,
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
    fee_public_key: [u8; 32],
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
    FailedToQueryFee(String),
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

/// Gets a mutable reference to {Config}
fn config_mut() -> &'static mut Config {
    return unsafe { CONFIG.as_mut().unwrap() };
}

/// Gets a unreadable reference to {Config}
fn config_ref() -> &'static Config {
    return unsafe { CONFIG.as_ref().unwrap() };
}

thread_local! {
    static ACTIONID_STORE: RefCell<ActionIdStore> = RefCell::default();
    static ACTIONID_STORE_CONFIG: RefCell<ActionIdStore> = RefCell::default();
    static WHITELIST_STORE: RefCell<WhitelistStore> = RefCell::default();
    static EVENT_STORE: RefCell<EventStore> = RefCell::default();
    static FEEBLOCK_STORE: RefCell<FeeBlockStore> = RefCell::default();
    static VALIDATED_EVENT_STORE: RefCell<ValidatedEventStore> = RefCell::default();
}

/// Checks if the signature is correctly signed by the correct
/// private key and makes sure the action id is not a duplicate.
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

/// Requires the contract to be in unpaused state.
fn require_unpause() -> Result<(), BridgeError> {
    if config_ref().paused {
        return Err(BridgeError::BridgePaused);
    }

    return Ok(());
}

/// Requires the NFT contract as sent in the paramter to be a whitelisted contract.
fn require_whitelist(contract: Principal) -> Result<(), BridgeError> {
    if !WHITELIST_STORE.with(|whitelist| whitelist.borrow().contains(&contract)) {
        return Err(BridgeError::NotWhitelisted);
    }

    return Ok(());
}

/// Checks in the prev blocks to make sure that
/// the fees was paid for transfer of the NFT
async fn require_tx_fee(
    canister_id: &Principal,
    caller: &Principal,
    fee_block: BlockIndex,
) -> Result<u64, BridgeError> {
    if FEEBLOCK_STORE.with(|store| store.borrow().contains(&fee_block)) {
        return Err(BridgeError::InvalidFee);
    }

    let caller_acc = AccountIdentifier::new(caller, &DEFAULT_SUBACCOUNT);
    let canister_acc = AccountIdentifier::new(canister_id, &DEFAULT_SUBACCOUNT);
    let query = GetBlocksArgs {
        start: fee_block,
        length: 1,
    };
    let block_info = query_blocks(MAINNET_LEDGER_CANISTER_ID, query)
        .await
        .map_err(|e| {
            BridgeError::FailedToQueryFee(format!(
                "Failed to Query for fee. Code: {:?}. Reason: {}",
                e.0, e.1
            ))
        })?;
    match block_info.blocks[0].transaction.operation {
        Some(Operation::Transfer {
            from, to, amount, ..
        }) if from == caller_acc && to == canister_acc => {
            FEEBLOCK_STORE.with(|s| s.borrow_mut().insert(fee_block));
            Ok(amount.e8s())
        }
        _ => Err(BridgeError::InvalidFee),
    }
}

/// Adds an event to the event store of the contract.
fn add_event(ctx: BridgeEventCtx, ev: BridgeEvent) -> Nat {
    let action_id = ctx.action_id.clone();
    EVENT_STORE.with(|store| store.borrow_mut().insert(ctx.action_id.clone(), (ctx, ev)));
    action_id
}
/// It makes an external call to mint an nft (ext standard) to the given contract.
async fn xpnft_mint(id: Principal, url: String, to: Principal) -> CallResult<(u32,)> {
    ic_cdk::call(
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
async fn xpnft_burn_for(id: Principal, token_id: u32) -> CallResult<()> {
    ic_cdk::call(id, "burnNFT", (token_id,)).await
}

/// It makes an external call to get the metadata of nft (ext standard) to the given contract.
async fn dip721_token_uri(id: Principal, token_id: Nat) -> CallResult<(Option<String>,)> {
    let principal = token_id_to_principal(token_id.0, id);
    let result: (MotokoResult<Metadata, CommonError>,) =
        ic_cdk::call(id, "metadata", (principal.to_text(),))
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

async fn xpnft_bearer(id: Principal, token_id: Nat) -> String {
    let result: (MotokoResult<String, CommonError>,) = ic_cdk::call(
        id,
        "bearer",
        (token_id_to_principal(token_id.into(), id).to_text(),),
    )
    .await
    .unwrap();
    if let (MotokoResult::Ok(account),) = result {
        account
    } else {
        panic!("Failed to get bearer: {:?}", result)
    }
}

/// It makes an external call to get the transfer an nft (ext standard) to the given contract.
async fn dip721_transfer(
    id: Principal,
    from: Principal,
    to: Principal,
    token_id: Nat,
) -> CallResult<()> {
    let principal = token_id_to_principal(token_id.0, id);
    let (result,): (MotokoResult<Nat, TransferResponseErrors>,) = ic_cdk::call(
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
    if let MotokoResult::Ok(_) = result {
        return Ok(());
    } else {
        panic!("Failed to transfer: {:?}", result)
    }
}
/// This is the function that is called when the bridge is initialized/contract is deployed.
/// It sets the group key, chainNonce and the contracts to whitelist NFTs.
#[ic_cdk_macros::init]
#[candid_method(init)]
pub(crate) fn init(
    group_key: [u8; 32],
    fee_public_key: [u8; 32],
    chain_nonce: u64,
    whitelist: Vec<String>,
) {
    unsafe {
        CONFIG = Some(Config {
            group_key,
            chain_nonce,
            paused: false,
            event_cnt: Nat::from(0),
            fee_public_key,
        });
    }
    whitelist.iter().for_each(|w| {
        let c = Principal::from_text(w).unwrap();
        WHITELIST_STORE.with(|store| store.borrow_mut().insert(c));
    });
}
/// This is the function that can be used to set bridge's state to paused.
/// It will stop any transactions from happening on the bridge
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) fn set_pause(action_id: Nat, action: ValidateSetPause, sig: Sig) -> u32 {
    require_sig_config(
        action_id.clone(),
        sig.0,
        b"ValidateSetPause",
        action.clone(),
    )
    .unwrap();
    config_mut().paused = action.pause;
    VALIDATED_EVENT_STORE.with(|store| {
        store.borrow_mut().insert(
            action_id.clone(),
            ValidatedEvent::ValidatedPause {
                paused: action.pause,
            },
        )
    });
    action_id.0.to_u32().unwrap()
}

/// This is the function that can be used to set the bridge's group key.
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) fn set_group_key(action_id: Nat, action: ValidateSetGroupKey, sig: Sig) -> u32 {
    require_unpause().unwrap();
    require_sig_config(
        action_id.clone(),
        sig.0,
        b"ValidateSetGroupKey",
        action.clone(),
    )
    .unwrap();

    config_mut().group_key = action.group_key;

    VALIDATED_EVENT_STORE.with(|store| {
        store.borrow_mut().insert(
            action_id.clone(),
            ValidatedEvent::ValidatedUpdateKey {
                key: action.group_key,
                key_type: KeyType::BridgeGroupKey,
            },
        )
    });
    action_id.0.to_u32().unwrap()
}

#[ic_cdk::update]
#[candid_method(update)]
pub(crate) fn set_fee_group_key(action_id: Nat, action: ValidateSetGroupKey, sig: Sig) -> u32 {
    require_unpause().unwrap();
    require_sig_config(
        action_id.clone(),
        sig.0,
        b"ValidateSetGroupKey",
        action.clone(),
    )
    .unwrap();

    config_mut().fee_public_key = action.group_key;

    VALIDATED_EVENT_STORE.with(|store| {
        store.borrow_mut().insert(
            action_id.clone(),
            ValidatedEvent::ValidatedUpdateKey {
                key: action.group_key,
                key_type: KeyType::FeeKey,
            },
        )
    });
    action_id.0.to_u32().unwrap()
}
/// This is the function that can be used to withdraw the fees from the minter smart contract
/// that is earned by the NFT transfers.
/// REQUIRED: The contract should not be in paused state.
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) async fn withdraw_fees(action_id: Nat, action: ValidateWithdrawFees, sig: Sig) -> u32 {
    require_unpause().unwrap();
    require_sig_config(
        action_id.clone(),
        sig.0,
        b"ValidateWithdrawFees",
        action.clone(),
    )
    .unwrap();

    let id = ic_cdk::id();

    let bal = account_balance(
        MAINNET_LEDGER_CANISTER_ID,
        AccountBalanceArgs {
            account: AccountIdentifier::new(&id, &DEFAULT_SUBACCOUNT),
        },
    )
    .await
    .unwrap();

    let args = TransferArgs {
        memo: Memo(0),
        amount: bal - DEFAULT_FEE,
        fee: DEFAULT_FEE,
        from_subaccount: None,
        to: AccountIdentifier::new(&action.to, &DEFAULT_SUBACCOUNT),
        created_at_time: None,
    };

    let block_index = transfer(MAINNET_LEDGER_CANISTER_ID, args)
        .await
        .unwrap()
        .unwrap();

    VALIDATED_EVENT_STORE.with(|store| {
        store.borrow_mut().insert(
            action_id.clone(),
            ValidatedEvent::ValidatedFeeWithdraw {
                to: action.to,
                block_index,
            },
        )
    });
    action_id.0.to_u32().unwrap()
}

/// This is the function that can be used to whitelist a smart contract so that it can be used for transfer.
/// This is generally required for freezeing NFTs of only contracts verified by us.
/// REQUIRED: The contract should not be in paused state.
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) fn add_whitelist(action_id: Nat, action: ValidateWhitelistDip721, sig: Sig) {
    require_unpause().unwrap();

    require_sig_config(action_id, sig.0, b"ValidateWhitelistNft", action.clone()).unwrap();

    WHITELIST_STORE.with(|store| store.borrow_mut().insert(action.dip_contract));
}

/// This is the function that can be used to clean the event store of the contract.
/// This removes all the actions that are stored in the event store.
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) fn clean_logs(action_id: Nat, action: ValidateCleanLogs, sig: Sig) -> () {
    require_unpause().unwrap();
    require_sig_config(
        action_id.clone(),
        sig.0,
        b"ValidateCleanLogs",
        action.clone(),
    )
    .unwrap();

    EVENT_STORE.with(|store| {
        let mut bmap = store.borrow_mut();
        bmap.clear();
    });
}
/// This is the function that will be called by a validator to
/// mint a new nft which acts as a pointer to the original nft on dfinity chain.
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) async fn validate_transfer_nft(
    action_id: Nat,
    action: ValidateTransferNft,
    sig: Sig,
) -> u32 {
    require_unpause().unwrap();
    ic_cdk::println!("Not Paused");
    require_sig(
        action_id.clone(),
        sig.0,
        b"ValidateTransferNft",
        action.clone(),
    )
    .unwrap();
    ic_cdk::println!("Sig Verified");
    let mint = xpnft_mint(action.mint_with, action.clone().token_url, action.to)
        .await
        .unwrap()
        .0;
    ic_cdk::println!("Minted {mint}");
    VALIDATED_EVENT_STORE.with(|store| {
        let mut st = store.borrow_mut();
        st.insert(
            action_id.clone(),
            ValidatedEvent::ValidatedMint {
                mint_with: action.mint_with,
                token_id: mint,
            },
        )
    });
    action_id.0.to_u32().unwrap()
}
/// This is the function that will be called by a validator to transfer
/// a pointer nft to back to the original chain.
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) async fn validate_unfreeze_nft(
    action_id: Nat,
    action: ValidateUnfreezeNft,
    sig: Sig,
) -> u32 {
    require_unpause().unwrap();
    require_sig(
        action_id.clone(),
        sig.0,
        b"ValidateUnfreezeNft",
        action.clone(),
    )
    .unwrap();

    dip721_transfer(
        action.dip_contract,
        ic_cdk::id(),
        action.clone().to,
        action.clone().token_id,
    )
    .await
    .unwrap();
    VALIDATED_EVENT_STORE.with(|store| {
        let mut st = store.borrow_mut();
        st.insert(
            action_id.clone(),
            ValidatedEvent::ValidatedUnfreeze {
                contract: action.dip_contract,
                token_id: action.token_id,
                to: action.to,
            },
        )
    });
    action_id.0.to_u32().unwrap()
}
/// Basically the same as validate_transfer_nf but for multiple nfts.
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) async fn validate_transfer_nft_batch(
    action_id: Nat,
    action: ValidateTransferNftBatch,
    sig: Sig,
) {
    require_unpause().unwrap();
    require_sig(
        action_id.clone(),
        sig.0,
        b"ValidateTransferNftBatch",
        action.clone(),
    )
    .unwrap();

    assert_eq!(action.mint_with.len(), action.token_urls.len());
    let mut token_ids = vec![];
    for (i, token_url) in action.clone().token_urls.into_iter().enumerate() {
        let (token_id,) = xpnft_mint(action.mint_with[i], token_url, action.to)
            .await
            .unwrap();
        token_ids.push(token_id)
    }
    VALIDATED_EVENT_STORE.with(|store| {
        let mut st = store.borrow_mut();
        st.insert(
            action_id.clone(),
            ValidatedEvent::ValidatedMintBatch {
                mint_with: action.mint_with,
                token_ids,
            },
        )
    });
    action_id.0.to_u32().unwrap();
}
/// Basically the same as validate_unfreeze_nft but for multiple nfts.
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) async fn validate_unfreeze_nft_batch(
    action_id: Nat,
    action: ValidateUnfreezeNftBatch,
    sig: Sig,
) -> u32 {
    require_unpause().unwrap();
    require_sig(
        action_id.clone(),
        sig.0,
        b"ValidateUnfreezeNftBatch",
        action.clone(),
    )
    .unwrap();

    let canister_id = ic_cdk::id();

    assert_eq!(action.token_ids.len(), action.dip_contracts.len());

    for (i, token_id) in action.clone().token_ids.into_iter().enumerate() {
        dip721_transfer(action.dip_contracts[i], canister_id, action.to, token_id)
            .await
            .unwrap();
    }
    VALIDATED_EVENT_STORE.with(|store| {
        let mut st = store.borrow_mut();
        st.insert(
            action_id.clone(),
            ValidatedEvent::ValidatedUnfreezeBatch {
                contracts: action.dip_contracts,
                token_ids: action.token_ids,
                to: action.to,
            },
        )
    });
    action_id.0.to_u32().unwrap()
}
/// This function is used to freeze an nft (ie transfer it to this SC)
/// so that it can be minted later on the destination chain.
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) async fn freeze_nft(
    tx_fee_block: BlockIndex,
    dip721_contract: Principal,
    token_id: Nat,
    chain_nonce: u64,
    to: String,
    mint_with: String,
    sig: Sig,
) -> Nat {
    require_unpause().unwrap();
    require_whitelist(dip721_contract).unwrap();

    let caller = ic_cdk::caller();
    let canister_id = ic_cdk::id();
    let fee = require_tx_fee(&canister_id, &caller, tx_fee_block)
        .await
        .unwrap();

    check_fee(
        TransferTx {
            from_chain: 0x1c,
            value: fee as u128,
            to_chain: chain_nonce as u8,
            to: to.clone(),
            num: 1,
        },
        sig,
    );

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
        caller,
    });

    add_event(ctx, ev)
}

/// Performs the same function as freeze_nft but for multiple nfts.
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) async fn freeze_nft_batch(
    tx_fee_block: BlockIndex,
    dip721_contract: Principal,
    token_ids: Vec<Nat>,
    chain_nonce: u64,
    to: String,
    mint_with: String,
    sig: Sig,
) -> Nat {
    require_unpause().unwrap();
    require_whitelist(dip721_contract).unwrap();

    let caller = ic_cdk::caller();
    let canister_id = ic_cdk::id();

    let fee = require_tx_fee(&canister_id, &caller, tx_fee_block)
        .await
        .unwrap();

    check_fee(
        TransferTx {
            from_chain: 0x1c,
            value: fee as u128,
            to_chain: chain_nonce as u8,
            to: to.clone(),
            num: token_ids.len() as u128,
        },
        sig,
    );

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
        caller,
    });

    add_event(ctx, ev)
}

/// Burns the minted NFT with the given token_id and later the
/// token is minted back to the original chain.
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) async fn withdraw_nft(
    tx_fee_block: BlockIndex,
    burner: Principal,
    token_id: Nat,
    chain_nonce: u64,
    to: String,
    sig: Sig,
) -> Nat {
    require_unpause().unwrap();
    let caller = ic_cdk::caller();
    let calleraid = AccountIdentifier::new(&caller, &DEFAULT_SUBACCOUNT).to_string();

    let bearer = xpnft_bearer(burner, token_id.clone()).await;

    assert!(bearer == calleraid, "Token owner is not the caller");

    let canister_id = ic_cdk::id();
    let fee = require_tx_fee(&canister_id, &caller, tx_fee_block)
        .await
        .unwrap();

    check_fee(
        TransferTx {
            from_chain: 0x1c,
            value: fee as u128,
            to_chain: chain_nonce as u8,
            to: to.clone(),
            num: 1,
        },
        sig,
    );

    let url = dip721_token_uri(burner, token_id.clone())
        .await
        .unwrap()
        .0
        .unwrap();

    xpnft_burn_for(burner, token_id.clone().0.to_u32().unwrap())
        .await
        .unwrap();

    let ctx = BridgeEventCtx::new(fee, chain_nonce, to);
    let ev = BridgeEvent::UnfreezeNft(UnfreezeNft {
        token_id,
        burner,
        uri: url,
        caller,
    });

    add_event(ctx, ev)
}

/// Performs the same function as withdraw_nft but for multiple nfts.
#[ic_cdk::update]
#[candid_method(update)]
pub(crate) async fn withdraw_nft_batch(
    tx_fee_block: BlockIndex,
    burner: Principal,
    token_ids: Vec<Nat>,
    chain_nonce: u64,
    to: String,
    sig: Sig,
) -> Nat {
    require_unpause().unwrap();

    let caller = ic_cdk::caller();
    let canister_id = ic_cdk::id();

    let fee = require_tx_fee(&canister_id, &caller, tx_fee_block)
        .await
        .unwrap();

    check_fee(
        TransferTx {
            from_chain: 0x1c,
            value: fee as u128,
            to_chain: chain_nonce as u8,
            to: to.clone(),
            num: token_ids.len() as u128,
        },
        sig,
    );

    let mut urls = Vec::with_capacity(token_ids.len());

    for token_id in token_ids.clone() {
        let calleraid = AccountIdentifier::new(&caller, &DEFAULT_SUBACCOUNT).to_string();
        let bearer = xpnft_bearer(burner, token_id.clone()).await;

        assert!(bearer == calleraid, "Token owner is not the caller");

        urls.push(
            dip721_token_uri(burner, token_id.clone())
                .await
                .unwrap()
                .0
                .unwrap(),
        );
        xpnft_burn_for(burner, token_id.0.to_u32().unwrap())
            .await
            .unwrap();
    }

    let ctx = BridgeEventCtx::new(fee, chain_nonce, to);
    let ev = BridgeEvent::UnfreezeNftBatch(UnfreezeNftBatch {
        token_ids,
        burner,
        uris: urls,
        caller,
    });

    add_event(ctx, ev)
}
/// Gets an event from the event storage of the contract.
#[ic_cdk::query]
#[candid_method(query)]
pub(crate) fn get_event(action_id: Nat) -> Option<(BridgeEventCtx, BridgeEvent)> {
    EVENT_STORE.with(|store| store.borrow().get(&action_id).cloned())
}

#[ic_cdk::query]
#[candid_method(query)]
pub(crate) fn get_validated_event(action_id: Nat) -> Option<ValidatedEvent> {
    VALIDATED_EVENT_STORE.with(|store| store.borrow().get(&action_id).cloned())
}

/// Gets the config of the contract.
#[ic_cdk::query]
#[candid_method(query)]
pub(crate) fn get_config() -> Config {
    config_ref().clone()
}

/// Encodes a ValidateTransferNft to Vec<u8>.
#[ic_cdk::query]
#[candid_method(query)]
pub(crate) fn encode_validate_transfer_nft(aid: Nat, inner: ValidateTransferNft) -> Vec<u8> {
    Encode!(&BridgeAction::new(aid, inner)).unwrap()
}

/// Encodes a ValidateTransferNft to Vec<u8>.
#[ic_cdk::query]
#[candid_method(query)]
pub(crate) fn encode_validate_unfreeze_nft(aid: Nat, inner: ValidateUnfreezeNft) -> Vec<u8> {
    Encode!(&BridgeAction::new(aid, inner)).unwrap()
}

/// Encodes a ValidateTransferNft to Vec<u8>.
#[ic_cdk::query]
#[candid_method(query)]
pub(crate) fn encode_validate_unfreeze_nft_batch(
    aid: Nat,
    inner: ValidateUnfreezeNftBatch,
) -> Vec<u8> {
    Encode!(&BridgeAction::new(aid, inner)).unwrap()
}

/// Encodes a ValidateTransferNft to Vec<u8>.
#[ic_cdk::query]
#[candid_method(query)]
pub(crate) fn encode_transfer_tx(
    from_chain: u8,
    to_chain: u8,
    to: String,
    value: u128,
    num: u128,
) -> Vec<u8> {
    Encode!(&TransferTx {
        from_chain,
        to_chain,
        to,
        value,
        num
    })
    .unwrap()
}

/// Encodes a ValidateTransferNft to Vec<u8>.
#[ic_cdk::query]
#[candid_method(query)]
pub(crate) fn encode_validate_transfer_nft_batch(
    aid: Nat,
    inner: ValidateTransferNftBatch,
) -> Vec<u8> {
    Encode!(&BridgeAction::new(aid, inner)).unwrap()
}

/// Encodes a ValidateTransferNft to Vec<u8>.
#[ic_cdk::query]
#[candid_method(query)]
pub(crate) fn encode_withdraw_fees(aid: Nat, inner: ValidateWithdrawFees) -> Vec<u8> {
    Encode!(&BridgeAction::new(aid, inner)).unwrap()
}

/// Checks if the contract is whitelisted or not
#[ic_cdk::query]
#[candid_method(query)]
pub(crate) fn is_whitelisted(contract: Principal) -> bool {
    require_whitelist(contract).is_ok()
}

pub(crate) fn check_fee(data: TransferTx, sig_data: Sig) {
    let fee_pk = config_ref().fee_public_key;
    let mut hasher = Sha512::new();
    hasher.update(Encode!(&data).unwrap());
    let hash = hasher.finalize();
    let sig = Signature::new(sig_data.0);
    let key = PublicKey::new(fee_pk);
    let _ = key
        .verify(hash, &sig)
        .expect("Amount Signature Verification Failed");
}

#[cfg(test)]
mod tests;
