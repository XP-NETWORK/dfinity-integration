use crate::ledger::{Block, Operation, QueryBlocksResponse, Transaction};

use super::*;
use ed25519_compact::{KeyPair, Seed};
use ic_kit::{async_test, mock_principals, Canister, Method, MockContext};
use ic_ledger_types::{Timestamp, Tokens, TransferResult};
use lazy_static::lazy_static;
use rand::Rng;

const NFT_URL: &str = "www.test.com";
const BLOCK_INDEX_TXFEE: BlockIndex = 0;
const CHAIN_NONCE: u64 = 7357;
const TARGET_NONCE: u64 = 2;
const TX_FEE_BAL: u64 = 1000;
const TARGET_ACC: &str = "TEST_ACC";
const TARGET_MW: &str = "MINT_WITH";
lazy_static! {
    static ref CALLER: Principal = mock_principals::alice();
    static ref CANISTER_ID: Principal = mock_principals::john();
    static ref XPNFT_ID: Principal = mock_principals::xtc();
    static ref TOKEN_ID: Nat = Nat::from(0u32);
    static ref KP: KeyPair = KeyPair::from_seed(Seed::from([1; 32]));
}

fn rand_actid() -> u64 {
    let mut rng = rand::thread_rng();

    return rng.gen();
}

fn xpnft_mock() -> Canister {
    let metadata: MotokoResult<Metadata, CommonError> = MotokoResult::Ok(Metadata::NonFungible {
        metadata: Some(NFT_URL.as_bytes().to_vec()),
    });
    let transfer: MotokoResult<Nat, TransferResponseErrors> = MotokoResult::Ok(Nat::from(0));
    let principal = token_id_to_principal(TOKEN_ID.0.clone(), XPNFT_ID.clone()).to_text();
    return Canister::new(XPNFT_ID.clone())
        .method(
            "mintNFT",
            Box::new(
                Method::new()
                    .expect_arguments((MintRequest {
                        metadata: Some(NFT_URL.as_bytes().to_vec()),
                        to: User::Principal(*CALLER),
                    },))
                    .response(0u32),
            ),
        )
        .method(
            "burnNFT",
            Box::new(
                Method::new()
                    .expect_arguments((TOKEN_ID.clone(),))
                    .response(()),
            ),
        )
        .method(
            "metadata",
            Box::new(
                Method::new()
                    .expect_arguments((principal,))
                    .response(metadata),
            ),
        )
        .method("transfer", Box::new(Method::new().response(transfer)));
}

fn ledger_mock(bal_id: Principal, bal: Tokens) -> Canister {
    Canister::new(MAINNET_LEDGER_CANISTER_ID)
        .method(
            "account_balance",
            Box::new(
                Method::new()
                    .expect_arguments((AccountBalanceArgs {
                        account: AccountIdentifier::new(&bal_id, &DEFAULT_SUBACCOUNT),
                    },))
                    .response(bal),
            ),
        )
        .method(
            "transfer",
            Box::new(Method::new().response::<TransferResult>(Ok(BLOCK_INDEX_TXFEE))),
        )
        .method(
            "query_blocks",
            Box::new(
                Method::new()
                    .expect_arguments((GetBlockArgs {
                        start: BLOCK_INDEX_TXFEE,
                        length: 1,
                    },))
                    .response(QueryBlocksResponse {
                        chain_length: 1,
                        certificate: None,
                        blocks: vec![Block {
                            parent_hash: None,
                            transaction: Transaction {
                                memo: Memo(0),
                                operation: Some(Operation::Transfer {
                                    from: AccountIdentifier::new(&CALLER, &DEFAULT_SUBACCOUNT),
                                    to: AccountIdentifier::new(&CANISTER_ID, &DEFAULT_SUBACCOUNT),
                                    amount: bal,
                                    fee: DEFAULT_FEE,
                                }),
                                created_at_time: Timestamp { timestamp_nanos: 0 },
                            },
                            timestamp: Timestamp { timestamp_nanos: 0 },
                        }],
                        first_block_index: BLOCK_INDEX_TXFEE,
                        archived_blocks: vec![],
                    }),
            ),
        )
}

fn whitelist_xpnft() {
    let action_id = Nat::from(rand_actid());
    let act = ValidateWhitelistDip721 {
        dip_contract: XPNFT_ID.clone(),
    };
    let sig = sign_action(action_id.clone(), b"ValidateWhitelistNft", act.clone());
    add_whitelist(action_id, act, sig);
}

fn validation_ctx_ledger() -> Canister {
    return ledger_mock(CANISTER_ID.clone(), Tokens::from_e8s(TX_FEE_BAL));
}

fn user_ctx_ledger() -> Canister {
    ledger_mock(CALLER.clone(), Tokens::from_e8s(TX_FEE_BAL))
}

fn init_context(ledger: Canister) -> &'static mut MockContext {
    let ctx = MockContext::new()
        .with_id(CANISTER_ID.clone())
        .with_caller(CALLER.clone())
        .with_handler(xpnft_mock())
        .with_handler(ledger)
        .inject();

    init(*KP.pk, CHAIN_NONCE);

    ctx
}

fn init_context_validator() -> &'static mut MockContext {
    init_context(validation_ctx_ledger())
}

fn init_context_user() -> &'static mut MockContext {
    let ctx = init_context(user_ctx_ledger());
    whitelist_xpnft();
    ctx
}

fn sign_action(action_id: Nat, context: &[u8], data: impl CandidType) -> Sig {
    let raw_act = Encode!(&BridgeAction::new(action_id, data)).unwrap();

    let mut hasher = Sha512::new();
    hasher.update(context);
    hasher.update(raw_act);
    let hash = hasher.finalize();

    return Sig(*KP.sk.sign(&hash, None));
}

#[test]
fn pause() {
    init_context_validator();

    let action_id = Nat::from(rand_actid());
    let act = ValidateSetPause { pause: true };
    let sig = sign_action(action_id.clone(), b"ValidateSetPause", act.clone());
    set_pause(action_id, act, sig);

    let conf = get_config();
    assert!(conf.paused);

    let action_id = Nat::from(rand_actid());
    let act = ValidateSetPause { pause: false };
    let sig = sign_action(action_id.clone(), b"ValidateSetPause", act.clone());
    set_pause(action_id, act, sig);

    let conf = get_config();
    assert!(!conf.paused);
}

#[test]
fn set_gk() {
    init_context_validator();

    let new_kp = KeyPair::from_seed(Seed::from([2; 32]));
    let action_id = Nat::from(rand_actid());
    let act = ValidateSetGroupKey {
        group_key: *new_kp.pk,
    };
    let sig = sign_action(action_id.clone(), b"ValidateSetGroupKey", act.clone());
    set_group_key(action_id, act, sig);

    let conf = get_config();
    assert_eq!(conf.group_key, *new_kp.pk);
}

#[async_test]
async fn withdraw_fee_test() {
    init_context_validator();

    let action_id = Nat::from(rand_actid());
    let act = ValidateWithdrawFees { to: CALLER.clone() };
    let sig = sign_action(action_id.clone(), b"ValidateWithdrawFees", act.clone());
    let res = withdraw_fees(action_id, act, sig).await;

    assert_eq!(res, BLOCK_INDEX_TXFEE);
}

#[test]
fn whitelist_nft() {
    init_context_validator();

    whitelist_xpnft();
    assert!(is_whitelisted(XPNFT_ID.clone()))
}

#[async_test]
async fn validate_transfer_nft_test() {
    init_context_validator();

    let aid = Nat::from(rand_actid());
    let act = ValidateTransferNft {
        mint_with: XPNFT_ID.clone(),
        token_url: NFT_URL.into(),
        to: *CALLER,
    };
    let sig = sign_action(aid.clone(), b"ValidateTransferNft", act.clone());
    let tid = validate_transfer_nft(aid, act, sig).await;
    assert_eq!(tid, *TOKEN_ID);
}

#[async_test]
async fn validate_unfreeze_nft_test() {
    init_context_validator();

    let aid = Nat::from(rand_actid());
    let act = ValidateUnfreezeNft {
        to: *CALLER,
        dip_contract: *XPNFT_ID,
        token_id: TOKEN_ID.clone(),
    };
    let sig = sign_action(aid.clone(), b"ValidateUnfreezeNft", act.clone());
    validate_unfreeze_nft(aid, act, sig).await;
}

#[async_test]
async fn validate_transfer_nft_batch_test() {
    init_context_validator();

    let aid = Nat::from(rand_actid());
    let act = ValidateTransferNftBatch {
        token_urls: vec![NFT_URL.to_string(), NFT_URL.to_string()],
        mint_with: vec![*XPNFT_ID, *XPNFT_ID],
        to: *CALLER,
    };
    let sig = sign_action(aid.clone(), b"ValidateTransferNftBatch", act.clone());
    validate_transfer_nft_batch(aid, act, sig).await;
}

#[async_test]
async fn validate_unfreeze_nft_batch_test() {
    init_context_validator();

    let aid = Nat::from(rand_actid());
    let act = ValidateUnfreezeNftBatch {
        to: *CALLER,
        dip_contracts: vec![*XPNFT_ID, *XPNFT_ID],
        token_ids: vec![TOKEN_ID.clone(), TOKEN_ID.clone()],
    };
    let sig = sign_action(aid.clone(), b"ValidateUnfreezeNftBatch", act.clone());

    validate_unfreeze_nft_batch(aid, act, sig).await;
}

#[async_test]
async fn freeze_nft_test() {
    init_context_user();

    let eid = freeze_nft(
        BLOCK_INDEX_TXFEE,
        *XPNFT_ID,
        TOKEN_ID.clone(),
        TARGET_NONCE,
        TARGET_ACC.into(),
        TARGET_MW.into(),
    )
    .await;

    let (evctx, ev) = get_event(eid.clone()).unwrap();
    assert_eq!(
        evctx,
        BridgeEventCtx {
            action_id: eid,
            chain_nonce: TARGET_NONCE,
            tx_fee: TX_FEE_BAL,
            to: TARGET_ACC.into()
        }
    );
    assert_eq!(
        ev,
        BridgeEvent::TransferNft(TransferNft {
            token_id: TOKEN_ID.clone(),
            dip721_contract: *XPNFT_ID,
            token_data: NFT_URL.into(),
            mint_with: TARGET_MW.into()
        })
    );
}

#[async_test]
async fn freeze_nft_batch_test() {
    init_context_user();

    let eid = freeze_nft_batch(
        BLOCK_INDEX_TXFEE,
        *XPNFT_ID,
        vec![TOKEN_ID.clone(), TOKEN_ID.clone()],
        TARGET_NONCE,
        TARGET_ACC.into(),
        TARGET_MW.into(),
    )
    .await;

    let (evctx, ev) = get_event(eid.clone()).unwrap();

    assert_eq!(
        evctx,
        BridgeEventCtx {
            action_id: eid,
            chain_nonce: TARGET_NONCE,
            tx_fee: TX_FEE_BAL,
            to: TARGET_ACC.into()
        }
    );

    assert_eq!(
        ev,
        BridgeEvent::TransferNftBatch(TransferNftBatch {
            token_ids: vec![TOKEN_ID.clone(), TOKEN_ID.clone()],
            dip721_contract: *XPNFT_ID,
            token_datas: vec![NFT_URL.into(), NFT_URL.into()],
            mint_with: TARGET_MW.into()
        })
    );
}

#[async_test]
async fn withdraw_nft_test() {
    init_context_user();

    let eid = withdraw_nft(
        BLOCK_INDEX_TXFEE,
        *XPNFT_ID,
        TOKEN_ID.clone(),
        TARGET_NONCE,
        TARGET_ACC.into(),
    )
    .await;

    let (evctx, ev) = get_event(eid.clone()).unwrap();

    assert_eq!(
        evctx,
        BridgeEventCtx {
            action_id: eid,
            chain_nonce: TARGET_NONCE,
            tx_fee: TX_FEE_BAL,
            to: TARGET_ACC.into()
        }
    );

    assert_eq!(
        ev,
        BridgeEvent::UnfreezeNft(UnfreezeNft {
            token_id: TOKEN_ID.clone(),
            burner: *XPNFT_ID,
            uri: NFT_URL.into()
        })
    );
}

#[async_test]
async fn withdraw_nft_batch_test() {
    init_context_user();

    let eid = withdraw_nft_batch(
        BLOCK_INDEX_TXFEE,
        *XPNFT_ID,
        vec![TOKEN_ID.clone(), TOKEN_ID.clone()],
        TARGET_NONCE,
        TARGET_ACC.into(),
    )
    .await;

    let (evctx, ev) = get_event(eid.clone()).unwrap();

    assert_eq!(
        evctx,
        BridgeEventCtx {
            action_id: eid,
            chain_nonce: TARGET_NONCE,
            tx_fee: TX_FEE_BAL,
            to: TARGET_ACC.into()
        }
    );

    assert_eq!(
        ev,
        BridgeEvent::UnfreezeNftBatch(UnfreezeNftBatch {
            token_ids: vec![TOKEN_ID.clone(), TOKEN_ID.clone()],
            burner: *XPNFT_ID,
            uris: vec![NFT_URL.into(), NFT_URL.into()]
        })
    );
}
