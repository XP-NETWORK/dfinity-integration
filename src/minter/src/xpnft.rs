use std::{collections::BTreeMap, iter::FromIterator};

use candid::Principal;
use ic_cdk::api::call::CallResult;
use num_traits::ToPrimitive;

use crate::types::icrc7::{self, ICRC7Metadata, MetadataValue, MintArgs, TransferArgs};

pub async fn mint(canister: Principal, _id: u128, mint_args: MintArgs) -> u128 {
    let (result,): (u128,) = ic_cdk::call(canister, "icrc7_mint", (mint_args,))
        .await
        .unwrap();
    result
}

pub async fn burn(canister: Principal, id: u128) -> u128 {
    let (result,): (u128,) = ic_cdk::call(canister, "icrc7_burn", (id,)).await.unwrap();
    result
}

pub async fn transfer(canister: Principal, from: Principal, to: Principal, id: u128) -> u128 {
    let (result,): (CallResult<u128>,) = ic_cdk::call(
        canister,
        "icrc7_transfer",
        (TransferArgs {
            created_at_time: Some(ic_cdk::api::time()),
            from: icrc7::Account {
                owner: from,
                subaccount: None,
            },
            to: icrc7::Account {
                owner: to,
                subaccount: None,
            },
            is_atomic: None,
            token_ids: vec![id],
            memo: None,
            spender_subaccount: None,
        },),
    )
    .await
    .unwrap();
    result.unwrap()
}

pub async fn metadata(canister: Principal, id: u128) -> ICRC7Metadata {
    let (result,): (Vec<(String, MetadataValue)>,) =
        ic_cdk::call(canister, "icrc7_metadata", (id,))
            .await
            .unwrap();

    let map = BTreeMap::from_iter(result.into_iter());

    let name = map.get("Name").and_then(|v| match v {
        MetadataValue::Text(name) => Some(name.clone()),
        _ => None,
    });
    let id = map.get("Id").and_then(|v| match v {
        MetadataValue::Nat(ind) => Some(ind.0.to_u128().unwrap()),
        _ => None,
    });
    let image = map.get("Image").and_then(|v| match v {
        MetadataValue::Blob(image) => Some(image.clone()),
        _ => None,
    });
    let description = map.get("Description").and_then(|v| match v {
        MetadataValue::Text(desc) => Some(desc.clone()),
        _ => None,
    });
    let xp_metadata = map.get("Xp Nft Meta").and_then(|v| match v {
        MetadataValue::Text(meta) => Some(meta.clone()),
        _ => None,
    });
    ICRC7Metadata {
        id: id.unwrap(),
        name: name.unwrap_or_default(),
        image,
        description,
        xp_metadata,
    }
}
