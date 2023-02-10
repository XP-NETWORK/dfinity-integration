use candid::export_service;
use crate::Sig;
use crate::{UpdateGroupKey, UpdatePrice, BridgeAction};
use candid::Nat;

#[ic_kit::macros::query(name = "__get_candid_interface_tmp_hack")]
fn export_candid() -> String {
    export_service!();
    __export_service()
}

#[test]
fn save_candid() {
    use std::env;
    use std::fs::write;
    use std::path::PathBuf;

    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let dir = dir.parent().unwrap().parent().unwrap().join("candid");
    write(dir.join("bucket.did"), export_candid()).expect("Write failed.");
}
