#[ic_cdk_macros::import(canister = "xpnft")]
struct XpWrapNft;

#[ic_cdk_macros::update]
async fn greet(url: String, to: String) -> candid::Nat {
    XpWrapNft::mint(url, to).await.0
}
