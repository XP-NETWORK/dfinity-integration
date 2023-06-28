### How to convert ICP to cycles -
Import your wallet pem = dfx identity import <IDENTITY> <WALLET_PEM>
Convert ICP to TC - dfx quickstart --identity <IDENTITY>

** Wasm is needed to compile canister **
>> rustup target add wasm32-unknown-unknown

** Then Build the contract **
>> cargo build --target wasm32-unknown-unknown --release

### Minter

Make sure you have enough cycles in your account to deploy canisters.

**_ dfx deploy minter --network ic --argument '(group_key, fee_public_key, chain_nonce, whitelist)' _**

ie dfx deploy minter --network ic --argument '(vec {35;129;26;181;204;54;158;190;252;138;189;179;55;164;183;162;81;179;201;231;180;53;17;94;131;152;124;248;146;27;138;162}, vec {77;169;194;176;185;135;211;24;138;121;130;249;221;145;108;194;92;241;151;218;23;240;2;249;215;248;184;42;50;115;136;50}, 28, vec {"54aho-4iaaa-aaaap-aa3va-cai"})'

### XPNFT

Make sure you have enough cycles in your account to deploy canisters.

**_ dfx deploy xpnft --network ic --argument '(bridge_address)' _**

ie dfx deploy xpnft --network ic --argument '("53bb2-rqaaa-aaaap-aa3vq-cai")'
