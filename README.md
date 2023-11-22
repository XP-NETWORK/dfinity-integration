# Converting ICP to cycles

## 1. Import your wallet pem

```shell
dfx identity import <IDENTITY> <WALLET_PEM>
```

## 2. Convert ICP to TC

```shell
dfx quickstart --identity <IDENTITY>
```

_Wasm is required to compile the canister._

```shell
rustup target add wasm32-unknown-unknown
```

## 3. Build the contract.

```shell
cargo build --target wasm32-unknown-unknown --release
```

## 4. Adding more cycles if not enough

```shell
dfx ledger --network ic top-up --amount <AMOUNT(ie 0.5)> <Your Wallet Canister Address>
```

## 5. Minter canister deployment

Make sure you have enough cycles in your account to deploy canisters.

Scheme: `dfx deploy minter --network ic --argument '(group_key, fee_public_key, chain_nonce, whitelist)'`

```shell
ie dfx deploy minter --network ic --argument '(vec {35;129;26;181;204;54;158;190;252;138;189;179;55;164;183;162;81;179;201;231;180;53;17;94;131;152;124;248;146;27;138;162}, vec {77;169;194;176;185;135;211;24;138;121;130;249;221;145;108;194;92;241;151;218;23;240;2;249;215;248;184;42;50;115;136;50}, 28, vec {"54aho-4iaaa-aaaap-aa3va-cai"})'
```

## 6. XPNFT canister deployment

Make sure you have enough cycles in your account to deploy canisters.

Scheme: `dfx deploy xpnft --network ic --argument '(bridge_address)'`

```shell
ie dfx deploy xpnft --network ic --argument '("53bb2-rqaaa-aaaap-aa3vq-cai")'
```
5. Deploy creator

```bash
dfx deploy creator --argument '(vec {principal "64sr6-x7vyc-6aa3t-5mma6-fkafb-6fubt-qr6da-kehuw-3bxem-htw7c-gqe" ; })' --network ic --identity dima
```