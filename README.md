### How to convert ICP to cycles -
1. Import your wallet 
   Structure: `dfx identity import <IDENTITY> <WALLET_PEM>`
    Example:
   ```bash
   dfx identity import dima ./dfinity.pem
   ```

2. Convert ICP to TC - 
   Structure: `dfx quickstart --identity <IDENTITY>`
   Example:
   ```bash
   dfx quickstart --identity dima
   ```
   Example output, questions and answers:
   ```bash
   Your DFX user principal: tc446-lek6d-tkkcf-dqjfl-bax66-5wfwr-mgnyf-6u3dr-4ibue-zky4o-6qe
   Your ledger account address: 1edcee2ef5cebda5dd1dae03eec294fac1df8258e7ef600bfd9efacb24caae9b
   Your ICP balance: 3.30000836 ICP
   Conversion rate: 1 ICP <> 3.3225 XDR
   Import an existing wallet? no
   Spend 3.00978179 ICP to create a new wallet with 10 TC? yes
   ⠒ Sending 3.00978179 ICP to the cycles minting canister...
     Sent 3.00978179 ICP to the cycles minting canister at height 6400579
     Created wallet canister with principal ID necbt-viaaa-aaaan-qd3jq-cai
     Installed the wallet code to the canister
   Success! Run this command again at any time to print all this information again.
   ```

#### Wasm is required to compile the canister
>> rustup target add wasm32-unknown-unknown

#### To Build the contract
```bash
cargo build --target wasm32-unknown-unknown --release
```

### Minter

Make sure you have enough cycles in your account to deploy canisters.

Convert all the below parameters to bytes like so: 
```ts 
// Group Key
const group_key = "";
console.log("GK:", [...Buffer.from(group_key, "hex")]);

// Fee Public Key
const fee_public_key = "";
console.log("GK:", [...Buffer.from(fee_public_key, "hex")]);
```

Scheme:
`dfx deploy minter --network ic --argument '(group_key, fee_public_key, chain_nonce, whitelist)'`

Development bucket example:

ie dfx deploy minter --network ic --argument '(vec {35;129;26;181;204;54;158;190;252;138;189;179;55;164;183;162;81;179;201;231;180;53;17;94;131;152;124;248;146;27;138;162}, vec {77;169;194;176;185;135;211;24;138;121;130;249;221;145;108;194;92;241;151;218;23;240;2;249;215;248;184;42;50;115;136;50}, 28, vec {"54aho-4iaaa-aaaap-aa3va-cai"})'

Production bucket example:

```bash
dfx deploy minter --network ic --argument '(vec {}, vec {}, 28, vec {"pk6rk-6aaaa-aaaae-qaazq-cai";"bzsui-sqaaa-aaaah-qce2a-cai";"oeee4-qaaaa-aaaak-qaaeq-cai";"dhiaa-ryaaa-aaaae-qabva-cai";"skjpp-haaaa-aaaae-qac7q-cai";"bxdf4-baaaa-aaaah-qaruq-cai";"rw623-hyaaa-aaaah-qctcq-cai";"e3izy-jiaaa-aaaah-qacbq-cai";"vlhm2-4iaaa-aaaam-qaatq-cai";"5movr-diaaa-aaaak-aaftq-cai";"yrdz3-2yaaa-aaaah-qcvpa-cai";"3mttv-dqaaa-aaaah-qcn6q-cai";"ugdkf-taaaa-aaaak-acoia-cai";"3vdxu-laaaa-aaaah-abqxa-cai";"4ggk4-mqaaa-aaaae-qad6q-cai";"gtb2b-tiaaa-aaaah-qcxca-cai";"j3dqa-byaaa-aaaah-qcwfa-cai";"txr2a-fqaaa-aaaah-qcmkq-cai";"txr2a-fqaaa-aaaah-qcmkq-cai"})' --identity dima
```

### XPNFT

Make sure you have enough cycles in your account to deploy canisters.

`dfx deploy xpnft --network ic --argument '(bridge_address)'`

Development example:
`dfx deploy xpnft --network ic --argument '("53bb2-rqaaa-aaaap-aa3vq-cai")'`
Productioin Example:
`dfx deploy xpnft --network ic --argument '("nwewk-zyaaa-aaaan-qd3kq-cai")' --identity dima`


### UMT

UserNftMinter is a contract where anybody can mint NFT (usually for testing purposes)

Production example:

```bash
dfx deploy umt --network ic  --identity dima
```

### Staging contracts

minter: https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=coptt-jaaaa-aaaap-qbjbq-cai
umt: https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=cvkpw-tyaaa-aaaap-qbjda-cai
xpnft: https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=c4jek-fqaaa-aaaap-qbjcq-cai

### Production contracts

minter: https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=nwewk-zyaaa-aaaan-qd3kq-cai
umt: https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=mvi7m-naaaa-aaaan-qd3ma-cai
xpnft: https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=n7h5w-pqaaa-aaaan-qd3la-cai