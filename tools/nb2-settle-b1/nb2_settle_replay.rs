//! NB2-C T4: the settlement custody fixtures through the vault on the real B1 precompiles. Run as an integration test in
//! reth-unicity-execution at the documented pin.
//! Fixture registry words stand in for authenticated execution state. Every
//! certificate and membership verdict comes from ureth's real B1 precompiles.

use alloy_evm::{Evm, EvmEnv, EvmFactory};
use alloy_primitives::{Address, B256, TxKind, U256, address, hex, keccak256};
use reth_unicity_b1::{Pins, REGISTRY};
use reth_unicity_execution::evm_factory::UnicityEvmFactory;
use revm::{
    Inspector,
    interpreter::{Interpreter, interpreter_types::MemoryTr},
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::result::{ExecutionResult, HaltReason, Output},
    database::{CacheDB, EmptyDB},
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
};
use serde_json::Value;
use std::{env, fs, path::{Path, PathBuf}};

const SENDER: Address = address!("1000000000000000000000000000000000000001");
const RECOVERY: Address = address!("000000000000000000000000000000000000f202");
const VAULT: Address = address!("000000000000000000000000000000000000f200");
const COLD_GAS: u64 = 24_000_000;
const FIXTURE_GAS: u64 = 1_000_000_000;

type Db = CacheDB<EmptyDB>;

fn raw(path: impl AsRef<Path>) -> Vec<u8> {
    fs::read(path.as_ref()).unwrap_or_else(|e| panic!("{}: {e}", path.as_ref().display()))
}

fn json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&raw(path)).unwrap()
}



fn pins(context: &Value) -> Pins {
    Pins {
        genesis_commitment: word(context["GenesisCommitment"].as_str().unwrap()),
        profile_hash: word(context["RegistryProfile"].as_str().unwrap()),
    }
}

fn word(hex_: &str) -> U256 {
    U256::from_be_slice(&hex::decode(hex_).unwrap())
}

fn install(db: &mut Db, addr: Address, code: Vec<u8>) {
    let code_hash = keccak256(&code);
    let code = Some(Bytecode::new_raw(code.into()));
    db.insert_account_info(addr, AccountInfo { code_hash, code, ..Default::default() });
}

fn context(db: &Db, pins: Pins) -> impl Evm<DB = Db, Tx = TxEnv, HaltReason = HaltReason> + use<> {
    let cfg = CfgEnv::new_with_spec(SpecId::CANCUN).with_chain_id(31337);
    let block = BlockEnv { gas_limit: FIXTURE_GAS, ..Default::default() };
    UnicityEvmFactory::new(pins).create_evm(db.clone(), EvmEnv::new(cfg, block))
}


const RECIPIENT: Address = address!("96f21e5603aff0a874383f28d66b2f68e6b51e2d");
const RECEIPTS: Address = address!("000000000000000000000000000000000000f201");
const K: u64 = 64;
const PAID: B256 = B256::new(hex_literal("606160394df2742a67735645b7e783304d61d2dbc5b550e8c6acfaf27b6291d7"));
const SEALED: B256 = B256::new(hex_literal("06e724201a1c72937156cbdb3b9522d26b3818ee33ace10cd7cda65bb9cae916"));

const fn hex_literal(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

fn ids(v: &Value, side: &str, which: &str) -> Vec<B256> {
    v[side][which].as_array().unwrap().iter().map(|x| B256::from_slice(&hex::decode(x.as_str().unwrap()).unwrap())).collect()
}

/// The vault storage the fixture describes: A, the two heads, both tag words and the live identifiers.
fn custody(v: &Value, side: &str) -> Vec<(U256, U256)> {
    let f = &v[side];
    let n = U256::from(f["Deposits"].as_u64().unwrap());
    let c = f["Segment"].as_u64().unwrap();
    let m = U256::from(f["Population"].as_u64().unwrap());
    let q: U256 = f["Liability"].as_str().unwrap().parse().unwrap();
    let mut out = vec![(U256::ZERO, (n << 200) | (U256::from(c) << 152) | (m << 144) | q)];
    out.push((U256::from(1 + (c & 1)), word(f["Head"].as_str().unwrap())));
    if c != 0 {
        out.push((U256::from(1 + ((c - 1) & 1)), word(f["PreviousHead"].as_str().unwrap())));
    }
    let mut buffers = vec![(c & 1, ids(v, side, "Current"))];
    if c != 0 {
        buffers.push(((c & 1) ^ 1, ids(v, side, "Previous")));
    }
    for (p, list) in buffers {
        let mut tags = U256::ZERO;
        for (i, id) in list.iter().enumerate() {
            tags |= (U256::from_be_slice(id.as_slice()) >> 252) << (4 * i);
            out.push((U256::from(16 + p * K + i as u64), U256::from_be_slice(id.as_slice())));
        }
        // Cells and tags beyond the live population are stale and never cleared.
        if !list.is_empty() || side == "Before" {
            out.push((U256::from(3 + p), tags));
        }
    }
    out
}

struct Run {
    result: ExecutionResult,
    state: revm::state::EvmState,
    memory: usize,
}

fn run(db: &Db, pins: Pins, target: Address, data: &[u8]) -> Run {
    let nonce = db.cache.accounts.get(&SENDER).unwrap().info.nonce;
    let cfg = CfgEnv::new_with_spec(SpecId::CANCUN).with_chain_id(31337);
    let block = BlockEnv { gas_limit: FIXTURE_GAS, ..Default::default() };
    let mut m = Measurement::default();
    let out = UnicityEvmFactory::new(pins)
        .create_evm_with_inspector(db.clone(), EvmEnv::new(cfg, block), &mut m)
        .transact_raw(TxEnv { caller: SENDER, kind: TxKind::Call(target), data: data.to_vec().into(), gas_limit: COLD_GAS, nonce, chain_id: Some(31337), ..Default::default() })
        .unwrap();
    assert!(m.memory <= 1 << 20, "peak EVM frame: {}", m.memory);
    Run { result: out.result, state: out.state, memory: m.memory }
}

#[derive(Default)]
struct Measurement {
    memory: usize,
}

impl<Context> Inspector<Context> for Measurement {
    fn step_end(&mut self, interpreter: &mut Interpreter, _: &mut Context) {
        self.memory = self.memory.max(interpreter.memory.size());
    }
}

fn storage(run: &Run, slot: U256) -> U256 {
    run.state.get(&VAULT).and_then(|a| a.storage.get(&slot)).map(|s| s.present_value).unwrap_or_default()
}

#[test]
fn settlement_custody_fixtures_on_native_b1() {
    let vectors = PathBuf::from(env::var_os("NB2_FLAT_VECTORS").expect("NB2_FLAT_VECTORS"));
    let out = PathBuf::from(env::var_os("NB2_SETTLE_OUT").expect("NB2_SETTLE_OUT"));
    let cases = vectors.join("transcripts");
    let fixture = json(cases.join("root/context.json"));
    let p = pins(&fixture);
    let hexcode = |name: &str| hex::decode(fs::read_to_string(out.join(name)).unwrap().trim().trim_start_matches("0x")).unwrap();
    let mut db = Db::new(EmptyDB::default());
    db.insert_account_info(SENDER, AccountInfo { balance: U256::from(10u64.pow(18)), ..Default::default() });
    install(&mut db, VAULT, hexcode("vault.hex"));
    install(&mut db, RECEIPTS, hexcode("receipts.hex"));
    install(&mut db, REGISTRY, vec![0x60, 0x02, 0x00]);
    for (slot, value) in fixture["Registry"].as_object().unwrap() {
        db.insert_account_storage(REGISTRY, word(slot), word(value.as_str().unwrap())).unwrap();
    }
    let mut names: Vec<_> = fs::read_dir(cases.join("cold")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).filter(|n| n.starts_with("settle-")).collect();
    names.sort();
    let mut settled = 0;
    for name in names {
        let dir = cases.join("cold").join(&name);
        let outcome = json(dir.join("outcome.json"));
        let calldata = raw(dir.join("calldata.bin"));
        let mut state = db.clone();
        // Replace the vault's storage with the fixture's Before custody.
        for (slot, value) in custody(&outcome, "Before") {
            state.insert_account_storage(VAULT, slot, value).unwrap();
        }
        let vault_balance: U256 = outcome["Before"]["VaultBalance"].as_str().unwrap().parse().unwrap();
        let mut info = state.cache.accounts.get(&VAULT).unwrap().info.clone();
        info.balance = vault_balance;
        state.insert_account_info(VAULT, info);
        let r = run(&state, p, VAULT, &calldata);
        let ExecutionResult::Success { logs, .. } = &r.result else { panic!("{name}: {:?}", r.result) };
        let paid = logs.iter().filter(|l| l.data.topics()[0] == PAID).count();
        let sealed = logs.iter().filter(|l| l.data.topics()[0] == SEALED).count();
        assert_eq!(paid, 1, "{name}");
        assert_eq!(sealed, usize::from(name.contains("seal")), "{name}");
        // The state diff lists touched slots only; an untouched slot keeps its Before value.
        let before: std::collections::HashMap<U256, U256> = custody(&outcome, "Before").into_iter().collect();
        for (slot, value) in custody(&outcome, "After") {
            let actual = r.state.get(&VAULT).and_then(|a| a.storage.get(&slot)).map(|s| s.present_value)
                .unwrap_or_else(|| before.get(&slot).copied().unwrap_or_default());
            assert_eq!(actual, value, "{name} slot {slot}");
        }
        let after: U256 = outcome["After"]["RecipientBalance"].as_str().unwrap().parse().unwrap();
        assert_eq!(r.state.get(&RECIPIENT).map(|a| a.info.balance).unwrap_or_default(), after, "{name}");
        println!("{name} bytes={} gas={} memory={}", calldata.len(), r.result.gas().total_gas_spent(), r.memory);
        settled += 1;
    }
    assert_eq!(settled, 10);
    println!("{settled} settlement fixtures paid once on the real B1 runtime");
}
