//! Run as an integration test in reth-unicity-execution at the documented pin.
//! Fixture registry words stand in for authenticated execution state. Every
//! certificate and membership verdict comes from ureth's real B1 precompiles.

use alloy_evm::{Evm, EvmEnv, EvmFactory};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, address, hex, keccak256};
use alloy_sol_types::SolValue;
use reth_unicity_b1::{Pins, REGISTRY};
use reth_unicity_execution::evm_factory::UnicityEvmFactory;
use revm::{
    DatabaseCommit, Inspector,
    interpreter::{CallInputs, CallOutcome, Interpreter, interpreter_types::MemoryTr},
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

fn artifact(out: &Path, source: &str, contract: &str) -> Vec<u8> {
    let doc = json(out.join(source).join(format!("{contract}.json")));
    hex::decode(doc["bytecode"]["object"].as_str().unwrap()).unwrap()
}

fn field<'a>(cursor: &mut &'a [u8]) -> &'a [u8] {
    let n = u32::from_be_bytes(cursor[..4].try_into().unwrap()) as usize;
    let (field, rest) = cursor[4..].split_at(n);
    *cursor = rest;
    field
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

fn deploy(
    db: &mut Db, pins: Pins, nonce: u64, mut init: Vec<u8>, args: Vec<u8>
) -> (Address, Vec<u8>) {
    init.extend(args);
    let mut evm = context(db, pins);
    let result = evm.transact_raw(TxEnv {
        caller: SENDER, kind: TxKind::Create, data: init.into(), gas_limit: COLD_GAS,
        nonce, chain_id: Some(31337), ..Default::default()
    }).unwrap();
    let ExecutionResult::Success { output: Output::Create(code, Some(address)), .. } = result.result
        else { panic!("fixture deployment failed: {:?}", result.result) };
    db.commit(result.state);
    (address, code.to_vec())
}

#[derive(Default)]
struct Measurement {
    memory: usize,
    certificate_calls: usize,
    membership_calls: usize,
}

impl<Context> Inspector<Context> for Measurement {
    fn step_end(&mut self, interpreter: &mut Interpreter, _: &mut Context) {
        self.memory = self.memory.max(interpreter.memory.size());
    }

    fn call(&mut self, _: &mut Context, inputs: &mut CallInputs) -> Option<CallOutcome> {
        match inputs.bytecode_address {
            address if address == reth_unicity_b1::Operation::CertBatch.address() => self.certificate_calls += 1,
            address if address == reth_unicity_b1::Operation::Member.address() => self.membership_calls += 1,
            _ => {}
        }
        None
    }
}

fn call(db: &Db, pins: Pins, target: Address, data: &[u8], gas_limit: u64) -> (ExecutionResult, Measurement) {
    let nonce = db.cache.accounts.get(&SENDER).unwrap().info.nonce;
    let cfg = CfgEnv::new_with_spec(SpecId::CANCUN).with_chain_id(31337);
    let block = BlockEnv { gas_limit: FIXTURE_GAS, ..Default::default() };
    let mut measurement = Measurement::default();
    let result = UnicityEvmFactory::new(pins)
        .create_evm_with_inspector(db.clone(), EvmEnv::new(cfg, block), &mut measurement)
        .transact_raw(TxEnv {
            caller: SENDER, kind: TxKind::Call(target), data: data.to_vec().into(), gas_limit,
            nonce, chain_id: Some(31337), ..Default::default()
        }).unwrap().result;
    assert!(measurement.memory <= 1 << 20, "peak EVM frame: {}", measurement.memory);
    (result, measurement)
}

fn config(gamma: &[u8]) -> (B256, u16, u32, u32, Bytes, Address, B256, B256) {
    // The golden domain and its two artifact-derived identity fields are loaded
    // by the caller. Other constants are fixed by §9.
    (B256::ZERO, 3, 7, 11, Bytes::from_static(&[0x80]), VAULT,
        B256::from_slice(&gamma[151..183]), B256::from_slice(&gamma[185..217]))
}

fn check_event(case: &str, result: &ExecutionResult, topics: &[u8], data: &[u8]) -> u64 {
    let ExecutionResult::Success { logs, .. } = result else { panic!("{case}: {result:?}") };
    assert_eq!(logs.len(), 1, "{case}");
    assert_eq!(logs[0].address, RECOVERY, "{case}");
    let actual: Vec<u8> = logs[0].data.topics().iter().flat_map(|t| t.as_slice().to_vec()).collect();
    assert_eq!(actual, topics, "{case}");
    assert_eq!(logs[0].data.data.as_ref(), data, "{case}");
    result.gas().total_gas_spent()
}

#[test]
fn signed_nb2_flat_transcripts_on_native_b1() {
    let vectors = PathBuf::from(env::var_os("NB2_FLAT_VECTORS").expect("NB2_FLAT_VECTORS"));
    let out = PathBuf::from(env::var_os("NB2_FLAT_FORGE_OUT").expect("NB2_FLAT_FORGE_OUT"));
    let cases = vectors.join("transcripts");
    let gamma: Bytes = raw(vectors.join("gamma.bin")).into();
    let fixture = json(cases.join("root/context.json"));
    let fixture_pins = pins(&fixture);
    let mut db = Db::new(EmptyDB::default());
    db.insert_account_info(SENDER, AccountInfo { balance: U256::from(10u64.pow(18)), ..Default::default() });

    let (receipts, _) = deploy(&mut db, fixture_pins, 0, artifact(&out, "FlatReceipts.sol", "FlatReceipts"), vec![]);
    let (lineage, _) = deploy(&mut db, fixture_pins, 1, artifact(&out, "FlatLineage.sol", "FlatLineage"), (receipts,).abi_encode_params());
    let (ordinary, _) = deploy(&mut db, fixture_pins, 2, artifact(&out, "FlatHarness.sol", "CorpusOrdinary11"), (lineage,).abi_encode_params());
    let mut cfg = config(&gamma);
    cfg.0 = B256::from_slice(&raw(vectors.join("domain.bin")));
    let dep_pins = B256::from_slice(&raw(vectors.join("pins.bin")));
    let generation = B256::from_slice(&raw(vectors.join("generation.bin")));
    let recovery_hash = keccak256([0x60, 0x03, 0x00]);
    let (_, recovery_code) = deploy(
        &mut db, fixture_pins, 3, artifact(&out, "FlatHarness.sol", "CorpusRecovery11"),
        (cfg, lineage, receipts, dep_pins, generation, recovery_hash).abi_encode_params(),
    );
    install(&mut db, RECOVERY, recovery_code);
    install(&mut db, REGISTRY, vec![0x60, 0x02, 0x00]);

    for name in ["root", "transfers", "one-split", "depth-20", "transfers-600", "parent-over-32-pages", "shared-claim", "alternate-certificate", "capped-root", "combined-large-receipt-and-paths"] {
        let case = cases.join(name);
        let fixture = json(case.join("context.json"));
        let p = pins(&fixture);
        let mut state = db.clone();
        for (slot, value) in fixture["Registry"].as_object().unwrap() {
            state.insert_account_storage(REGISTRY, word(slot), word(value.as_str().unwrap())).unwrap();
        }
        let evidence: Bytes = raw(case.join("evidence.bin")).into();
        let mut input = keccak256("verifyReturn(bytes,bytes)")[..4].to_vec();
        input.extend((gamma.clone(), evidence).abi_encode_params());
        let (result, measured) = call(&state, p, ordinary, &input, FIXTURE_GAS);
        assert!(result.is_success(), "{name} ordinary: {result:?}");
        assert_eq!(result.output().unwrap().as_ref(), &raw(case.join("verdict.bin")));
        println!("{name} ordinary bytes={} gas={} memory={} cert={} member={}", input.len(), result.gas().total_gas_spent(), measured.memory, measured.certificate_calls, measured.membership_calls);

        let trace = raw(case.join("trace.bin"));
        let mut cursor = trace.as_slice();
        let mut index = 0;
        let (mut sum, mut max_gas, mut max_bytes) = (0u64, 0u64, 0usize);
        while !cursor.is_empty() {
            let packet = field(&mut cursor);
            let _incoming = field(&mut cursor);
            let _outgoing = field(&mut cursor);
            let topics = field(&mut cursor);
            let data = field(&mut cursor);
            let _receipt = field(&mut cursor);
            let (result, measured) = call(&state, p, RECOVERY, packet, COLD_GAS);
            let gas = check_event(&format!("{name}/{index}"), &result, topics, data);
            println!("{name} packet={index} bytes={} gas={gas} memory={} cert={} member={}", packet.len(), measured.memory, measured.certificate_calls, measured.membership_calls);
            sum += gas;
            max_gas = max_gas.max(gas);
            max_bytes = max_bytes.max(packet.len());
            index += 1;
        }
        println!("{name} packets={index} max_bytes={max_bytes} max_gas={max_gas} total_gas={sum}");
    }

    for (slot, value) in fixture["Registry"].as_object().unwrap() {
        db.insert_account_storage(REGISTRY, word(slot), word(value.as_str().unwrap())).unwrap();
    }
    for entry in fs::read_dir(cases.join("cold")).unwrap() {
        let case = entry.unwrap().path();
        let name = case.file_name().unwrap().to_str().unwrap();
        if !name.starts_with("advance-") { continue; }
        let packet = raw(case.join("calldata.bin"));
        let event = raw(case.join("event.bin"));
        let (result, measured) = call(&db, fixture_pins, RECOVERY, &packet, COLD_GAS);
        let gas = check_event(name, &result, &event[..64], &event[64..]);
        println!("{name} bytes={} gas={gas} memory={} cert={} member={}", packet.len(), measured.memory, measured.certificate_calls, measured.membership_calls);
    }
    let run = keccak256("run(bytes)");
    let advance = keccak256("advanceGaps(bytes)");
    let mut refusals = 0;
    let mut retries = 0;
    let mut paths: Vec<_> = fs::read_dir(cases.join("refusals"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    for case in paths {
        let packet = raw(case.join("calldata.bin"));
        if packet[..4] != run[..4] && packet[..4] != advance[..4] {
            continue; // Settlement is exercised by T4.
        }
        let name = case.file_name().unwrap().to_str().unwrap();
        let stage = fs::read_to_string(case.join("stage.txt")).unwrap();
        let expected = keccak256(format!("{}()", stage.trim()));
        let (result, _) = call(&db, fixture_pins, RECOVERY, &packet, COLD_GAS);
        let ExecutionResult::Revert { output, .. } = result else {
            panic!("{name}: {result:?}");
        };
        assert_eq!(output.as_ref(), &expected[..4], "{name}");
        refusals += 1;
        let retry = case.join("retry-calldata.bin");
        if retry.exists() {
            let (result, _) = call(&db, fixture_pins, RECOVERY, &raw(retry), COLD_GAS);
            assert!(result.is_success(), "{name} retry: {result:?}");
            assert_eq!(result.logs().len(), 1, "{name} retry");
            retries += 1;
        }
    }
    assert_eq!(refusals, 36);
    assert_eq!(retries, 29);
    println!("{refusals} published recovery refusals, {retries} successful retries");

}
