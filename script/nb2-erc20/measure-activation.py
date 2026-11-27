#!/usr/bin/env python3
"""Measure signed ERC20 activation transactions on a disposable loopback Cancun node."""

import argparse
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = "0xff00000000000000000000000000000000000002"
TX_GAS = 24_000_000
BLOCK_GAS = 86_802_168
USER_BLOCK_GAS = 60_000_000
POOL_INPUT_BYTES = 4_194_304
WALLET_BYTES = 524_288
CHAIN_ID = 1038
ERC20_PROFILE = "0x99773bbdfde2fa77cf43e029b61086a7eb121adfe57097872fc6ea9f0497e4d9"


def cast(*args):
    return subprocess.check_output(["cast", *args], text=True).strip()


def artifact(name, field):
    fixture = name in ("HostileToken", "ERC20ActivationBatch")
    source = "ERC20Bridge.t.sol" if fixture else f"{name}.sol"
    build = "out-fixture" if fixture and (ROOT / "out-fixture").exists() else "out"
    path = ROOT / build / source / f"{name}.json"
    return json.loads(path.read_text())[field]["object"]


def encode(signature, *args):
    return cast("abi-encode", signature, *args)[2:]


def send(endpoint, sender, *args):
    return json.loads(cast(
        "send", "--rpc-url", endpoint, "--json", "--unlocked", "--from", sender,
        "--gas-limit", str(TX_GAS), *args,
    ))


def status(receipt):
    assert int(str(receipt["status"]), 0) == 1, receipt


def deploy(endpoint, sender, name, constructor=""):
    r = send(endpoint, sender, "--create", artifact(name, "bytecode") + constructor)
    status(r)
    return r["contractAddress"]


def run(node, chain_id, widest, sdk_root):
    for line in node.stdout:
        match = re.fullmatch(r"Listening on (127\.0\.0\.1:\d+)\s*", line)
        if match:
            endpoint = "http://" + match[1]
            break
    else:
        raise RuntimeError("anvil did not provide its loopback listener")

    def rpc(method, *args):
        return json.loads(cast("rpc", "--rpc-url", endpoint, method, *args))

    def codehash(address):
        return cast("keccak", rpc("eth_getCode", address, "latest"))

    sender, other, *_ = rpc("eth_accounts")
    genesis = rpc("eth_getBlockByNumber", "0x0", "false")["hash"]
    rpc("anvil_setCode", REGISTRY, "0x600200")
    profile = ERC20_PROFILE if sdk_root else cast("keccak", "erc20 activation measurement")
    generation = cast("keccak", "erc20 activation generation")
    receipts = deploy(endpoint, sender, "FlatReceipts")
    lineage = deploy(endpoint, sender, "ERC20FlatLineage", encode("f(address)", receipts))
    ordinary = deploy(endpoint, sender, "ERC20BridgeVerifier", encode(
        "f(address,bytes32,bytes32,bytes32)", lineage, codehash(lineage), profile, codehash(REGISTRY),
    ))

    vault = artifact("ERC20BridgeVault", "bytecode")
    recovery = artifact("ERC20BridgeRecovery", "bytecode")
    zero = "0x" + "11" * 32
    network, evm, shard, agg, qmax = 3, 8, "0x80", 7, 10 ** 27
    if widest:
        network, evm, shard, agg, qmax = 65535, 2 ** 32 - 1, "0x" + "ff" * 32 + "80", 2 ** 32 - 2, 2 ** 144 - 1
    factory_args = encode(
        "f((uint16,bytes32,bytes32,uint32,bytes,uint32,uint144),"
        "(address,bytes32,bytes32,bytes32,bytes32,bytes32,(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)))",
        f"({network},{sdk_root or zero},{genesis},{evm},{shard},{agg},{qmax})",
        "(" + ",".join([ordinary, codehash(ordinary), profile, generation,
            cast("keccak", vault), cast("keccak", recovery), "(" + ",".join([zero] * 6) + ")"]) + ")",
    )
    factory = deploy(endpoint, sender, "ERC20BridgeFactory", factory_args)
    token = deploy(endpoint, sender, "HostileToken")
    if sdk_root:
        token_b = deploy(endpoint, sender, "HostileToken")
        batch = send(endpoint, sender, "--create", artifact("ERC20ActivationBatch", "bytecode") + encode(
            "f(address,address,address,bytes,bytes)", factory, token, token_b, vault, recovery,
        ))
        status(batch)
        assert len(batch["logs"]) == 2
        assets = []
        for token_address, log in zip((token, token_b), batch["logs"], strict=True):
            assert log["address"].lower() == factory.lower()
            assert "0x" + log["topics"][1][-40:] == token_address.lower()
            vault_address, recovery_address = ("0x" + topic[-40:] for topic in log["topics"][2:])
            data = cast("calldata", "config(address)", token_address)
            config = rpc("eth_call", json.dumps({"to": factory, "data": data}), "latest")
            actual = rpc("eth_call", json.dumps({"to": vault_address, "data": cast("calldata", "config()")}), "latest")
            assert actual == config
            assets.append({"token": token_address, "vault": vault_address, "recovery": recovery_address, "config": config})
        graph = [receipts, lineage, ordinary, factory] + [a[k] for a in assets for k in ("vault", "recovery")]
        print(json.dumps({
            "factory": factory, "ordinary": ordinary, "lineage": lineage, "receipts": receipts, "generation": generation,
            "genesis": rpc("eth_getBlockByNumber", "0x0", "false"), "assets": assets, "activation": batch,
            "vaultInitcodeHash": cast("keccak", vault), "recoveryInitcodeHash": cast("keccak", recovery),
            "code": {address.lower(): rpc("eth_getCode", address, "latest") for address in graph},
        }, separators=(",", ":")))
        return
    call = ["activate(address,bytes,bytes)", token, vault, recovery]
    data = cast("calldata", *call)
    rpc("evm_setAutomine", "false")
    pending = [cast("send", "--rpc-url", endpoint, "--unlocked", "--from", account,
                    "--gas-limit", str(TX_GAS), "--async", factory, data)
               for account in (sender, other)]
    rpc("evm_mine")
    rpc("evm_setAutomine", "true")
    raced = [rpc("eth_getTransactionReceipt", tx) for tx in pending]
    assert all(r is not None for r in raced)
    assert raced[0]["blockHash"] == raced[1]["blockHash"]
    activation, race_loser = sorted(raced, key=lambda r: len(r["logs"]), reverse=True)
    duplicate = send(endpoint, other, factory, cast("calldata", call[0], token, "0x", "0x"))
    entries = {}
    for label, receipt in [("activation", activation), ("racedDuplicate", race_loser), ("duplicate", duplicate)]:
        status(receipt)
        tx = rpc("eth_getTransactionByHash", receipt["transactionHash"])
        raw = rpc("eth_getRawTransactionByHash", receipt["transactionHash"])
        gas = int(str(receipt["gasUsed"]), 0)
        wire = bytes.fromhex(tx["input"][2:])
        signed = len(bytes.fromhex(raw[2:]))
        intrinsic = 21_000 + sum(16 if b else 4 for b in wire)
        assert gas <= TX_GAS and gas <= USER_BLOCK_GAS and gas <= BLOCK_GAS
        assert len(wire) <= POOL_INPUT_BYTES and signed <= WALLET_BYTES
        entries[label] = {
            "gasUsed": gas, "intrinsicGas": intrinsic, "calldataBytes": len(wire), "signedBytes": signed,
            "transaction": receipt["transactionHash"], "blockHash": receipt["blockHash"], "logs": len(receipt["logs"]),
        }
    assert [entries[key]["logs"] for key in ("activation", "racedDuplicate", "duplicate")] == [1, 0, 0]
    print(json.dumps({
        "network": {"chainId": chain_id, "maximumConfigWidths": widest, "genesis": genesis, "gasBid": TX_GAS, "blockGas": BLOCK_GAS},
        "comparisonLimits": {"lanePoolInputBytes": POOL_INPUT_BYTES, "walletSignedBytes": WALLET_BYTES,
            "laneTransactionGas": USER_BLOCK_GAS, "laneUserBlockGas": USER_BLOCK_GAS},
        "factoryInitcodeBytes": len(bytes.fromhex(artifact("ERC20BridgeFactory", "bytecode")[2:] + factory_args)),
        "instances": {name: codehash(address) for name, address in [
            ("receipts", receipts), ("lineage", lineage), ("ordinary", ordinary), ("factory", factory)]},
        **entries,
    }, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--max-config", action="store_true", help="use the largest legal configuration widths")
    mode.add_argument("--sdk-root", help="export a deployed ERC20-profile graph and batched activation for this fixture root trust pin")
    args = parser.parse_args()
    chain_id = 2 ** 64 - 1 if args.max_config else (31337 if args.sdk_root else CHAIN_ID)
    node = subprocess.Popen(
        ["anvil", "--host", "127.0.0.1", "--port", "0", "--hardfork", "cancun", "--chain-id",
         str(chain_id), "--gas-limit", str(BLOCK_GAS), "--disable-console-log",
         *(["--timestamp", "1700000000"] if args.sdk_root else [])],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    try:
        run(node, chain_id, args.max_config, args.sdk_root)
    finally:
        node.terminate()
        try:
            node.wait(timeout=5)
        except subprocess.TimeoutExpired:
            node.kill()
            node.wait()


if __name__ == "__main__":
    main()
