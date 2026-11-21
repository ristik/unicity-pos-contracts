// Run from the pinned T2 package's scripts directory. Signing and proof checks
// use the T2 SDK. This driver constructs only the T3 transport and checkpoints.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { concat, fromHex, toHex } from '../src/bytes.js';
import { SdkAggregator } from '../src/nb2/aggregator.js';
import { ascii, be, beInt, bstr, raw, scanNative, scanOne, u16, u64, u256 } from '../src/nb2/cbor.js';
import { ASSET_UCT, deriveCoin, deriveType, domainOf, encodeConfig, PRODUCTION_PARAMS, type Config } from '../src/nb2/config.js';
import { HE, HU } from '../src/nb2/crypto.js';
import { decodeDepositProof, decodeReceiptBacking, depositSalt, encodeReceiptBacking, firstOwnerOf, rhoOf } from '../src/nb2/deposit.js';
import { GapTree, genesisHead, nextHead } from '../src/nb2/segment.js';
import { decodeSplitManifest, parentLink } from '../src/nb2/split.js';
import { burnPredicate, decodeToken, encodeLevel, encodeProof, lineageOf, resultState, signaturePredicate, stateId, tokenIdOf, valueData } from '../src/nb2/token.js';
import { appendTransfer, certifyChecked, childMint, localOwner, mintRequest, splitPlan, tokenOfChild, tokenOfMint, transferRequest } from '../src/nb2/tokenops.js';
import { TrustInput } from '../src/nb2/trust.js';
import { encodeReturnData, verdictAbi, verifyReturn, verifySplit } from '../src/nb2/verify.js';

const [out, rpc, aggregator, chain, artifacts, proofTool] = process.argv.slice(2);
const registry = '0xff00000000000000000000000000000000000002';
const senderKey = '0x' + readFileSync(join(out, 'sender.key'), 'utf8').trim().replace(/^0x/, '');
const owner = localOwner(randomBytes(32));
const secret = randomBytes(32);
const ZERO = new Uint8Array(32);
const hex = (input: Uint8Array) => '0x' + toHex(input);
const bytes = (input: string) => fromHex(input.trim().replace(/^0x/, ''))!;
const h = (label: string, ...fields: Uint8Array[]) => HE(HE(ascii('UNICITY/NB2/CONT/1.1/' + label)), ...fields);
const layout = (x: Uint8Array) => concat(be(x.length, 4), x);
const encodeCall = (signature: string, arg: Uint8Array) => concat(
  HE(ascii(signature)).subarray(0, 4), u256(32), u256(arg.length), arg, new Uint8Array((32 - arg.length % 32) % 32),
);

function command(name: string, args: string[]): string {
  const r = spawnSync(name, args, { encoding: 'utf8', maxBuffer: 8 << 20 });
  if (r.status !== 0) throw new Error(`${name} failed: ${r.stderr || r.error || r.stdout}`);
  return r.stdout.trim();
}

type Log = { topics: string[]; data: string };
function send(name: string, ...args: string[]) {
  const start = Date.now();
  const tx = JSON.parse(command('cast', ['send', '--json', '--rpc-url', rpc, '--private-key', senderKey, '--gas-limit', '24000000', ...args]));
  assert.equal(tx.status, '0x1', name);
  const fullTx = JSON.parse(command('cast', ['rpc', '--rpc-url', rpc, 'eth_getTransactionByHash', tx.transactionHash]));
  const signedTx = command('cast', ['rpc', '--rpc-url', rpc, 'eth_getRawTransactionByHash', tx.transactionHash]);
  const signedBytes = bytes(JSON.parse(signedTx)).length;
  writeFileSync(join(out, name + '.json'), JSON.stringify(tx, null, 2));
  console.log(JSON.stringify({ name, tx: tx.transactionHash, block: Number(tx.blockNumber), gas: Number(tx.gasUsed),
    bytes: bytes(fullTx.input).length, signedBytes, inclusionMs: Date.now() - start }));
  return tx as { contractAddress: string; transactionHash: string; logs: Log[] };
}

function deploy(name: string, args = '0x') {
  const code = JSON.parse(readFileSync(join(artifacts, name + '.sol', name + '.json'), 'utf8')).bytecode.object;
  const init = code + args.slice(2);
  const tx = send(name, '--create', init);
  writeFileSync(join(out, name + '.initcode'), bytes(init));
  return tx.contractAddress;
}
const abi = (signature: string, ...args: string[]) => command('cast', ['abi-encode', signature, ...args]);
const codehash = (address: string) => bytes(command('cast', ['codehash', '--rpc-url', rpc, address]));
function receipt(name: string, tx: ReturnType<typeof send>, emitter: string) {
  const start = Date.now();
  const path = join(out, name + '.cbor');
  command(proofTool, ['receipt', '-rpc', rpc, '-tx', tx.transactionHash, '-emitter', emitter, '-topic0', tx.logs[0].topics[0], '-out', path]);
  const proof = readFileSync(path);
  console.log(JSON.stringify({ name, proofBytes: proof.length, acquisitionMs: Date.now() - start }));
  return proof;
}

const receipts = deploy('FlatReceipts');
const lineage = deploy('FlatLineage', abi('f(address)', receipts));
const descriptors = ['cert', 'member', 'layout', 'execution', 'build', 'vectors'].map(
  (name) => HU(readFileSync(join(out, name + '.descriptor'))),
);
const profile = HU(readFileSync(join(out, 'profile.json')));
const ordinary = deploy('NativeBridgeVerifier11', abi('f(address,bytes32,bytes32,bytes32)',
  lineage, hex(codehash(lineage)), hex(profile), hex(codehash(registry))));
const vault = deploy('LaneDeposit11');
const rootGenesis = bytes(readFileSync(join(out, 'trust.pin'), 'utf8'));
const executionGenesis = bytes(readFileSync(join(out, 'execution.pin'), 'utf8'));
const chainId = BigInt(chain);
const c: Config = {
  network: 3, rootGenesis, executionGenesis, chainId, evmPartition: 8, evmShard: Uint8Array.of(0x80),
  aggregatorPartition: 7, vault: bytes(vault), asset: ASSET_UCT, ty: deriveType(3, rootGenesis, executionGenesis, chainId),
  aid: deriveCoin(3, rootGenesis, executionGenesis, chainId), semanticProfileHash: profile, verifier: bytes(ordinary),
  verifierCodeHash: codehash(ordinary), K: 64n, B: 16n, Qmax: 10n ** 30n,
};
const gamma = encodeConfig(c);
const d = domainOf(gamma);
const record = (role: number, addr: string, digest: Uint8Array) => concat(u16(role), bytes(addr), digest);
const pins = h('PINS', h('RELEASE', ...descriptors), u16(6),
  record(1, ordinary, codehash(ordinary)), record(2, receipts, codehash(receipts)),
  record(3, '0000000000000000000000000000000000000100', descriptors[0]),
  record(4, '0000000000000000000000000000000000000102', descriptors[1]),
  record(5, registry, h('REGISTRY', codehash(registry), descriptors[2])), record(256, lineage, codehash(lineage)),
);
const salt = randomBytes(32);
const recovery = deploy('NativeBridgeRecovery11',
  abi('f(bytes,address,bytes32,(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32),bytes32)',
    hex(gamma), ordinary, hex(salt), '(' + descriptors.map(hex).join(',') + ')', hex(pins)));
writeFileSync(join(out, 'gamma.bin'), gamma);
writeFileSync(join(out, 'manifest.json'), JSON.stringify({
  ordinary, receipts, lineage, vault, recovery, pins: hex(pins), salt: hex(salt), domain: hex(d),
  runtime: Object.fromEntries([ordinary, receipts, lineage, vault, recovery, registry].map((a) => [a, hex(codehash(a))])),
}, null, 2));

const depositAmount = 9n;
const depositTx = send('deposit', vault, 'deposit(bytes,bytes32,bytes32)', hex(firstOwnerOf(owner.publicKey)),
  hex(rhoOf(d, secret)), hex(d), '--value', depositAmount.toString());
const j = { d, r: secret, n: 1n, proof: decodeDepositProof(receipt('deposit', depositTx, vault)) };
const agg = new SdkAggregator(aggregator, { allowInsecure: true });
const trust = await TrustInput.fromBundle(readFileSync(join(out, 'trust.cbor')), c.rootGenesis);
const root = mintRequest({
  network: c.network, recipient: signaturePredicate(owner.publicKey), salt: depositSalt(d, 1n, secret), type: c.ty,
  justification: encodeReceiptBacking(j), data: valueData(c.aid, depositAmount), deadline: null,
});
let token = tokenOfMint(root.tx, await certifyChecked(agg, root.cd));
async function spend(transfer: Parameters<typeof transferRequest>[2]) {
  const request = await transferRequest(token, owner, transfer);
  token = appendTransfer(token, request.tx, await certifyChecked(agg, request.cd));
}
await spend({ recipient: signaturePredicate(owner.publicKey), mask: randomBytes(32), data: null, deadline: null });
const split = splitPlan(decodeToken(token), [
  { ownerKey: owner.publicKey, amount: 8n, salt: randomBytes(32) },
  { ownerKey: owner.publicKey, amount: 1n, salt: randomBytes(32) },
], c.ty, c.aid, randomBytes(32));
await spend(split.burn);
const verifiedSplit = await verifySplit(c, d, trust, decodeToken(token));
const child = childMint(verifiedSplit.link, split.tree, split.children[0]);
const mint = mintRequest(child.mint);
token = tokenOfChild(token, child.allocation, mint.tx, await certifyChecked(agg, mint.cd));
const returnData = encodeReturnData({ d, asset: c.asset, recipient: bytes('0000000000000000000000000000000000000011'),
  amount: 8n, minIndex: 0n });
await spend({ recipient: burnPredicate(HU(returnData)), mask: randomBytes(32), data: returnData, deadline: null });
const expected = verdictAbi(await verifyReturn(gamma, token, trust, PRODUCTION_PARAMS));
writeFileSync(join(out, 'evidence.bin'), token);
const levels = lineageOf(decodeToken(token));
const roundSlot = hex(HE(ascii('unicity.seal-registry/clock.rootRound')));
const sealRound = (uc: Uint8Array) => scanNative(uc).kids[0].kids[6].kids[0].kids[2].arg;

async function awaitOrigin(ucs: Uint8Array[]) {
  const target = ucs.map(sealRound).reduce((max, round) => round > max ? round : max, 0n);
  for (let i = 0; i < 60; ++i) {
    const round = BigInt(command('cast', ['storage', '--rpc-url', rpc, registry, roundSlot]));
    if (round >= target) {
      console.log(JSON.stringify({ certifiedRootRound: Number(target), executionOrigin: Number(round) }));
      return;
    }
    await delay(1000);
  }
  throw new Error(`execution origin did not reach certified root round ${target}`);
}
await awaitOrigin([j.proof.uc, ...levels.flatMap((level) => [level.mintProof.uc, ...level.proofs.map((p) => p.uc)])]);

const ordinaryData = command('cast', ['calldata', 'verifyReturn(bytes,bytes)', hex(gamma), hex(token)]);
try {
  assert.equal(command('cast', ['call', '--rpc-url', rpc, ordinary, '--data', ordinaryData]), hex(expected));
} catch (error) {
  const trace = command('cast', ['rpc', '--rpc-url', rpc, 'debug_traceCall',
    JSON.stringify({ to: ordinary, data: ordinaryData, gas: '0x16e3600' }), 'latest',
    JSON.stringify({ tracer: 'callTracer' })]);
  writeFileSync(join(out, 'ordinary-refusal.json'), trace);
  throw error;
}
send('ordinary', ordinary, '--data', ordinaryData);

// Leaf-first sparse storage stores only the nonempty branches.
class Sparse {
  readonly empty = [ZERO];
  readonly layers = Array.from({ length: 257 }, () => new Map<bigint, Uint8Array>());
  constructor(readonly label: string) {
    for (let i = 0; i < 256; ++i) this.empty.push(h(label, this.empty[i], this.empty[i]));
  }
  root() { return this.layers[256].get(0n) ?? this.empty[256]; }
  path(key: Uint8Array) {
    let k = beInt(key), bitmap = 0n;
    const siblings: Uint8Array[] = [];
    for (let i = 0; i < 256; ++i, k >>= 1n) {
      const sibling = this.layers[i].get(k ^ 1n);
      if (sibling) { bitmap |= 1n << BigInt(i); siblings.push(sibling); }
    }
    return concat(u256(bitmap), ...siblings);
  }
  insert(key: Uint8Array, leaf: Uint8Array) {
    let k = beInt(key);
    for (let i = 0; i < 256; ++i, k >>= 1n) {
      this.layers[i].set(k, leaf);
      const sibling = this.layers[i].get(k ^ 1n) ?? this.empty[i];
      leaf = k & 1n ? h(this.label, sibling, leaf) : h(this.label, leaf, sibling);
    }
    this.layers[256].set(0n, leaf);
  }
}

function claim(uc: Uint8Array, partition: number) {
  const [ , ir, , shardConfig, shardTree, , seal ] = scanNative(uc).kids[0].kids;
  const [, shard] = shardTree.kids[0].kids;
  const prefix = concat(be(partition, 4), u16(bstr(shard).length), bstr(shard));
  const state = bstr(ir.kids[0].kids[4]);
  return {
    key: h('CLAIM_KEY', HU(raw(uc, seal)), prefix),
    value: h('CLAIM_VALUE', HU(concat(prefix, bstr(shardConfig), state, HU(raw(uc, ir)), layout(uc)))),
  };
}

let pos = 14;
const ops = levels.flatMap((l, level) => {
  const prefixLength = encodeLevel({ ...l, transfers: [], transfersRaw: [], proofs: [] }).length;
  const ownId = tokenIdOf(l.mint.salt, c.network);
  const amount = beInt(bstr(scanOne(l.mint.data!).kids[0].kids[1].kids[0].kids[1]));
  const mintEnd = pos += prefixLength;
  const mintOp = {
    code: level === 0 ? 1 : 2, end: mintEnd, levels: levels.length - level, transfers: l.proofs.length,
    split: false, owner: l.mint.recipient.params, state: resultState(l.mintProof.cd.sourceHash, ownId),
    id: ownId, amount, link: ZERO, manifest: ZERO,
    sid: stateId(l.mintProof.cd.source, l.mintProof.cd.sourceHash),
    claims: [...(level === 0 ? [claim(decodeReceiptBacking(l.mint.justification!).proof.uc, c.evmPartition)] : []),
      claim(l.mintProof.uc, c.aggregatorPartition)],
  };
  return [mintOp, ...l.proofs.map((p, i) => {
    const t = l.transfers[i], left = l.proofs.length - 1 - i;
    const ending = left === 0 && level + 1 < levels.length;
    const manifest = ending ? decodeSplitManifest(t.data!) : ZERO;
    const sid = stateId(p.cd.source, p.cd.sourceHash);
    pos += 4 + 1 + l.transfersRaw[i].length + encodeProof(p).length;
    return { code: 3, end: pos, levels: levels.length - level - Number(ending), transfers: left,
      split: ending, owner: ending ? new Uint8Array(33) : t.recipient.params,
      state: ending ? ZERO : resultState(p.cd.sourceHash, t.mask), id: ownId, amount,
      link: ending ? parentLink(d, ownId, sid, p.cd.txHash, manifest, amount) : ZERO,
      manifest, sid, claims: [claim(p.uc, c.aggregatorPartition)] };
  })];
});
assert.equal(pos, token.length);
const pages = Array.from({ length: Math.ceil(token.length / 4096) }, (_, i) => token.subarray(i * 4096, (i + 1) * 4096));
const pageLeaves = pages.map((data, i) => h('PAGE', u64(token.length), u64(i), u16(data.length), data));
while ((pageLeaves.length & (pageLeaves.length - 1)) !== 0) pageLeaves.push(h('PAD'));
const pageTree = [pageLeaves];
while (pageTree.at(-1)!.length > 1) {
  const xs = pageTree.at(-1)!;
  pageTree.push(xs.filter((_, i) => i % 2 === 0).map((node, i) => h('PAGE_NODE', node, xs[2 * i + 1])));
}
const pageHeader = concat(u16(0x0101), u64(token.length), pageTree.at(-1)![0]);
const session = h('SESSION', u16(0x0101), h('GEN', salt, d), d, c.vault, bytes(recovery),
  codehash(recovery), pins, pageHeader.subarray(2));

async function replay(mode: string, cuts: number[]) {
  const sidTree = new Sparse('SID_NODE'), claimTree = new Sparse('CLAIM_NODE');
  const seen = new Map<string, Uint8Array>();
  let start = 0, seq = 0, index = 0, predecessor: Uint8Array | undefined, alternate: Uint8Array | undefined;
  let state: Uint8Array, complete: Uint8Array | undefined;
  for (const count of cuts) {
    const pack = ops.slice(index, index + count);
    const local = new Set<string>();
    const last = pack.at(-1)!;
    const packetPages = [];
    for (let i = Math.floor(start / 4096); i <= Math.floor((last.end - 1) / 4096); ++i) {
      packetPages.push(concat(u64(i), pages[i], ...pageTree.slice(0, -1).map((xs, height) => xs[(i >> height) ^ 1])));
    }
    const entries = pack.map((op) => {
      const sidPath = sidTree.path(op.sid);
      sidTree.insert(op.sid, h('SID', op.sid));
      return concat(be(op.code, 1), sidPath, ...op.claims.map(({ key, value }) => {
        const id = hex(key), previous = seen.get(id);
        if (local.has(id)) return be(1, 1);
        local.add(id);
        const opening = claimTree.path(key);
        if (previous) assert.equal(hex(previous), hex(value));
        else { claimTree.insert(key, h('CLAIM', key, value)); seen.set(id, value); }
        return concat(be(0, 1), be(Number(!!previous), 1), previous ?? new Uint8Array(0), opening);
      }));
    });
    const input = (prior?: Uint8Array) => hex(encodeCall('run(bytes)', concat(pageHeader,
      prior ? concat(be(1, 1), state, layout(prior)) : be(0, 1),
      be(packetPages.length, 1), ...packetPages, be(pack.length, 1), ...entries)));
    index += count;
    ++seq;
    const name = `${mode}-${seq}`;
    const earlier = [alternate, predecessor].flatMap((proof) => proof ? [decodeDepositProof(proof).uc] : []);
    if (earlier.length !== 0) await awaitOrigin(earlier);
    const data = input(alternate ?? predecessor);
    if (alternate) command('cast', ['call', '--rpc-url', rpc, recovery, '--data', input(predecessor)]);
    const tx = send(name, recovery, '--data', data);
    assert.equal(tx.logs.length, 1);
    assert.equal(tx.logs[0].topics[1], hex(session));
    if (index === ops.length) {
      assert.equal(tx.logs[0].topics[0], hex(HE(ascii('NB2Complete11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256)'))));
      assert.equal(tx.logs[0].data, hex(concat(u256(seq), expected)));
      complete = receipt(name, tx, recovery);
      continue;
    }
    assert.equal(tx.logs[0].topics[0], hex(HE(ascii('NB2Progress11(bytes32,uint64,bytes32)'))));
    state = concat(be(last.split ? 2 : 3, 1), u64(seq), u64(last.end), u64(last.levels), u64(last.transfers),
      sidTree.root(), claimTree.root(), last.owner, last.state, last.id, u256(last.amount), last.link, last.manifest);
    assert.equal(state.length, 290);
    assert.equal(tx.logs[0].data, hex(concat(u256(seq), h('STATE', session, state))));
    predecessor = receipt(name, tx, recovery);
    alternate = undefined;
    if (mode === 'packed' && seq === 1) {
      const copy = send('equivalent-progress', recovery, '--data', data);
      assert.deepEqual(copy.logs.map(({ topics, data }) => ({ topics, data })), tx.logs.map(({ topics, data }) => ({ topics, data })));
      alternate = receipt('equivalent-progress', copy, recovery);
      assert.notEqual(hex(alternate), hex(predecessor));
    }
    start = last.end;
  }
  assert(complete);
  return { complete, seq };
}

assert.equal(ops.length, 5);
const { complete, seq } = await replay('packed', [2, 2, 1]);
await replay('one-source', [1, 1, 1, 1, 1]);

// Advance accepts a proof-created archive prefix. A vault's eventual settlement
// compares the head to its actual archive. This lane deploys a deposit emitter.
const eta = expected.subarray(32, 64);
const tree = GapTree.build(Array.from({ length: 64 }, (_, i) => u256(i + 1)))!;
const gap = tree.prove(eta);
assert(gap);
const startHead = genesisHead(d, 64n);
await awaitOrigin([decodeDepositProof(complete).uc]);
const gapTx = send('advance', recovery, '--data', hex(encodeCall('advanceGaps(bytes)',
  concat(pageHeader, be(1, 1), layout(complete), u16(1), startHead, gap))));
assert.equal(gapTx.logs.length, 1);
assert.deepEqual(gapTx.logs[0].topics, [
  hex(HE(ascii('NB2Gap11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256,uint64,bytes32)'))),
  hex(session),
]);
assert.equal(gapTx.logs[0].data, hex(concat(u256(seq + 1), expected, u256(1), nextHead(d, 0n, startHead, tree.root))));
receipt('advance', gapTx, recovery);
