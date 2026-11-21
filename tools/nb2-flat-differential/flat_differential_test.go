package nb2ref

// Differential corpus for the Solidity verifiers. Copy this file into nb2ref at the pinned
// bft-core commit (see run.sh), then run it (NB2_DIFF_OUT, default /tmp/nb2-diff-out). It mutates the published
// evidence and packets deterministically and records the oracle's verdict or refusal stage for
// every mutation. The Foundry suite applies the same mutations and must agree exactly.
//
// Line formats (fields are space separated, hex has no prefix):
//   O <scenario> <op> <pos> <val> <result>             ordinary evidence mutation
//   R <scenario> <record> <op> <pos> <val> <result>    run(bytes) packet mutation
//   A <case> <op> <pos> <val> <result>                 advanceGaps(bytes) packet mutation
//   M <scenario> <pages> <operation count> <operations hex> <op> <pos> <val> <result>
//                                                      like S for every operation of the first Start packet
//   S <scenario> <first operation hex> <op> <pos> <val> <result>
//                                                      Start packet over mutated evidence with a freshly
//                                                      built page tree, so the step logic is reached
// op: x xor byte at pos with val, t truncate to length pos, a append byte val.
// result: ok:<hex> (ABI verdict, or event topics||data), or the stage name.

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1ref"
)

type diffRng uint64

func (s *diffRng) next() uint64 {
	*s += 0x9e3779b97f4a7c15
	z := uint64(*s)
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

type diffMutation struct {
	op  byte
	pos int
	val byte
}

func diffMutations(name string, size, count int) []diffMutation {
	digest := HU([]byte(name))
	seed := diffRng(binary.BigEndian.Uint64(digest[:8]))
	out := []diffMutation{{'t', size - 1, 0}, {'a', 0, 0}, {'t', size / 2, 0}, {'t', 0, 0}}
	vals := []byte{0x01, 0x80, 0xff}
	for len(out) < count {
		r := seed.next()
		limit := size
		if r&1 == 0 && size > 700 {
			limit = 700
		}
		pos := int(seed.next() % uint64(limit))
		val := vals[seed.next()%3]
		out = append(out, diffMutation{'x', pos, val})
	}
	return out
}

// diffMutationsIn flips bytes only inside [lo, hi): the framed operations or the gap proofs.
func diffMutationsIn(name string, lo, hi, count int) []diffMutation {
	digest := HU([]byte(name))
	seed := diffRng(binary.BigEndian.Uint64(digest[:8]))
	vals := []byte{0x01, 0x80, 0xff}
	var out []diffMutation
	for len(out) < count {
		out = append(out, diffMutation{'x', lo + int(seed.next()%uint64(hi-lo)), vals[seed.next()%3]})
	}
	return out
}

func (m diffMutation) apply(b []byte) []byte {
	switch m.op {
	case 't':
		return bytes.Clone(b[:m.pos])
	case 'a':
		return append(bytes.Clone(b), m.val)
	}
	c := bytes.Clone(b)
	c[m.pos] ^= m.val
	return c
}

func diffStage(t *testing.T, err error) string {
	t.Helper()
	var pos *PositionError
	if errors.As(err, &pos) && pos.Rule == ErrBadGapProof {
		return fmt.Sprintf("BadGapProof:%d", pos.Position)
	}
	for _, s := range []struct {
		e error
		n string
	}{{ErrFlatPacket, "BadPacket"}, {ErrFlatPredecessor, "BadPredecessor"}, {ErrFlatPage, "BadPage"}, {ErrFlatStep, "BadStep"}} {
		if errors.Is(err, s.e) {
			return s.n
		}
	}
	t.Fatalf("unmapped oracle error: %v", err)
	return ""
}

func diffOperation(t *testing.T, op FlatOperation) []byte {
	t.Helper()
	out := op.SID.appendTo([]byte{byte(op.Code)})
	for _, c := range op.Claims {
		var err error
		out, err = c.appendTo(out)
		require.NoError(t, err)
	}
	return out
}

func diffRead(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	require.NoError(t, err)
	return b
}

func diffScenarioVerifier(t *testing.T, dir string) *FlatVerifier {
	t.Helper()
	var ctx struct {
		GenesisCommitment, RegistryProfile, RecoveryAddress, RecoveryRuntimeHash string
		Registry                                                                  map[string]string
	}
	require.NoError(t, json.Unmarshal(diffRead(t, dir, "context.json"), &ctx))
	registry := make(b1ref.Words, len(ctx.Registry))
	for k, val := range ctx.Registry {
		registry[[32]byte(mustHex(k))] = [32]byte(mustHex(val))
	}
	gamma := flatGolden(t, "gamma")
	deploy := FlatDeployment{Salt: [32]byte(flatGolden(t, "generation-salt")), Pins: [32]byte(flatGolden(t, "pins")),
		Runtime: [32]byte(mustHex(ctx.RecoveryRuntimeHash)), Recovery: [20]byte(mustHex(ctx.RecoveryAddress))}
	v, err := NewFlatVerifier(gamma, deploy, FlatAuthority{Registry: registry,
		Pins: b1ref.Pins{GenesisCommitment: [32]byte(mustHex(ctx.GenesisCommitment)), ProfileHash: [32]byte(mustHex(ctx.RegistryProfile))}})
	require.NoError(t, err)
	return v
}

func TestFlatDifferentialCorpus(t *testing.T) {
	outDir := os.Getenv("NB2_DIFF_OUT")
	if outDir == "" {
		outDir = "/tmp/nb2-diff-out"
	}
	root := filepath.Join(flatVectorDir, "transcripts")
	ordinary := []string{"root", "transfers", "one-split", "shared-claim", "alternate-certificate", "capped-root",
		"combined-large-receipt-and-paths", "depth-20", "held-sibling-0"}
	runs := []string{"root", "transfers", "one-split", "shared-claim", "alternate-certificate", "capped-root",
		"combined-large-receipt-and-paths"}
	var o, r, a, st strings.Builder
	for _, name := range ordinary {
		dir := filepath.Join(root, name)
		v := diffScenarioVerifier(t, dir)
		evidence := diffRead(t, dir, "evidence.bin")
		for _, m := range diffMutations("O/"+name, len(evidence), 160) {
			got := "BadStep"
			verdict, err := v.VerifyFlatReturn(m.apply(evidence))
			if err == nil {
				got = "ok:" + hex.EncodeToString(verdict.ABI())
			}
			fmt.Fprintf(&o, "O %s %c %d %x %s\n", name, m.op, m.pos, m.val, got)
		}
	}
	for _, name := range runs {
		dir := filepath.Join(root, name)
		v := diffScenarioVerifier(t, dir)
		gz, err := gzip.NewReader(bytes.NewReader(diffRead(t, dir, "trace.bin.gz")))
		require.NoError(t, err)
		trace, err := io.ReadAll(gz)
		require.NoError(t, err)
		rd := flatReader{raw: trace}
		for rec := 0; len(rd.raw) > 0; rec++ {
			calldata := rd.blob(FlatMaxCalldata)
			rd.blob(FlatStateBytes)
			rd.blob(FlatStateBytes)
			rd.blob(64)
			rd.blob(288)
			rd.blob(FlatMaxReceipt)
			require.NoError(t, rd.err)
			for _, m := range diffMutations(fmt.Sprintf("R/%s/%d", name, rec), len(calldata), 48) {
				got := ""
				res, err := v.RunFlat(m.apply(calldata))
				if err != nil {
					got = diffStage(t, err)
				} else {
					log := res.Event.Log(v.deployment.Recovery)
					got = "ok:" + hex.EncodeToString(bytes.Join([][]byte{log.Topics[0][:], log.Topics[1][:], log.Data}, nil))
				}
				fmt.Fprintf(&r, "R %s %d %c %d %x %s\n", name, rec, m.op, m.pos, m.val, got)
			}
			// Targeted: only the framed operations (sparse openings and opcodes), so the step
			// logic of later records is reached instead of page authentication.
			pk, err := DecodeFlatRun(calldata)
			require.NoError(t, err)
			opsLen := 1
			for _, op := range pk.Operations {
				opsLen += len(diffOperation(t, op))
			}
			end := 68 + int(binary.BigEndian.Uint64(calldata[60:68]))
			for _, m := range diffMutationsIn(fmt.Sprintf("RO/%s/%d", name, rec), end-opsLen, end, 40) {
				got := ""
				res, err := v.RunFlat(m.apply(calldata))
				if err != nil {
					got = diffStage(t, err)
				} else {
					log := res.Event.Log(v.deployment.Recovery)
					got = "ok:" + hex.EncodeToString(bytes.Join([][]byte{log.Topics[0][:], log.Topics[1][:], log.Data}, nil))
				}
				fmt.Fprintf(&r, "R %s %d %c %d %x %s\n", name, rec, m.op, m.pos, m.val, got)
			}
		}
	}
	for _, name := range runs {
		dir := filepath.Join(root, name)
		v := diffScenarioVerifier(t, dir)
		gz, err := gzip.NewReader(bytes.NewReader(diffRead(t, dir, "trace.bin.gz")))
		require.NoError(t, err)
		trace, err := io.ReadAll(gz)
		require.NoError(t, err)
		rd := flatReader{raw: trace}
		first := rd.blob(FlatMaxCalldata)
		require.NoError(t, rd.err)
		packet, err := DecodeFlatRun(first)
		require.NoError(t, err)
		op := packet.Operations[0]
		opBytes := op.SID.appendTo([]byte{byte(op.Code)})
		for _, c := range op.Claims {
			opBytes, err = c.appendTo(opBytes)
			require.NoError(t, err)
		}
		evidence := diffRead(t, dir, "evidence.bin")
		end := 14
		for i := 0; i < 3; i++ {
			end += 4 + int(binary.BigEndian.Uint32(evidence[end:]))
		}
		end += 8
		pages := (end-1)/FlatPageBytes + 1
		for _, m := range diffMutations("S/"+name, end, 300) {
			mutated := m.apply(evidence)
			e, err := NewFlatEvidence(mutated)
			if err != nil {
				continue
			}
			p := FlatRunPacket{Header: e.Header(), Operations: []FlatOperation{op}}
			for i := uint64(0); i < uint64(pages) && i < flatPageCount(uint64(len(mutated))); i++ {
				page, err := e.Page(i)
				require.NoError(t, err)
				p.Pages = append(p.Pages, page)
			}
			data, err := p.Calldata()
			if err != nil {
				continue
			}
			got := ""
			res, err := v.RunFlat(data)
			if err != nil {
				got = diffStage(t, err)
			} else {
				log := res.Event.Log(v.deployment.Recovery)
				got = "ok:" + hex.EncodeToString(bytes.Join([][]byte{log.Topics[0][:], log.Topics[1][:], log.Data}, nil))
			}
			fmt.Fprintf(&st, "S %s %x %c %d %x %s\n", name, opBytes, m.op, m.pos, m.val, got)
		}
		// Every operation of the first Start packet over mutated evidence.
		var all []byte
		for _, o := range packet.Operations {
			all = append(all, diffOperation(t, o)...)
		}
		span := min(len(packet.Pages)*FlatPageBytes, len(evidence))
		for _, m := range diffMutationsIn("M/"+name, 0, span, 120) {
			mutated := m.apply(evidence)
			e, err := NewFlatEvidence(mutated)
			if err != nil {
				continue
			}
			p := FlatRunPacket{Header: e.Header(), Operations: packet.Operations}
			for i := uint64(0); i < uint64(len(packet.Pages)) && i < flatPageCount(uint64(len(mutated))); i++ {
				page, err := e.Page(i)
				require.NoError(t, err)
				p.Pages = append(p.Pages, page)
			}
			data, err := p.Calldata()
			if err != nil {
				continue
			}
			got := ""
			res, err := v.RunFlat(data)
			if err != nil {
				got = diffStage(t, err)
			} else {
				log := res.Event.Log(v.deployment.Recovery)
				got = "ok:" + hex.EncodeToString(bytes.Join([][]byte{log.Topics[0][:], log.Topics[1][:], log.Data}, nil))
			}
			fmt.Fprintf(&st, "M %s %d %d %x %c %d %x %s\n", name, len(packet.Pages), len(packet.Operations), all, m.op, m.pos, m.val, got)
		}
	}
	_, v, _ := flatFixtureVerifier(t)
	for _, name := range []string{"advance-kind1-count1", "advance-kind2-count1"} {
		wire := diffRead(t, filepath.Join(root, "cold", name), "calldata.bin")
		for _, m := range diffMutations("A/"+name, len(wire), 160) {
			got := ""
			ev, err := v.AdvanceFlatGaps(m.apply(wire))
			if err != nil {
				got = diffStage(t, err)
			} else {
				log := ev.Log(v.deployment.Recovery)
				got = "ok:" + hex.EncodeToString(bytes.Join([][]byte{log.Topics[0][:], log.Topics[1][:], log.Data}, nil))
			}
			fmt.Fprintf(&a, "A %s %c %d %x %s\n", name, m.op, m.pos, m.val, got)
		}
		gapEnd := 68 + int(binary.BigEndian.Uint64(wire[60:68]))
		for _, m := range diffMutationsIn("AG/"+name, gapEnd-257, gapEnd, 60) {
			got := ""
			ev, err := v.AdvanceFlatGaps(m.apply(wire))
			if err != nil {
				got = diffStage(t, err)
			} else {
				log := ev.Log(v.deployment.Recovery)
				got = "ok:" + hex.EncodeToString(bytes.Join([][]byte{log.Topics[0][:], log.Topics[1][:], log.Data}, nil))
			}
			fmt.Fprintf(&a, "A %s %c %d %x %s\n", name, m.op, m.pos, m.val, got)
		}
	}
	// A refusal at a nonzero position: a valid earlier gap, then one whose index byte is >= K.
	for _, name := range []string{"advance-kind1-count1024", "advance-kind2-count1024"} {
		wire := diffRead(t, filepath.Join(root, "cold", name), "calldata.bin")
		gapEnd := 68 + int(binary.BigEndian.Uint64(wire[60:68]))
		for _, k := range []int{1, 17, 512, 1023} {
			m := diffMutation{'x', gapEnd - 1024*257 + 257*k, 0xff}
			_, err := v.AdvanceFlatGaps(m.apply(wire))
			require.Error(t, err)
			fmt.Fprintf(&a, "A %s %c %d %x %s\n", name, m.op, m.pos, m.val, diffStage(t, err))
		}
	}
	require.NoError(t, os.MkdirAll(outDir, 0o755))
	for name, b := range map[string]*strings.Builder{"ordinary.txt": &o, "run.txt": &r, "advance.txt": &a, "start.txt": &st} {
		require.NoError(t, os.WriteFile(filepath.Join(outDir, name), []byte(b.String()), 0o644))
	}
}
