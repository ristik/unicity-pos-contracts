#!/usr/bin/env python3
"""Generates the PoS-capable VR build (VT-04, astra's ruling on option 1): VR's core, its three facets and VRShared copied with the
callback caps CAP_ELECT 7,000,000, CAP_OUTPUT 1,500,000 and CAP_RECORD 2,500,000 (compile-time constants) into src/vr/pos/build/, the
contracts renamed with the suffix Pos, and (#1286) the PoS adapter's output rule in ValidatorRegistry (POS_RULE). The PoA build (src/vr/*.sol, its pins and code hashes) is untouched. CI runs this and fails if the
committed files differ. Usage (repository root): python3 script/gen-vr-pos-build.py [--check]"""
import pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC, OUT = ROOT / "src/vr", ROOT / "src/vr/pos/build"
COPIED = ["VRShared", "ValidatorRegistry", "VRGovernanceFacet", "VRRepairFacet", "VRRecordsFacet"]
CAPS = {"CAP_ELECT": "7_000_000", "CAP_OUTPUT": "1_500_000", "CAP_RECORD": "2_500_000"}
# #1286 (astra): in the PoS build an output of the P85 adapter carries custody's bond-cycle generation. VR's binding words must be its
# exact current or nonzero staged ref, and the member generation must equal the generation custody (holder 0 of the active adapter,
# at its pinned code hash) holds for that identity, which is the generation frozen for the result (a referenced lot cannot be released,
# so custody's generation cannot move while the result is open); monotonicity against VR's installed generation is the secondary check.
# Every other module keeps the PoA rule (current at g, staged at g + 1) exactly. The PoA source and build are unchanged.
POS_RULE = [
    ("""    /// @dev VR's validation of an output's member set (design sections 3.1 and 3.5.4): known identities whose words are exactly their
    /// current binding (generation g) or their staged binding (generation g + 1); positive raw weights quantized by the shared rule; and,
    /// for module outputs, the committee limits (in range or strictly toward it) and the O -> S continuity budget.
""", """    /// @dev VR's validation of an output's member set (design sections 3.1 and 3.5.4): known identities whose words are exactly their
    /// current binding (generation g) or their staged binding (generation g + 1); positive raw weights quantized by the shared rule; and,
    /// for module outputs, the committee limits (in range or strictly toward it) and the O -> S continuity budget. PoS build (#1286): an
    /// output of the P85 adapter names VR's exact current or nonzero staged binding at the custody generation (`_posCustody`).
"""),
    ("""        uint256[] memory raw = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            Member memory m = ms[i];
            if (i > 0 && ms[i - 1].id >= m.id) return false;
""", """        uint256[] memory raw = new uint256[](n);
        address custody = _posCustody();
        for (uint256 i = 0; i < n; ++i) {
            Member memory m = ms[i];
            if (i > 0 && ms[i - 1].id >= m.id) return false;
"""),
    ("""            bool current = m.generation == idn.generation && ref == idn.currentRef;
            bool staged =
                idn.stagedRef != 0 && m.generation == idn.generation + 1 && ref == idn.stagedRef;
            if (!current && !staged) return false;
""", """            bool current;
            bool staged;
            if (custody == address(0)) {
                current = m.generation == idn.generation && ref == idn.currentRef;
                staged = idn.stagedRef != 0 && m.generation == idn.generation + 1
                    && ref == idn.stagedRef;
            } else {
                current = ref == idn.currentRef;
                staged = idn.stagedRef != 0 && ref == idn.stagedRef;
                if (
                    m.generation < idn.generation
                        || m.generation != _custodyGeneration(custody, m.id)
                ) return false;
            }
            if (!current && !staged) return false;
"""),
    ("""    function _limitDistance(uint256 n) private view returns (uint256) {
""", """    /// @dev The PoS adapter's moduleTag and custody's `positions(uint64)` (its fifth word is the bond-cycle generation).
    bytes32 private constant POS_MODULE_TAG = keccak256("unicity.vr.pos-p85.v1");
    bytes4 private constant POSITIONS = bytes4(keccak256("positions(uint64)"));

    /// @dev PoS build (#1286): custody, when the active module is the P85 adapter and holder 0 is its liability holder; zero otherwise
    /// (the PoA rule applies).
    function _posCustody() private view returns (address) {
        VRLayout.VRStorage storage $ = VRLayout.load();
        if ($.module.moduleTag != POS_MODULE_TAG || $.status.holderCount == 0) return address(0);
        VRLayout.Holder storage h = $.holders[0];
        if (h.module != $.activeModule) return address(0);
        return h.holder;
    }

    /// @dev Custody's generation of `id` (zero, so no member matches, when custody's code is not the pinned holder code or the read fails).
    function _custodyGeneration(address custody, uint64 id) private view returns (uint256 g) {
        if (custody.codehash != VRLayout.load().holders[0].holderCodeHash) return 0;
        (bool ok, bytes memory r) = custody.staticcall(abi.encodeWithSelector(POSITIONS, id));
        if (!ok || r.length != 288) return 0;
        assembly ("memory-safe") {
            g := mload(add(r, 160))
        }
    }

    function _limitDistance(uint256 n) private view returns (uint256) {
"""),
]
HEADER = ("// GENERATED by script/gen-vr-pos-build.py from src/vr/{name}.sol: the PoS-capable VR build (callback caps CAP_ELECT 7,000,000,\n"
          "// CAP_OUTPUT 1,500,000, CAP_RECORD 2,500,000). Do not edit; change the source and regenerate.\n")


def gen(name):
    s = (SRC / f"{name}.sol").read_text()
    for n in COPIED:
        s = re.sub(rf"\b{n}\b", n + "Pos", s)
    # imports of files that are not copied move up two directories; the copied ones keep their (renamed) sibling files
    def imp(m):
        path = m.group(1)
        base = pathlib.PurePosixPath(path).name.removesuffix(".sol")
        if path.startswith("./") and base.removesuffix("Pos") in COPIED:
            return f'"./{base}.sol"'
        if path.startswith("./"):
            return f'"../../{base}.sol"'
        if path.startswith("../"):
            return '"../../' + path + '"'
        return m.group(0)
    s = re.sub(r'"(\.{1,2}/[^"]+\.sol)"', imp, s)
    if name == "ValidatorRegistry":
        for a, b in POS_RULE:
            assert s.count(a) == 1, a[:80]
            s = s.replace(a, b)
    for k, v in CAPS.items():
        s, n = re.subn(rf"(uint64 internal constant {k} = )[0-9_]+;", rf"\g<1>{v};", s)
        assert name != "VRShared" or n == 1, k
    lines = s.split("\n")
    # keep the SPDX line and pragma first
    i = next(i for i, l in enumerate(lines) if l.startswith("pragma"))
    lines.insert(i + 1, "\n" + HEADER.format(name=name).rstrip("\n"))
    return "\n".join(lines)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    stale = []
    for n in COPIED:
        text, path = gen(n), OUT / f"{n}Pos.sol"
        if "--check" in sys.argv:
            if not path.exists() or path.read_text() != text:
                stale.append(path.name)
        else:
            path.write_text(text)
    if stale:
        sys.exit("stale generated files: " + ", ".join(stale))


main()
