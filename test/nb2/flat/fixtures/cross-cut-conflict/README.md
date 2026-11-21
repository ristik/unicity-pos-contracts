# T1 cross-cut claim-map inputs

The three claim and calldata files are byte-for-byte copies of
[bft-core's cross-cut conflict fixture](https://github.com/ristik/bft-core/tree/0f075c2bb/testvectors/nb2-continuation-v1.1-supplement/cross-cut-conflict).
`retry-state.bin` is the outgoing state (third field) of the second frame of that fixture's
`trace.bin.gz`. Decompress the trace and read the six length-prefixed fields per frame as
described in the corpus README. The shortened retry executes the first transfer of the
failed call, so its outgoing claim root is the root immediately before the conflicting
transfer. The production replay authenticates this state through the retry's Progress event.

The Solidity regression extracts the conflicting transfer's first-use-present opening
from the original failed calldata. It shares that opening and the retry's claim root
between the committed mint claim and the conflicting candidate.
