# root-records-vectors.json
Produced by bft-core `rootrecords` (branch p85/pr1b, commit bf5cc4ff4967a1813c821c7b7024c9cb967b6a92, `ROOTRECORDS_UPDATE=1 go test ./rootrecords`).
Do not edit by hand; regenerate and copy. Replayed verbatim by `AuthenticatedRecords.t.sol`.

UC time: the times in these vectors are quorum-approved wall-clock times of the root seal, bounded by root consensus (monotonic against the
parent, 30 s voter clock skew: ristik/bft-core#445) and imported monotonically on one lineage (bft-core `rootrecords.Clock`).
