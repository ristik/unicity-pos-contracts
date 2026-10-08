# root-records-vectors.json
Produced by bft-core `rootrecords` (branch p85/pr1c-import, commit 83f7cfb53799d6e9eb2751f1b2d709af40995038, `ROOTRECORDS_UPDATE=1 go test ./rootrecords`).
Do not edit by hand; regenerate and copy. Replayed by `AuthenticatedRecords.t.sol`: every record verbatim except the digest words of Closure and
Retirement, which the projection holds as opaque labels and the test replaces with custody-derived words (re-linking the chain) until the digest
formulas are shared.

UC time: the times in these vectors are quorum-approved wall-clock times of the root seal, bounded by root consensus (monotonic against the
parent, 30 s voter clock skew: ristik/bft-core#445, merged in ristik/bft-core#447) and imported monotonically on one lineage (bft-core `rootrecords.Clock`).

# root-records-import-vectors.json
Produced by bft-core `rootrecords` (branch p85/pr1c-import, commit c63e6fd122b9e05ff644a9bf1dab209bca68795c; `ROOTRECORDS_UPDATE=1 go test ./rootrecords`).
The registry import calls the projection owes, block by block, with each block's canonical companion and `rootRecordsHash`.
Replayed by `test/RootRecordsImport.t.sol`.
