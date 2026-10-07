# root-records-vectors.json
Produced by bft-core `rootrecords` (branch p85/pr1b, commit bf5cc4ff4967a1813c821c7b7024c9cb967b6a92, `ROOTRECORDS_UPDATE=1 go test ./rootrecords`).
Do not edit by hand; regenerate and copy. Replayed verbatim by `AuthenticatedRecords.t.sol`.

Limitation: the UC times in these vectors are imported on one lineage and never decrease (bft-core `rootrecords.Clock`), but the
root's own proposal timestamp is not yet bounded against its parent or a voter's clock; that is a root consensus rule tracked as
ristik/bft-core#445. Until it lands, custody's time gate trusts the importer-side monotonicity check only.
