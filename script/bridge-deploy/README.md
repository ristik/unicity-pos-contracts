# Bridge deployment inputs

`script/BridgeDeploy.s.sol` reads `BRIDGE_GENESIS` and `BRIDGE_DEPLOYMENT` from this directory (the only
one the script may read). Both are 0x-prefixed JSON. `BRIDGE_GENESIS` is the genesis tool's identity
document (`rootGenesisId`, `evmGenesisHash`, `profileHash`, `executionChainId`, `registryWords`);
`BRIDGE_DEPLOYMENT` carries the vault's inputs. The script refuses to broadcast unless the vault's
`rootGenesis`, `executionGenesis` and `b1ProfileHash` equal the genesis' own, the target chain is the
genesis' execution chain, and the registry on the target chain holds the genesis' `b1.profileHash`.
Example: `BRIDGE_GENESIS=script/bridge-deploy/genesis.json BRIDGE_DEPLOYMENT=... forge script script/BridgeDeploy.s.sol --rpc-url ... --broadcast`.
Test fixtures: `test/bridge/deploy/`.
