// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import { Script } from "forge-std/Script.sol";
import { JWKSRegistry } from "../src/JWKSRegistry.sol";

/// @notice Sends a signed JWKS snapshot from the TEE updater to the registry.
/// @dev Put the registry address in `REGISTRY` and the JSON output of `tee-updater sign` (or of the
/// enclave `sign` request) in `SNAPSHOT`. The snapshot is not trusted data: the registry examines
/// its signature, so the script takes only the keys, the time, and the signature from it. Anyone
/// can send a snapshot:
///
/// REGISTRY=0x... SNAPSHOT="$(cat snapshot.json)" forge script script/UpdateKeys.s.sol \
///     --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
contract UpdateKeys is Script {
    function run() external {
        JWKSRegistry registry = JWKSRegistry(vm.envAddress("REGISTRY"));
        string memory snapshot = vm.envString("SNAPSHOT");
        JWKSRegistry.Key[] memory keys = abi.decode(
            vm.parseJsonTypeArray(snapshot, ".keys", "Key(string kid,bytes modulus)"),
            (JWKSRegistry.Key[])
        );
        uint64 fetchedAt = uint64(vm.parseJsonUint(snapshot, ".fetchedAt"));

        vm.broadcast();
        registry.updateKeys(keys, fetchedAt, vm.parseJsonBytes(snapshot, ".signature"));
    }
}
