// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Script } from "forge-std/Script.sol";
import { JWKSRegistry } from "../src/JWKSRegistry.sol";

/// @notice Sends a signed JWKS snapshot from the TEE updater to the registry.
/// @dev Put the JSON output of `tee-updater sign` (or of the enclave `sign` request) in the
/// `SNAPSHOT` environment variable. Anyone can send a snapshot:
///
/// SNAPSHOT="$(cat snapshot.json)" forge script script/UpdateKeys.s.sol \
///     --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
contract UpdateKeys is Script {
    function run() external {
        string memory snapshot = vm.envString("SNAPSHOT");
        JWKSRegistry registry = JWKSRegistry(vm.parseJsonAddress(snapshot, ".registry"));
        JWKSRegistry.Key[] memory keys = abi.decode(
            vm.parseJsonTypeArray(snapshot, ".keys", "Key(string kid,bytes modulus)"),
            (JWKSRegistry.Key[])
        );
        uint64 fetchedAt = uint64(vm.parseJsonUint(snapshot, ".fetchedAt"));

        vm.broadcast();
        registry.updateKeys(keys, fetchedAt, vm.parseJsonBytes(snapshot, ".signature"));
    }
}
