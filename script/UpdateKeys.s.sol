// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import { Script } from "forge-std/Script.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { JWKSRegistry } from "../src/JWKSRegistry.sol";

/// @notice Sends a signed JWKS snapshot from the TEE updater to the registry.
/// @dev Set `REGISTRY` to the registry address. Set `SNAPSHOT` to the JSON from the updater.
contract UpdateKeys is Script {
    function run() external {
        JWKSRegistry registry = JWKSRegistry(vm.envAddress("REGISTRY"));
        string memory snapshot = vm.envString("SNAPSHOT");
        JWKSRegistry.Key[] memory keys = abi.decode(
            vm.parseJsonTypeArray(snapshot, ".keys", "Key(string kid,bytes modulus)"),
            (JWKSRegistry.Key[])
        );
        uint64 fetchedAt = SafeCast.toUint64(vm.parseJsonUint(snapshot, ".fetchedAt"));

        vm.broadcast();
        registry.updateKeys(keys, fetchedAt, vm.parseJsonBytes(snapshot, ".signature"));
    }
}
