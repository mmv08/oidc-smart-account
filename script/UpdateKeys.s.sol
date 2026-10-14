// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import { Script } from "forge-std/Script.sol";
import { JWKSRegistry } from "../src/JWKSRegistry.sol";

/// @notice Sends a key set that the TEE updater signed to the registry. Anyone can send it.
/// @dev Put the registry address in `REGISTRY`. Put the JSON output of the TEE updater `sign`
/// command (or of the enclave `sign` request) in `KEY_SET`. The JSON is not trusted data, because
/// the host can change it. Thus the script takes only the keys, the time, and the signature from
/// it. The registry examines the signature of these values:
///
/// REGISTRY=0x... KEY_SET="$(cat key-set.json)" forge script script/UpdateKeys.s.sol \
///     --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
contract UpdateKeys is Script {
    function run() external {
        JWKSRegistry registry = JWKSRegistry(vm.envAddress("REGISTRY"));
        string memory keySet = vm.envString("KEY_SET");
        JWKSRegistry.Key[] memory keys = abi.decode(
            vm.parseJsonTypeArray(keySet, ".keys", "Key(string kid,bytes modulus)"),
            (JWKSRegistry.Key[])
        );
        uint64 fetchedAt = uint64(vm.parseJsonUint(keySet, ".fetchedAt"));

        vm.broadcast();
        registry.updateKeys(keys, fetchedAt, vm.parseJsonBytes(keySet, ".signature"));
    }
}
