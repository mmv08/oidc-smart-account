// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import { Test } from "forge-std/Test.sol";
import { JWKSRegistry } from "../../src/JWKSRegistry.sol";
import { JWTVerifier } from "../../src/JWTVerifier.sol";
import { MockIssuer } from "./MockIssuer.sol";

/// @notice Deploys the registry and the verifier, and publishes the mock issuer key.
abstract contract TestBase is Test {
    string internal constant JWKS_URI = "https://issuer.example/jwks.json";
    uint256 internal constant ATTESTOR_KEY = 0xA77E57;

    JWKSRegistry internal registry;
    JWTVerifier internal verifier;

    function setUp() public virtual {
        vm.warp(1_700_000_000);
        registry = new JWKSRegistry(address(this), JWKS_URI);
        registry.setAttestor(vm.addr(ATTESTOR_KEY));
        publish(MockIssuer.keys(), uint64(block.timestamp));
        verifier = new JWTVerifier(registry, MockIssuer.ISSUER, MockIssuer.AUDIENCE);
    }

    /// @dev Sends a key set that the attestor signed, as the TEE updater does.
    function publish(JWKSRegistry.Key[] memory keys, uint64 fetchedAt) internal {
        registry.updateKeys(keys, fetchedAt, signKeySet(ATTESTOR_KEY, keys, fetchedAt));
    }

    function signKeySet(uint256 privateKey, JWKSRegistry.Key[] memory keys, uint64 fetchedAt)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, registry.hashKeySet(keys, fetchedAt));
        return abi.encodePacked(r, s, v);
    }
}
