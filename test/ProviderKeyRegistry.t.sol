// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { ProviderKeyRegistry } from "../src/ProviderKeyRegistry.sol";

contract ProviderKeyRegistryTest is Test {
    ProviderKeyRegistry internal registry;
    bytes32 internal constant PROVIDER = keccak256("google-client-policy-v1");
    bytes32 internal constant KID = keccak256("kid-2026-01");
    bytes internal constant JWK = bytes('{"e":"AQAB","kty":"RSA","n":"canonical"}');

    function setUp() public {
        registry = new ProviderKeyRegistry(address(this));
        registry.registerProvider(PROVIDER);
    }

    function test_keyValidityUsesIssuanceTimeButEmergencyRevocationAlwaysWins() public {
        bytes32 keyHash = registry.publishKey(PROVIDER, KID, JWK, 100, 200);
        assertEq(keyHash, sha256(JWK));
        assertTrue(registry.isKeyValid(PROVIDER, keyHash, 100));
        assertTrue(registry.isKeyValid(PROVIDER, keyHash, 199));
        assertFalse(registry.isKeyValid(PROVIDER, keyHash, 99));
        assertFalse(registry.isKeyValid(PROVIDER, keyHash, 200));

        registry.revokeKey(PROVIDER, keyHash);
        assertFalse(registry.isKeyValid(PROVIDER, keyHash, 150));
    }

    function test_rotationOverlapAcceptsBothCanonicalKeysAtIssuanceTime() public {
        bytes32 oldKey = registry.publishKey(PROVIDER, KID, JWK, 100, 200);
        bytes memory nextJwk = bytes('{"e":"AQAB","kty":"RSA","n":"next"}');
        bytes32 nextKey = registry.publishKey(PROVIDER, keccak256("next-kid"), nextJwk, 150, 300);
        assertTrue(registry.isKeyValid(PROVIDER, oldKey, 175));
        assertTrue(registry.isKeyValid(PROVIDER, nextKey, 175));
        assertEq(registry.getKey(PROVIDER, nextKey).canonicalJwk, nextJwk);
    }

    function test_rejectsUnknownProviderDuplicateCanonicalKeyAndBadWindow() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ProviderKeyRegistry.ProviderNotRegistered.selector, bytes32(uint256(1))
            )
        );
        registry.publishKey(bytes32(uint256(1)), KID, JWK, 100, 200);
        registry.publishKey(PROVIDER, KID, JWK, 100, 200);
        vm.expectRevert();
        registry.publishKey(PROVIDER, keccak256("different-kid"), JWK, 100, 200);
        vm.expectRevert(ProviderKeyRegistry.InvalidValidityWindow.selector);
        registry.publishKey(PROVIDER, keccak256("bad"), bytes("other"), 200, 200);
    }

    function test_sameProviderJwkCanServeIndependentAudiencePolicies() public {
        bytes32 secondPolicy = keccak256("google-second-client-policy");
        registry.registerProvider(secondPolicy);
        bytes32 firstHash = registry.publishKey(PROVIDER, KID, JWK, 100, 200);
        bytes32 secondHash = registry.publishKey(secondPolicy, KID, JWK, 100, 200);
        assertEq(firstHash, secondHash);
        assertTrue(registry.isKeyValid(PROVIDER, firstHash, 150));
        assertTrue(registry.isKeyValid(secondPolicy, secondHash, 150));
    }
}

