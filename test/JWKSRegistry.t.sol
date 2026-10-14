// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { JWKSRegistry } from "../src/JWKSRegistry.sol";
import { MockIssuer } from "./helpers/MockIssuer.sol";
import { TestBase } from "./helpers/TestBase.sol";

contract JWKSRegistryTest is TestBase {
    bytes32 internal constant KID_HASH = keccak256(bytes(MockIssuer.KID));

    function test_signedKeySetIsPublished() public view {
        assertEq(registry.getKey(KID_HASH), MockIssuer.MODULUS);
        assertEq(registry.fetchedAt(), block.timestamp);
    }

    function test_anyoneCanRelayASignedKeySet() public {
        JWKSRegistry.Key[] memory keys = MockIssuer.keys();
        uint64 fetchedAt = uint64(block.timestamp + 1);
        bytes memory signature = signKeySet(ATTESTOR_KEY, keys, fetchedAt);

        vm.prank(makeAddr("relayer"));
        registry.updateKeys(keys, fetchedAt, signature);
        assertEq(registry.fetchedAt(), fetchedAt);
    }

    function test_rejectsKeySetNotSignedByAttestor() public {
        JWKSRegistry.Key[] memory keys = _key("attacker-key", hex"c1");
        uint64 fetchedAt = uint64(block.timestamp + 1);
        bytes memory signature = signKeySet(0xBAD, keys, fetchedAt);

        vm.expectRevert(JWKSRegistry.InvalidSignature.selector);
        registry.updateKeys(keys, fetchedAt, signature);
    }

    function test_rejectsReplayOfOldKeySet() public {
        JWKSRegistry.Key[] memory keys = MockIssuer.keys();
        uint64 fetchedAt = registry.fetchedAt();
        bytes memory signature = signKeySet(ATTESTOR_KEY, keys, fetchedAt);

        vm.expectRevert(JWKSRegistry.OldKeySet.selector);
        registry.updateKeys(keys, fetchedAt, signature);
    }

    function test_newKeySetReplacesAllKeys() public {
        JWKSRegistry.Key[] memory next = _key("test-key-2", hex"d3");
        publish(next, uint64(block.timestamp + 1));

        assertEq(registry.getKey(keccak256("test-key-2")), next[0].modulus);
        vm.expectRevert(JWKSRegistry.UnknownKey.selector);
        registry.getKey(KID_HASH);
    }

    function test_keySetBecomesStaleAfterMaxAge() public {
        uint256 lastFreshTime = registry.fetchedAt() + registry.MAX_KEY_SET_AGE();
        vm.warp(lastFreshTime);
        registry.getKey(KID_HASH);

        vm.warp(lastFreshTime + 1);
        vm.expectRevert(JWKSRegistry.StaleKeySet.selector);
        registry.getKey(KID_HASH);
    }

    function test_newAttestorRemovesKeysOfOldAttestor() public {
        uint256 newAttestorKey = 0xB0B;
        registry.setAttestor(vm.addr(newAttestorKey));

        vm.expectRevert(JWKSRegistry.StaleKeySet.selector);
        registry.getKey(KID_HASH);

        JWKSRegistry.Key[] memory keys = MockIssuer.keys();
        uint64 fetchedAt = uint64(block.timestamp + 1);
        bytes memory oldSignature = signKeySet(ATTESTOR_KEY, keys, fetchedAt);
        vm.expectRevert(JWKSRegistry.InvalidSignature.selector);
        registry.updateKeys(keys, fetchedAt, oldSignature);

        registry.updateKeys(keys, fetchedAt, signKeySet(newAttestorKey, keys, fetchedAt));
        assertEq(registry.getKey(KID_HASH), MockIssuer.MODULUS);
    }

    function test_onlyOwnerSetsAttestor() public {
        address stranger = makeAddr("stranger");
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger)
        );
        vm.prank(stranger);
        registry.setAttestor(stranger);
    }

    /// @dev The Rust TEE updater test `digest_and_signature_match_the_registry` uses the same values.
    function test_digestMatchesRustUpdater() public {
        address fixedAddress = 0x1111111111111111111111111111111111111111;
        vm.chainId(31_337);
        deployCodeTo(
            "JWKSRegistry.sol:JWKSRegistry", abi.encode(address(this), JWKS_URI), fixedAddress
        );

        JWKSRegistry.Key[] memory keys = new JWKSRegistry.Key[](2);
        keys[0] = _key("key-1", hex"c1")[0];
        keys[1] = _key("key-2", hex"d3")[0];
        bytes32 digest = JWKSRegistry(fixedAddress).hashKeySet(keys, 1_700_000_000);

        assertEq(digest, 0x4fe5221e4e43037a6991b326969306ffa1415717bc7e1580e7601075eb63d267);
        bytes memory rustSignature = hex"a16daa7c6f7b20a1e903a2825c66139d14c49999e0b0ff7e947e85241d7d6140"
            hex"42c72b86c658a54698ac50e143cb16bdd6fe1272bdaf1d2ee9bb74c0f78ccc271b";
        assertEq(ECDSA.recover(digest, rustSignature), vm.addr(1));
    }

    /// @dev Returns one key whose modulus is 256 bytes of `fill`.
    function _key(string memory kid, bytes1 fill)
        internal
        pure
        returns (JWKSRegistry.Key[] memory keys)
    {
        bytes memory modulus = new bytes(256);
        for (uint256 i = 0; i < modulus.length; ++i) {
            modulus[i] = fill;
        }
        keys = new JWKSRegistry.Key[](1);
        keys[0] = JWKSRegistry.Key({ kid: kid, modulus: modulus });
    }
}
