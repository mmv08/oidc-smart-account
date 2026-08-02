// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { TEEGoogleKeyUpdater } from "../src/TEEGoogleKeyUpdater.sol";

contract TEEGoogleKeyUpdaterTest is Test {
    uint256 internal constant ATTESTOR_KEY = 0xA11CE;
    uint64 internal constant ROTATION_DELAY = 7 days;
    uint64 internal constant MAX_OBSERVATION_AGE = 15 minutes;
    uint64 internal constant MAX_REGISTRY_STALENESS = 24 hours;

    address internal governance = makeAddr("governance");
    address internal guardian = makeAddr("guardian");
    address internal attestor = vm.addr(ATTESTOR_KEY);

    TEEGoogleKeyUpdater internal updater;

    function setUp() public {
        vm.warp(1_700_000_000);
        updater = new TEEGoogleKeyUpdater(
            governance, guardian, ROTATION_DELAY, MAX_OBSERVATION_AGE, MAX_REGISTRY_STALENESS
        );
        vm.prank(governance);
        updater.scheduleAttestor(attestor);
        vm.warp(block.timestamp + ROTATION_DELAY);
        updater.finalizeAttestorRotation();
    }

    function test_attestedSnapshotPublishesGoogleKey() public {
        TEEGoogleKeyUpdater.GoogleKey[] memory keys = _oneKey(keccak256("google-key-1"), 0x11);
        uint64 fetchedAt = uint64(block.timestamp);
        bytes memory signature = _sign(keys, fetchedAt, updater.updateNonce());

        vm.prank(makeAddr("relayer"));
        updater.submitKeySet(keys, fetchedAt, updater.updateNonce(), signature);

        (bytes memory modulus, uint64 validAfter, uint64 validUntil) =
            updater.getKey(keys[0].kidHash);
        assertEq(modulus, keys[0].modulus);
        assertEq(validAfter, fetchedAt);
        assertEq(validUntil, 0);
        assertEq(updater.updateNonce(), 1);
        assertEq(updater.lastFetchedAt(), fetchedAt);
    }

    function test_rejectsSnapshotReplay() public {
        TEEGoogleKeyUpdater.GoogleKey[] memory keys = _oneKey(keccak256("google-key-1"), 0x11);
        uint64 fetchedAt = uint64(block.timestamp);
        bytes memory signature = _sign(keys, fetchedAt, 0);

        updater.submitKeySet(keys, fetchedAt, 0, signature);

        vm.expectRevert(
            abi.encodeWithSelector(
                TEEGoogleKeyUpdater.InvalidNonce.selector, uint256(1), uint256(0)
            )
        );
        updater.submitKeySet(keys, fetchedAt, 0, signature);
    }

    function test_rejectsNonAttestorSignature() public {
        TEEGoogleKeyUpdater.GoogleKey[] memory keys = _oneKey(keccak256("google-key-1"), 0x11);
        uint64 fetchedAt = uint64(block.timestamp);
        bytes32 digest = updater.keySetDigest(keys, fetchedAt, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, digest);

        vm.expectRevert(TEEGoogleKeyUpdater.InvalidAttestorSignature.selector);
        updater.submitKeySet(keys, fetchedAt, 0, abi.encodePacked(r, s, v));
    }

    function test_newSnapshotRetiresMissingKeyWithoutInvalidatingOlderTokens() public {
        bytes32 firstKid = bytes32(uint256(1));
        bytes32 secondKid = bytes32(uint256(2));
        TEEGoogleKeyUpdater.GoogleKey[] memory initial = _twoKeys(firstKid, 0x11, secondKid, 0x22);
        uint64 firstFetch = uint64(block.timestamp);
        updater.submitKeySet(initial, firstFetch, 0, _sign(initial, firstFetch, 0));

        uint64 secondFetch = firstFetch + 60;
        vm.warp(secondFetch);
        TEEGoogleKeyUpdater.GoogleKey[] memory next = _oneKey(secondKid, 0x22);
        bytes memory signature = _sign(next, secondFetch, 1);
        updater.submitKeySet(next, secondFetch, 1, signature);

        (bytes memory firstModulus, uint64 firstValidAfter, uint64 firstValidUntil) =
            updater.getKey(firstKid);
        assertEq(firstModulus, initial[0].modulus);
        assertEq(firstValidAfter, firstFetch);
        assertEq(firstValidUntil, secondFetch);

        (bytes memory secondModulus, uint64 secondValidAfter, uint64 secondValidUntil) =
            updater.getKey(secondKid);
        assertEq(secondModulus, initial[1].modulus);
        assertEq(secondValidAfter, firstFetch);
        assertEq(secondValidUntil, 0);
    }

    function test_rejectsStaleObservation() public {
        TEEGoogleKeyUpdater.GoogleKey[] memory keys = _oneKey(keccak256("google-key-1"), 0x11);
        uint64 staleFetch = uint64(block.timestamp) - MAX_OBSERVATION_AGE - 1;
        bytes memory signature = _sign(keys, staleFetch, 0);

        vm.expectRevert(TEEGoogleKeyUpdater.InvalidObservationTime.selector);
        updater.submitKeySet(keys, staleFetch, 0, signature);
    }

    function test_rejectsEmptyAndNonCanonicalKeySets() public {
        TEEGoogleKeyUpdater.GoogleKey[] memory empty = new TEEGoogleKeyUpdater.GoogleKey[](0);
        uint64 fetchedAt = uint64(block.timestamp);
        bytes memory emptySignature = _sign(empty, fetchedAt, 0);
        vm.expectRevert(TEEGoogleKeyUpdater.InvalidKeySet.selector);
        updater.submitKeySet(empty, fetchedAt, 0, emptySignature);

        TEEGoogleKeyUpdater.GoogleKey[] memory unsorted =
            _twoKeys(bytes32(uint256(2)), 0x22, bytes32(uint256(1)), 0x11);
        bytes memory unsortedSignature = _sign(unsorted, fetchedAt, 0);
        vm.expectRevert(TEEGoogleKeyUpdater.InvalidKeySet.selector);
        updater.submitKeySet(unsorted, fetchedAt, 0, unsortedSignature);

        TEEGoogleKeyUpdater.GoogleKey[] memory duplicate =
            _twoKeys(bytes32(uint256(1)), 0x11, bytes32(uint256(1)), 0x11);
        bytes memory duplicateSignature = _sign(duplicate, fetchedAt, 0);
        vm.expectRevert(TEEGoogleKeyUpdater.InvalidKeySet.selector);
        updater.submitKeySet(duplicate, fetchedAt, 0, duplicateSignature);
    }

    function test_rejectsNon2048BitOrEvenRsaModulus() public {
        uint64 fetchedAt = uint64(block.timestamp);
        TEEGoogleKeyUpdater.GoogleKey[] memory keys = _oneKey(bytes32(uint256(1)), 0x11);

        keys[0].modulus[0] = 0x7f;
        bytes memory signature = _sign(keys, fetchedAt, 0);
        vm.expectRevert(TEEGoogleKeyUpdater.InvalidKeySet.selector);
        updater.submitKeySet(keys, fetchedAt, 0, signature);

        keys = _oneKey(bytes32(uint256(1)), 0x11);
        keys[0].modulus[255] = 0x10;
        signature = _sign(keys, fetchedAt, 0);
        vm.expectRevert(TEEGoogleKeyUpdater.InvalidKeySet.selector);
        updater.submitKeySet(keys, fetchedAt, 0, signature);
    }

    function test_governanceRotationIsDelayedAndInvalidatesOldAttestorSignatures() public {
        uint256 nextAttestorKey = 0xB0B;
        address nextAttestor = vm.addr(nextAttestorKey);
        TEEGoogleKeyUpdater.GoogleKey[] memory keys = _oneKey(keccak256("google-key-1"), 0x11);

        vm.prank(governance);
        updater.scheduleAttestor(nextAttestor);
        uint64 readyAt = uint64(block.timestamp) + ROTATION_DELAY;
        uint64 fetchedAt = readyAt;
        bytes memory oldSignature = _sign(keys, fetchedAt, 0);
        assertEq(updater.pendingAttestor(), nextAttestor);
        assertEq(updater.pendingAttestorReadyAt(), readyAt);

        vm.warp(readyAt - 1);
        vm.expectRevert(TEEGoogleKeyUpdater.AttestorRotationNotReady.selector);
        updater.finalizeAttestorRotation();

        vm.warp(readyAt);
        updater.finalizeAttestorRotation();
        assertEq(updater.attestor(), nextAttestor);
        assertEq(updater.attestorEpoch(), 2);

        vm.expectRevert(TEEGoogleKeyUpdater.InvalidAttestorSignature.selector);
        updater.submitKeySet(keys, fetchedAt, 0, oldSignature);

        bytes32 digest = updater.keySetDigest(keys, fetchedAt, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(nextAttestorKey, digest);
        updater.submitKeySet(keys, fetchedAt, 0, abi.encodePacked(r, s, v));
    }

    function test_guardianPauseStopsKeyConsumptionAndUnpauseIsDelayed() public {
        TEEGoogleKeyUpdater.GoogleKey[] memory keys = _oneKey(keccak256("google-key-1"), 0x11);
        uint64 fetchedAt = uint64(block.timestamp);
        updater.submitKeySet(keys, fetchedAt, 0, _sign(keys, fetchedAt, 0));

        vm.prank(guardian);
        updater.pause();
        assertTrue(updater.paused());
        (bytes memory pausedModulus,,) = updater.getKey(keys[0].kidHash);
        assertEq(pausedModulus.length, 0);

        vm.prank(guardian);
        vm.expectRevert();
        updater.scheduleUnpause();

        vm.prank(governance);
        updater.scheduleUnpause();
        uint64 readyAt = uint64(block.timestamp) + ROTATION_DELAY;
        assertEq(updater.unpauseReadyAt(), readyAt);

        vm.warp(readyAt - 1);
        vm.expectRevert(TEEGoogleKeyUpdater.UnpauseNotReady.selector);
        updater.finalizeUnpause();

        vm.warp(readyAt);
        bytes memory heartbeatSignature = _sign(keys, readyAt, 1);
        updater.submitKeySet(keys, readyAt, 1, heartbeatSignature);
        (bytes memory stillPausedModulus,,) = updater.getKey(keys[0].kidHash);
        assertEq(stillPausedModulus.length, 0);

        updater.finalizeUnpause();
        (bytes memory restoredModulus,,) = updater.getKey(keys[0].kidHash);
        assertEq(restoredModulus, keys[0].modulus);
    }

    function test_unpauseRequiresHeartbeatObservedAfterScheduling() public {
        TEEGoogleKeyUpdater.GoogleKey[] memory keys = _oneKey(keccak256("google-key-1"), 0x11);
        uint64 fetchedAt = uint64(block.timestamp);
        updater.submitKeySet(keys, fetchedAt, 0, _sign(keys, fetchedAt, 0));

        vm.prank(guardian);
        updater.pause();
        vm.prank(governance);
        updater.scheduleUnpause();
        vm.warp(block.timestamp + ROTATION_DELAY);

        vm.expectRevert(TEEGoogleKeyUpdater.FreshHeartbeatRequired.selector);
        updater.finalizeUnpause();
    }

    function test_staleRegistryFailsClosedUntilFreshHeartbeat() public {
        TEEGoogleKeyUpdater.GoogleKey[] memory keys = _oneKey(keccak256("google-key-1"), 0x11);
        uint64 fetchedAt = uint64(block.timestamp);
        updater.submitKeySet(keys, fetchedAt, 0, _sign(keys, fetchedAt, 0));

        uint64 heartbeatAt = fetchedAt + MAX_REGISTRY_STALENESS + 1;
        vm.warp(heartbeatAt);
        (bytes memory staleModulus,,) = updater.getKey(keys[0].kidHash);
        assertEq(staleModulus.length, 0);

        bytes memory heartbeatSignature = _sign(keys, heartbeatAt, 1);
        updater.submitKeySet(keys, heartbeatAt, 1, heartbeatSignature);
        (bytes memory freshModulus,,) = updater.getKey(keys[0].kidHash);
        assertEq(freshModulus, keys[0].modulus);
    }

    function test_reappearingKeyStartsANewValidityInterval() public {
        bytes32 firstKid = bytes32(uint256(1));
        bytes32 secondKid = bytes32(uint256(2));
        TEEGoogleKeyUpdater.GoogleKey[] memory both = _twoKeys(firstKid, 0x11, secondKid, 0x22);
        uint64 firstFetch = uint64(block.timestamp);
        updater.submitKeySet(both, firstFetch, 0, _sign(both, firstFetch, 0));

        TEEGoogleKeyUpdater.GoogleKey[] memory secondOnly = _oneKey(secondKid, 0x22);
        uint64 retirementFetch = firstFetch + 60;
        vm.warp(retirementFetch);
        updater.submitKeySet(secondOnly, retirementFetch, 1, _sign(secondOnly, retirementFetch, 1));

        uint64 reappearanceFetch = retirementFetch + 60;
        vm.warp(reappearanceFetch);
        updater.submitKeySet(both, reappearanceFetch, 2, _sign(both, reappearanceFetch, 2));

        (, uint64 validAfter, uint64 validUntil) = updater.getKey(firstKid);
        assertEq(validAfter, reappearanceFetch);
        assertEq(validUntil, 0);
    }

    function test_rejectsChangedMaterialForExistingKid() public {
        bytes32 kidHash = bytes32(uint256(1));
        TEEGoogleKeyUpdater.GoogleKey[] memory initial = _oneKey(kidHash, 0x11);
        uint64 firstFetch = uint64(block.timestamp);
        updater.submitKeySet(initial, firstFetch, 0, _sign(initial, firstFetch, 0));

        uint64 nextFetch = firstFetch + 60;
        vm.warp(nextFetch);
        TEEGoogleKeyUpdater.GoogleKey[] memory changed = _oneKey(kidHash, 0x22);
        bytes memory signature = _sign(changed, nextFetch, 1);
        vm.expectRevert(
            abi.encodeWithSelector(TEEGoogleKeyUpdater.ChangedKeyMaterial.selector, kidHash)
        );
        updater.submitKeySet(changed, nextFetch, 1, signature);
    }

    function test_rustSnapshotFixtureMatchesSolidityEip712DigestAndSignature() public {
        string memory json = vm.readFile("test/fixtures/tee-key-snapshot.json");
        address fixtureUpdater = vm.parseJsonAddress(json, ".updater");
        vm.chainId(vm.parseJsonUint(json, ".chainId"));
        vm.etch(fixtureUpdater, address(updater).code);

        TEEGoogleKeyUpdater.GoogleKey[] memory keys = new TEEGoogleKeyUpdater.GoogleKey[](4);
        for (uint256 i; i < keys.length; ++i) {
            string memory prefix = string.concat(".keys[", vm.toString(i), "]");
            keys[i] = TEEGoogleKeyUpdater.GoogleKey({
                kidHash: vm.parseJsonBytes32(json, string.concat(prefix, ".kidHash")),
                modulus: vm.parseJsonBytes(json, string.concat(prefix, ".modulus"))
            });
        }

        uint64 fetchedAt = uint64(vm.parseJsonUint(json, ".fetchedAt"));
        uint64 epoch = uint64(vm.parseJsonUint(json, ".attestorEpoch"));
        uint256 nonce = vm.parseJsonUint(json, ".nonce");
        bytes32 expectedDigest = vm.parseJsonBytes32(json, ".digest");
        bytes32 actualDigest =
            TEEGoogleKeyUpdater(fixtureUpdater).keySetDigestForEpoch(keys, fetchedAt, epoch, nonce);

        assertEq(actualDigest, expectedDigest);
        assertEq(
            ECDSA.recover(actualDigest, vm.parseJsonBytes(json, ".signature")),
            vm.parseJsonAddress(json, ".attestor")
        );
    }

    function _sign(TEEGoogleKeyUpdater.GoogleKey[] memory keys, uint64 fetchedAt, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = updater.keySetDigest(keys, fetchedAt, nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTESTOR_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _oneKey(bytes32 kidHash, uint8 fill)
        internal
        pure
        returns (TEEGoogleKeyUpdater.GoogleKey[] memory keys)
    {
        keys = new TEEGoogleKeyUpdater.GoogleKey[](1);
        keys[0] = TEEGoogleKeyUpdater.GoogleKey({ kidHash: kidHash, modulus: _modulus(fill) });
    }

    function _twoKeys(bytes32 firstKid, uint8 firstFill, bytes32 secondKid, uint8 secondFill)
        internal
        pure
        returns (TEEGoogleKeyUpdater.GoogleKey[] memory keys)
    {
        keys = new TEEGoogleKeyUpdater.GoogleKey[](2);
        keys[0] = TEEGoogleKeyUpdater.GoogleKey({ kidHash: firstKid, modulus: _modulus(firstFill) });
        keys[1] =
            TEEGoogleKeyUpdater.GoogleKey({ kidHash: secondKid, modulus: _modulus(secondFill) });
    }

    function _modulus(uint8 fill) internal pure returns (bytes memory modulus) {
        modulus = new bytes(256);
        for (uint256 i; i < modulus.length; ++i) {
            modulus[i] = bytes1(fill);
        }
        modulus[0] = bytes1(fill | 0x80);
        modulus[255] = bytes1(fill | 0x01);
    }
}
