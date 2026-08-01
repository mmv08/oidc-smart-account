// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { ProviderKeyRegistry } from "../src/ProviderKeyRegistry.sol";
import { IdentityIntentVerifier } from "../src/IdentityIntentVerifier.sol";

contract IdentityIntentVerifierTest is Test {
    ProviderKeyRegistry internal registry;
    IdentityIntentVerifier internal verifier;
    uint256 internal attestorPk1 = 0xA11CE;
    uint256 internal attestorPk2 = 0xB0B;
    bytes32 internal provider = keccak256("provider-policy");
    bytes32 internal keyHash;

    function setUp() public {
        vm.warp(1000);
        registry = new ProviderKeyRegistry(address(this));
        registry.registerProvider(provider);
        keyHash = registry.publishKey(provider, keccak256("kid"), bytes("canonical-jwk"), 900, 2000);
        address[] memory attestors = new address[](2);
        attestors[0] = vm.addr(attestorPk1);
        attestors[1] = vm.addr(attestorPk2);
        if (attestors[0] > attestors[1]) {
            (attestors[0], attestors[1]) = (attestors[1], attestors[0]);
        }
        verifier = new IdentityIntentVerifier(registry, attestors, 2, 10 minutes, address(this));
    }

    function _intent() internal view returns (IdentityIntentVerifier.Intent memory intent) {
        intent = IdentityIntentVerifier.Intent({
            version: 1,
            action: IdentityIntentVerifier.Action.ADD,
            identityCommitment: keccak256("opaque-random-commitment"),
            account: address(0xAACC),
            controller: address(this),
            currentSignerHash: keccak256("old"),
            newSignerHash: keccak256("new"),
            recoveryNonce: 0,
            intentNonce: keccak256("oidc-nonce"),
            providerId: provider,
            providerKeyHash: bytes32(0),
            issuedAt: 1000,
            validAfter: 1000,
            validUntil: 1300,
            chainId: block.chainid,
            attestorEpoch: verifier.attestorEpoch()
        });
    }

    function _attest(bytes32 digest) internal returns (bytes[] memory signatures) {
        bytes32 attestationDigest = verifier.hashAttestation(digest, keyHash, 1000);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(attestorPk1, attestationDigest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(attestorPk2, attestationDigest);
        bytes memory sig1 = abi.encodePacked(r1, s1, v1);
        bytes memory sig2 = abi.encodePacked(r2, s2, v2);
        signatures = new bytes[](2);
        if (vm.addr(attestorPk1) < vm.addr(attestorPk2)) {
            signatures[0] = abi.encode(keyHash, uint64(1000), sig1);
            signatures[1] = abi.encode(keyHash, uint64(1000), sig2);
        } else {
            signatures[0] = abi.encode(keyHash, uint64(1000), sig2);
            signatures[1] = abi.encode(keyHash, uint64(1000), sig1);
        }
    }

    function test_independentAttestorsCanUseDifferentRotatingProviderKeysAndTokenTimes() public {
        bytes32 nextKey = registry.publishKey(
            provider, keccak256("next-kid"), bytes("next-canonical-jwk"), 900, 2000
        );
        IdentityIntentVerifier.Intent memory intent = _intent();
        bytes32 digest = verifier.hashIntent(intent);
        bytes[] memory attestations = new bytes[](2);

        bytes32 firstDigest = verifier.hashAttestation(digest, keyHash, 999);
        bytes32 secondDigest = verifier.hashAttestation(digest, nextKey, 1000);
        bytes memory firstSignature;
        bytes memory secondSignature;
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(attestorPk1, firstDigest);
            firstSignature = abi.encodePacked(r, s, v);
        }
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(attestorPk2, secondDigest);
            secondSignature = abi.encodePacked(r, s, v);
        }
        if (vm.addr(attestorPk1) < vm.addr(attestorPk2)) {
            attestations[0] = abi.encode(keyHash, uint64(999), firstSignature);
            attestations[1] = abi.encode(nextKey, uint64(1000), secondSignature);
        } else {
            attestations[0] = abi.encode(nextKey, uint64(1000), secondSignature);
            attestations[1] = abi.encode(keyHash, uint64(999), firstSignature);
        }
        assertEq(verifier.consume(intent, attestations), digest);
    }

    function test_twoAttestorsAuthorizeExactIntentOnlyOnce() public {
        IdentityIntentVerifier.Intent memory intent = _intent();
        bytes32 digest = verifier.hashIntent(intent);
        bytes[] memory signatures = _attest(digest);
        assertEq(verifier.consume(intent, signatures), digest);
        assertTrue(verifier.consumed(digest));
        vm.expectRevert(
            abi.encodeWithSelector(IdentityIntentVerifier.IntentAlreadyConsumed.selector, digest)
        );
        verifier.consume(intent, signatures);
    }

    function test_duplicateOrUnsortedAttestorsCannotReachThreshold() public {
        IdentityIntentVerifier.Intent memory intent = _intent();
        bytes32 digest = verifier.hashIntent(intent);
        bytes[] memory sigs = _attest(digest);
        sigs[1] = sigs[0];
        vm.expectRevert(IdentityIntentVerifier.InvalidAttestation.selector);
        verifier.consume(intent, sigs);

        address[] memory duplicate = new address[](2);
        duplicate[0] = vm.addr(attestorPk1);
        duplicate[1] = duplicate[0];
        vm.expectRevert(IdentityIntentVerifier.InvalidAttestorConfiguration.selector);
        verifier.setAttestors(duplicate, 2);
    }

    function test_rejectsFutureStaleExpiredWrongKeyControllerEpochAndChain() public {
        IdentityIntentVerifier.Intent memory intent = _intent();
        intent.issuedAt = 1001;
        bytes[] memory sigs = _attest(verifier.hashIntent(intent));
        vm.expectRevert(IdentityIntentVerifier.InvalidIntentTime.selector);
        verifier.consume(intent, sigs);

        intent = _intent();
        intent.issuedAt = 1;
        intent.validAfter = 1;
        intent.validUntil = 1000;
        sigs = _attest(verifier.hashIntent(intent));
        vm.expectRevert(IdentityIntentVerifier.InvalidIntentTime.selector);
        verifier.consume(intent, sigs);

        intent = _intent();
        intent.providerKeyHash = keccak256("wrong");
        sigs = _attest(verifier.hashIntent(intent));
        vm.expectRevert(IdentityIntentVerifier.InvalidProviderKey.selector);
        verifier.consume(intent, sigs);

        intent = _intent();
        intent.controller = address(0xBEEF);
        sigs = _attest(verifier.hashIntent(intent));
        vm.expectRevert();
        verifier.consume(intent, sigs);

        intent = _intent();
        intent.chainId = block.chainid + 1;
        sigs = _attest(verifier.hashIntent(intent));
        vm.expectPartialRevert(IdentityIntentVerifier.InvalidChain.selector);
        verifier.consume(intent, sigs);

        intent = _intent();
        intent.attestorEpoch++;
        sigs = _attest(verifier.hashIntent(intent));
        vm.expectPartialRevert(IdentityIntentVerifier.InvalidEpoch.selector);
        verifier.consume(intent, sigs);
    }

    function testFuzz_anyIdentityMutationInvalidatesExistingAttestation(bytes32 changedCommitment)
        public
    {
        vm.assume(changedCommitment != keccak256("opaque-random-commitment"));
        IdentityIntentVerifier.Intent memory intent = _intent();
        bytes[] memory signatures = _attest(verifier.hashIntent(intent));
        intent.identityCommitment = changedCommitment;
        vm.expectRevert(IdentityIntentVerifier.InvalidAttestation.selector);
        verifier.consume(intent, signatures);
    }

    function test_actionRequestHashBindsProviderPolicy() public view {
        IdentityIntentVerifier.Intent memory intent = _intent();
        bytes32 original = verifier.hashActionRequest(intent);
        intent.providerId = keccak256("different-provider-policy");
        assertNotEq(verifier.hashActionRequest(intent), original);
    }

    function test_actionRequestHashMatchesTypeScriptGoldenVector() public {
        vm.chainId(31_337);
        address fixedVerifierAddress = address(0xCcCC);
        vm.etch(fixedVerifierAddress, address(verifier).code);
        IdentityIntentVerifier.Intent memory intent = IdentityIntentVerifier.Intent({
            version: 1,
            action: IdentityIntentVerifier.Action.CREATE,
            identityCommitment: bytes32(
                uint256(0x5656565656565656565656565656565656565656565656565656565656565656)
            ),
            account: address(0xaAaA),
            controller: address(0xbBbB),
            currentSignerHash: bytes32(0),
            newSignerHash: bytes32(
                uint256(0xfe87802413d7ef2c0aca6eaaa9d44d0c79ccf07d8808832e4f05d1441a4f7af8)
            ),
            recoveryNonce: 0,
            intentNonce: bytes32(
                uint256(0x3434343434343434343434343434343434343434343434343434343434343434)
            ),
            providerId: keccak256("google-client-policy-v1"),
            providerKeyHash: bytes32(0),
            issuedAt: 1_900_000_000,
            validAfter: 1_900_000_000,
            validUntil: 1_900_003_600,
            chainId: 31_337,
            attestorEpoch: 7
        });
        assertEq(
            IdentityIntentVerifier(fixedVerifierAddress).hashActionRequest(intent),
            0x1fcaaf4f7325eb077e92f3d9f39ba6a2331582b223e1ceecae10a093f52118f0
        );
    }
}

