// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { ProviderKeyRegistry } from "../src/ProviderKeyRegistry.sol";
import { IdentityIntentVerifier } from "../src/IdentityIntentVerifier.sol";
import { IdentityRecoveryManager } from "../src/IdentityRecoveryManager.sol";
import { IdentityAccountFactory } from "../src/IdentityAccountFactory.sol";
import { IndependentKeyAccount } from "../src/IndependentKeyAccount.sol";

contract IdentityAccountFactoryTest is Test {
    uint256 internal a1 = 0xA11CE;
    uint256 internal a2 = 0xB0B;
    uint256 internal userPk = 0xCAFE;
    bytes32 internal provider = keccak256("provider");
    bytes32 internal keyHash;
    IdentityIntentVerifier internal verifier;
    IdentityRecoveryManager internal manager;
    IdentityAccountFactory internal factory;

    function setUp() public {
        vm.warp(50_000);
        ProviderKeyRegistry registry = new ProviderKeyRegistry(address(this));
        registry.registerProvider(provider);
        keyHash = registry.publishKey(provider, keccak256("kid"), bytes("jwk"), 40_000, 60_000);
        address[] memory aa = new address[](2);
        aa[0] = vm.addr(a1);
        aa[1] = vm.addr(a2);
        if (aa[0] > aa[1]) (aa[0], aa[1]) = (aa[1], aa[0]);
        verifier = new IdentityIntentVerifier(registry, aa, 2, 1 hours, address(this));
        manager = new IdentityRecoveryManager(verifier, 1 days, 7 days, address(this));
        factory = new IdentityAccountFactory(manager, verifier);
    }

    function _sign(uint256 pk, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _attest(bytes32 digest) internal returns (bytes[] memory sigs) {
        uint64 tokenIssuedAt = uint64(block.timestamp);
        bytes32 attestationDigest = verifier.hashAttestation(digest, keyHash, tokenIssuedAt);
        bytes memory s1 = _sign(a1, attestationDigest);
        bytes memory s2 = _sign(a2, attestationDigest);
        sigs = new bytes[](2);
        if (vm.addr(a1) < vm.addr(a2)) {
            sigs[0] = abi.encode(keyHash, tokenIssuedAt, s1);
            sigs[1] = abi.encode(keyHash, tokenIssuedAt, s2);
        } else {
            sigs[0] = abi.encode(keyHash, tokenIssuedAt, s2);
            sigs[1] = abi.encode(keyHash, tokenIssuedAt, s1);
        }
    }

    function _createIntent(bytes32 identity, bytes32 salt, bytes memory signer, bytes32 nonce)
        internal
        view
        returns (IdentityIntentVerifier.Intent memory intent)
    {
        intent = IdentityIntentVerifier.Intent({
            version: 1,
            action: IdentityIntentVerifier.Action.CREATE,
            identityCommitment: identity,
            account: factory.predictAccount(salt, identity, signer),
            controller: address(factory),
            currentSignerHash: bytes32(0),
            newSignerHash: keccak256(signer),
            recoveryNonce: 0,
            intentNonce: nonce,
            providerId: provider,
            providerKeyHash: bytes32(0),
            issuedAt: 50_000,
            validAfter: 50_000,
            validUntil: 50_600,
            chainId: block.chainid,
            attestorEpoch: verifier.attestorEpoch()
        });
    }

    function test_create2PredictionAndCreationBindExactInitialSigner() public {
        bytes32 identity = keccak256("random-opaque-identity");
        bytes32 salt = keccak256("random-salt");
        bytes memory signer = abi.encodePacked(vm.addr(userPk));
        address predicted = factory.predictAccount(salt, identity, signer);
        IdentityIntentVerifier.Intent memory intent = IdentityIntentVerifier.Intent({
            version: 1,
            action: IdentityIntentVerifier.Action.CREATE,
            identityCommitment: identity,
            account: predicted,
            controller: address(factory),
            currentSignerHash: bytes32(0),
            newSignerHash: keccak256(signer),
            recoveryNonce: 0,
            intentNonce: keccak256("oidc-create-nonce"),
            providerId: provider,
            providerKeyHash: bytes32(0),
            issuedAt: 50_000,
            validAfter: 50_000,
            validUntil: 50_600,
            chainId: block.chainid,
            attestorEpoch: verifier.attestorEpoch()
        });
        bytes32 digest = verifier.hashIntent(intent);
        vm.prank(address(0xF00D));
        IndependentKeyAccount deployed = factory.createAccount(
            salt, identity, signer, _sign(userPk, digest), intent, _attest(digest)
        );
        assertEq(address(deployed), predicted);
        assertTrue(deployed.isSigner(signer));
    }

    function test_frontrunnerCannotAlterSignerOrPredictedAccount() public {
        bytes32 identity = keccak256("identity-2");
        bytes32 salt = keccak256("salt-2");
        bytes memory signer = abi.encodePacked(vm.addr(userPk));
        IdentityIntentVerifier.Intent memory intent =
            _createIntent(identity, salt, signer, keccak256("nonce-2"));
        bytes32 digest = verifier.hashIntent(intent);
        bytes memory pop = _sign(userPk, digest);
        bytes[] memory attestations = _attest(digest);

        bytes memory attackerSigner = abi.encodePacked(address(0xBAD0));
        vm.prank(address(0xF00D));
        vm.expectRevert(IdentityAccountFactory.InvalidCreateIntent.selector);
        factory.createAccount(salt, identity, attackerSigner, pop, intent, attestations);

        IdentityIntentVerifier.Intent memory altered =
            _createIntent(identity, salt, signer, keccak256("nonce-2"));
        altered.account = address(0xBEEF);
        vm.prank(address(0xF00D));
        vm.expectRevert(IdentityAccountFactory.InvalidCreateIntent.selector);
        factory.createAccount(salt, identity, signer, pop, altered, attestations);

        vm.prank(address(0xF00D));
        IndependentKeyAccount deployed =
            factory.createAccount(salt, identity, signer, pop, intent, attestations);
        assertEq(address(deployed), intent.account);
    }

    function test_createRequiresProofAndConsumedIntentCannotReplay() public {
        bytes32 identity = keccak256("identity-3");
        bytes32 salt = keccak256("salt-3");
        bytes memory signer = abi.encodePacked(vm.addr(userPk));
        IdentityIntentVerifier.Intent memory intent =
            _createIntent(identity, salt, signer, keccak256("nonce-3"));
        bytes32 digest = verifier.hashIntent(intent);
        bytes[] memory attestations = _attest(digest);
        vm.expectRevert(IdentityAccountFactory.InvalidProofOfPossession.selector);
        factory.createAccount(salt, identity, signer, _sign(0x123456, digest), intent, attestations);

        bytes memory pop = _sign(userPk, digest);
        factory.createAccount(salt, identity, signer, pop, intent, attestations);
        vm.expectRevert();
        factory.createAccount(salt, identity, signer, pop, intent, attestations);
    }

    function test_invalidInitialSignerAndWrongActionAreRejected() public {
        bytes32 identity = keccak256("identity-4");
        bytes32 salt = keccak256("salt-4");
        bytes memory signer = abi.encodePacked(vm.addr(userPk));
        IdentityIntentVerifier.Intent memory intent =
            _createIntent(identity, salt, signer, keccak256("nonce-4"));
        intent.action = IdentityIntentVerifier.Action.ADD;
        bytes32 digest = verifier.hashIntent(intent);
        bytes[] memory attestations = _attest(digest);
        vm.expectRevert(IdentityAccountFactory.InvalidCreateIntent.selector);
        factory.createAccount(salt, identity, signer, _sign(userPk, digest), intent, attestations);

        bytes memory dangerous = abi.encodePacked(address(4));
        IdentityIntentVerifier.Intent memory dangerousIntent =
            _createIntent(identity, salt, dangerous, keccak256("n"));
        digest = verifier.hashIntent(dangerousIntent);
        attestations = _attest(digest);
        vm.expectRevert();
        factory.createAccount(salt, identity, dangerous, bytes(""), dangerousIntent, attestations);
    }
}
