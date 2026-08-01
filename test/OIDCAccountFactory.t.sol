// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { IOIDCClaimVerifier } from "../src/IOIDCClaimVerifier.sol";
import { OIDCAccount } from "../src/OIDCAccount.sol";
import { OIDCRecoveryController } from "../src/OIDCRecoveryController.sol";
import { OIDCAccountFactory } from "../src/OIDCAccountFactory.sol";
import { TestOIDCClaimVerifier, TestERC7913Verifier } from "./helpers/TestVerifiers.sol";

contract OIDCAccountFactoryTest is Test {
    uint256 internal signerPk = 0xA11CE;
    bytes32 internal policy = keccak256("apple-policy");
    bytes32 internal identity = keccak256("apple-user-commitment");

    TestOIDCClaimVerifier internal claimVerifier;
    OIDCRecoveryController internal controller;
    OIDCAccountFactory internal factory;

    function setUp() public {
        vm.warp(1_700_000_000);
        claimVerifier = new TestOIDCClaimVerifier();
        controller = new OIDCRecoveryController(claimVerifier, 2 days, 7 days, 10 minutes);
        factory = new OIDCAccountFactory(controller);
    }

    function test_matchingAppleClaimCreatesExactCounterfactualAccount() public {
        bytes memory initialSigner = abi.encodePacked(vm.addr(signerPk));
        bytes32 salt = keccak256("account-salt");
        address predicted = factory.predictAccount(salt, policy, identity, initialSigner);
        OIDCAccountFactory.CreateRequest memory request = OIDCAccountFactory.CreateRequest({
            account: predicted,
            salt: salt,
            providerPolicyId: policy,
            identityCommitment: identity,
            initialSignerHash: keccak256(initialSigner),
            validAfter: uint64(block.timestamp),
            validUntil: uint64(block.timestamp + 10 minutes)
        });
        bytes32 digest = factory.hashCreate(request);
        claimVerifier.setClaim(
            IOIDCClaimVerifier.VerifiedOIDCClaim({
                providerPolicyId: policy,
                identityCommitment: identity,
                nonce: digest,
                issuedAt: uint64(block.timestamp),
                expiresAt: uint64(block.timestamp + 10 minutes)
            })
        );

        OIDCAccount account =
            factory.createAccount(request, initialSigner, _sign(signerPk, digest), hex"aabb");

        assertEq(address(account), predicted);
        assertEq(account.identityController(), address(controller));
        assertEq(account.providerPolicyId(), policy);
        assertEq(account.identityCommitment(), identity);
        assertEq(account.signer(), initialSigner);
    }

    function test_addresslessERC7913SignerProvesPossessionAndControlsCreatedAccount() public {
        uint256 keyPk = 0x9191;
        TestERC7913Verifier signerVerifier = new TestERC7913Verifier();
        bytes memory initialSigner = abi.encodePacked(address(signerVerifier), vm.addr(keyPk));
        bytes32 salt = keccak256("addressless-account-salt");
        address predicted = factory.predictAccount(salt, policy, identity, initialSigner);
        OIDCAccountFactory.CreateRequest memory request = OIDCAccountFactory.CreateRequest({
            account: predicted,
            salt: salt,
            providerPolicyId: policy,
            identityCommitment: identity,
            initialSignerHash: keccak256(initialSigner),
            validAfter: uint64(block.timestamp),
            validUntil: uint64(block.timestamp + 10 minutes)
        });
        bytes32 digest = factory.hashCreate(request);
        claimVerifier.setClaim(
            IOIDCClaimVerifier.VerifiedOIDCClaim({
                providerPolicyId: policy,
                identityCommitment: identity,
                nonce: digest,
                issuedAt: uint64(block.timestamp),
                expiresAt: uint64(block.timestamp + 10 minutes)
            })
        );

        OIDCAccount account =
            factory.createAccount(request, initialSigner, _sign(keyPk, digest), hex"01");
        bytes32 message = keccak256("addressless-account-message");
        assertEq(
            account.isValidSignature(message, _sign(keyPk, message)),
            IERC1271.isValidSignature.selector
        );
    }

    function test_claimAndRequestSubstitutionAreRejectedAndExactRequestCannotReplay() public {
        bytes memory initialSigner = abi.encodePacked(vm.addr(signerPk));
        bytes32 salt = keccak256("negative-account-salt");
        address predicted = factory.predictAccount(salt, policy, identity, initialSigner);
        OIDCAccountFactory.CreateRequest memory request = OIDCAccountFactory.CreateRequest({
            account: predicted,
            salt: salt,
            providerPolicyId: policy,
            identityCommitment: identity,
            initialSignerHash: keccak256(initialSigner),
            validAfter: uint64(block.timestamp),
            validUntil: uint64(block.timestamp + 10 minutes)
        });
        bytes32 digest = factory.hashCreate(request);
        bytes memory pop = _sign(signerPk, digest);

        claimVerifier.setClaim(
            IOIDCClaimVerifier.VerifiedOIDCClaim({
                providerPolicyId: policy,
                identityCommitment: keccak256("other-user"),
                nonce: digest,
                issuedAt: uint64(block.timestamp),
                expiresAt: uint64(block.timestamp + 10 minutes)
            })
        );
        vm.expectRevert(OIDCAccountFactory.InvalidClaim.selector);
        factory.createAccount(request, initialSigner, pop, hex"01");

        claimVerifier.setClaim(
            IOIDCClaimVerifier.VerifiedOIDCClaim({
                providerPolicyId: policy,
                identityCommitment: identity,
                nonce: digest,
                issuedAt: uint64(block.timestamp),
                expiresAt: uint64(block.timestamp + 10 minutes)
            })
        );
        bytes memory substitutedSigner = abi.encodePacked(vm.addr(0xBAD));
        vm.expectRevert(OIDCAccountFactory.InvalidCreateRequest.selector);
        factory.createAccount(request, substitutedSigner, pop, hex"01");

        vm.prank(address(0xBEEF));
        factory.createAccount(request, initialSigner, pop, hex"01");
        assertGt(predicted.code.length, 0);

        vm.expectRevert(
            abi.encodeWithSelector(OIDCAccountFactory.AccountAlreadyDeployed.selector, predicted)
        );
        factory.createAccount(request, initialSigner, pop, hex"01");
    }

    function test_createDigestCannotReplayOnAnotherChain() public {
        bytes memory initialSigner = abi.encodePacked(vm.addr(signerPk));
        bytes32 salt = keccak256("chain-account-salt");
        address predicted = factory.predictAccount(salt, policy, identity, initialSigner);
        OIDCAccountFactory.CreateRequest memory request = OIDCAccountFactory.CreateRequest({
            account: predicted,
            salt: salt,
            providerPolicyId: policy,
            identityCommitment: identity,
            initialSignerHash: keccak256(initialSigner),
            validAfter: uint64(block.timestamp),
            validUntil: uint64(block.timestamp + 10 minutes)
        });
        bytes32 digest = factory.hashCreate(request);
        claimVerifier.setClaim(
            IOIDCClaimVerifier.VerifiedOIDCClaim({
                providerPolicyId: policy,
                identityCommitment: identity,
                nonce: digest,
                issuedAt: uint64(block.timestamp),
                expiresAt: uint64(block.timestamp + 10 minutes)
            })
        );
        bytes memory pop = _sign(signerPk, digest);

        vm.chainId(block.chainid + 1);
        vm.expectRevert(OIDCAccountFactory.InvalidProofOfPossession.selector);
        factory.createAccount(request, initialSigner, pop, hex"01");
    }

    function test_hashCreateMatchesTypeScriptGoldenVector() public {
        vm.chainId(1);
        address goldenFactory = 0x2222222222222222222222222222222222222222;
        vm.etch(goldenFactory, address(factory).code);
        OIDCAccountFactory.CreateRequest memory request = OIDCAccountFactory.CreateRequest({
            account: 0x1111111111111111111111111111111111111111,
            salt: bytes32(
                uint256(0x0101010101010101010101010101010101010101010101010101010101010101)
            ),
            providerPolicyId: bytes32(
                uint256(0x0202020202020202020202020202020202020202020202020202020202020202)
            ),
            identityCommitment: bytes32(
                uint256(0x0303030303030303030303030303030303030303030303030303030303030303)
            ),
            initialSignerHash: bytes32(
                uint256(0x0404040404040404040404040404040404040404040404040404040404040404)
            ),
            validAfter: 1_700_000_000,
            validUntil: 1_700_000_600
        });

        assertEq(
            OIDCAccountFactory(goldenFactory).hashCreate(request),
            0x677f32e974fe77dca8ebabcec5fba3568dcc4dc151a979517fc1879e1321365a
        );
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
