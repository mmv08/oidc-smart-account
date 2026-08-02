// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { IOIDCClaimVerifier } from "../src/IOIDCClaimVerifier.sol";
import { OIDCAccount } from "../src/OIDCAccount.sol";
import { OIDCRecoveryController } from "../src/OIDCRecoveryController.sol";
import {
    RevocableTestERC7913Verifier,
    TestOIDCClaimVerifier,
    TestERC7913Verifier
} from "./helpers/TestVerifiers.sol";

contract OIDCRecoveryControllerTest is Test {
    uint256 internal currentPk = 0xA11CE;
    uint256 internal replacementPk = 0xB0B;
    bytes32 internal policy = keccak256("google-policy");
    bytes32 internal identity = keccak256("google-user-commitment");

    TestOIDCClaimVerifier internal claimVerifier;
    OIDCRecoveryController internal controller;
    OIDCAccount internal account;

    function setUp() public {
        vm.warp(1_700_000_000);
        claimVerifier = new TestOIDCClaimVerifier();
        controller = new OIDCRecoveryController(claimVerifier, 2 days, 7 days, 10 minutes);
        account = new OIDCAccount(
            address(controller), policy, identity, abi.encodePacked(vm.addr(currentPk))
        );
    }

    function test_constructorRejectsAnAddressWithoutVerifierCode() public {
        vm.expectRevert(OIDCRecoveryController.InvalidConfiguration.selector);
        new OIDCRecoveryController(IOIDCClaimVerifier(address(0x1234)), 2 days, 7 days, 10 minutes);
    }

    function test_verifiedMatchingClaimSchedulesAndFinalizesExactSignerReplacement() public {
        bytes memory newSigner = abi.encodePacked(vm.addr(replacementPk));
        OIDCRecoveryController.RecoveryRequest memory request = _request(newSigner);
        bytes32 digest = controller.hashRecovery(request);
        _setFreshClaim(digest);

        controller.schedule(request, newSigner, _sign(replacementPk, digest), hex"1234");

        OIDCRecoveryController.PendingRecovery memory pending =
            controller.getPending(address(account));
        assertEq(pending.digest, digest);
        assertEq(pending.newSigner, newSigner);
        assertEq(pending.executeAfter, block.timestamp + 2 days);
        assertEq(controller.recoveryNonces(address(account)), 1);

        vm.warp(block.timestamp + 2 days);
        controller.finalize(address(account), _sign(replacementPk, digest));

        assertEq(account.signer(), newSigner);
        assertEq(controller.getPending(address(account)).executeAfter, 0);
    }

    function test_addresslessERC7913SignerCanBeRecoveredAndControlAccount() public {
        uint256 keyPk = 0x9191;
        TestERC7913Verifier signerVerifier = new TestERC7913Verifier();
        bytes memory newSigner = abi.encodePacked(address(signerVerifier), vm.addr(keyPk));
        OIDCRecoveryController.RecoveryRequest memory request = _request(newSigner);
        bytes32 digest = controller.hashRecovery(request);
        _setFreshClaim(digest);

        controller.schedule(request, newSigner, _sign(keyPk, digest), hex"01");
        vm.warp(block.timestamp + 2 days);
        controller.finalize(address(account), _sign(keyPk, digest));

        bytes32 message = keccak256("recovered-addressless-message");
        assertEq(account.signer(), newSigner);
        assertEq(
            account.isValidSignature(message, _sign(keyPk, message)),
            IERC1271.isValidSignature.selector
        );
    }

    function test_finalizeRevalidatesDynamicSignerProofOfPossession() public {
        uint256 keyPk = 0x9292;
        RevocableTestERC7913Verifier signerVerifier = new RevocableTestERC7913Verifier();
        bytes memory newSigner = abi.encodePacked(address(signerVerifier), vm.addr(keyPk));
        OIDCRecoveryController.RecoveryRequest memory request = _request(newSigner);
        bytes32 digest = controller.hashRecovery(request);
        bytes memory proof = _sign(keyPk, digest);
        _setFreshClaim(digest);

        controller.schedule(request, newSigner, proof, hex"01");
        signerVerifier.setEnabled(false);
        vm.warp(block.timestamp + 2 days);

        vm.expectRevert(OIDCRecoveryController.InvalidProofOfPossession.selector);
        controller.finalize(address(account), proof);
        assertEq(controller.getPending(address(account)).digest, digest);

        signerVerifier.setEnabled(true);
        controller.finalize(address(account), proof);
        assertEq(account.signer(), newSigner);
    }

    function test_claimMustMatchPolicyIdentityNonceAndFreshness() public {
        bytes memory newSigner = abi.encodePacked(vm.addr(replacementPk));
        OIDCRecoveryController.RecoveryRequest memory request = _request(newSigner);
        bytes32 digest = controller.hashRecovery(request);
        bytes memory pop = _sign(replacementPk, digest);

        IOIDCClaimVerifier.VerifiedOIDCClaim memory claim = IOIDCClaimVerifier.VerifiedOIDCClaim({
            providerPolicyId: policy,
            identityCommitment: identity,
            nonce: digest,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + 10 minutes)
        });

        claim.providerPolicyId = keccak256("apple-policy");
        claimVerifier.setClaim(claim);
        vm.expectRevert(OIDCRecoveryController.InvalidClaim.selector);
        controller.schedule(request, newSigner, pop, hex"01");

        claim.providerPolicyId = policy;
        claim.identityCommitment = keccak256("other-user");
        claimVerifier.setClaim(claim);
        vm.expectRevert(OIDCRecoveryController.InvalidClaim.selector);
        controller.schedule(request, newSigner, pop, hex"01");

        claim.identityCommitment = identity;
        claim.nonce = keccak256("other-action");
        claimVerifier.setClaim(claim);
        vm.expectRevert(OIDCRecoveryController.InvalidClaim.selector);
        controller.schedule(request, newSigner, pop, hex"01");

        claim.nonce = digest;
        claim.issuedAt = uint64(block.timestamp + 1);
        claimVerifier.setClaim(claim);
        vm.expectRevert(OIDCRecoveryController.InvalidClaim.selector);
        controller.schedule(request, newSigner, pop, hex"01");

        claim.issuedAt = uint64(block.timestamp - 11 minutes);
        claim.expiresAt = uint64(block.timestamp + 1);
        claimVerifier.setClaim(claim);
        vm.expectRevert(OIDCRecoveryController.InvalidClaim.selector);
        controller.schedule(request, newSigner, pop, hex"01");
    }

    function test_currentSignerCancelsAndConsumedRecoveryNonceCannotReplay() public {
        bytes memory newSigner = abi.encodePacked(vm.addr(replacementPk));
        OIDCRecoveryController.RecoveryRequest memory request = _request(newSigner);
        bytes32 digest = controller.hashRecovery(request);
        _setFreshClaim(digest);
        controller.schedule(request, newSigner, _sign(replacementPk, digest), hex"01");

        vm.expectRevert(OIDCRecoveryController.NoPendingRecovery.selector);
        vm.prank(address(0xBAD));
        controller.cancel();
        assertGt(controller.getPending(address(account)).executeAfter, 0);

        vm.prank(vm.addr(currentPk));
        account.execute(address(controller), 0, abi.encodeCall(OIDCRecoveryController.cancel, ()));
        assertEq(controller.getPending(address(account)).executeAfter, 0);

        vm.expectRevert(OIDCRecoveryController.InvalidRecoveryRequest.selector);
        controller.schedule(request, newSigner, _sign(replacementPk, digest), hex"01");
    }

    function test_signerRotationMakesPendingRecoveryStale() public {
        bytes memory recoveredSigner = abi.encodePacked(vm.addr(replacementPk));
        OIDCRecoveryController.RecoveryRequest memory request = _request(recoveredSigner);
        bytes32 digest = controller.hashRecovery(request);
        _setFreshClaim(digest);
        controller.schedule(request, recoveredSigner, _sign(replacementPk, digest), hex"01");

        vm.prank(vm.addr(currentPk));
        account.rotateSigner(abi.encodePacked(vm.addr(0xCAFE)));
        vm.prank(vm.addr(0xCAFE));
        account.rotateSigner(abi.encodePacked(vm.addr(currentPk)));
        vm.warp(block.timestamp + 2 days);

        vm.expectRevert(OIDCAccount.StaleSigner.selector);
        controller.finalize(address(account), _sign(replacementPk, digest));
    }

    function test_expiredPendingRecoveryDoesNotBlockReplacementRequest() public {
        bytes memory firstSigner = abi.encodePacked(vm.addr(replacementPk));
        OIDCRecoveryController.RecoveryRequest memory first = _request(firstSigner);
        bytes32 firstDigest = controller.hashRecovery(first);
        _setFreshClaim(firstDigest);
        controller.schedule(first, firstSigner, _sign(replacementPk, firstDigest), hex"01");

        vm.warp(block.timestamp + 9 days + 1);
        bytes memory secondSigner = abi.encodePacked(vm.addr(0xD00D));
        OIDCRecoveryController.RecoveryRequest memory second = _request(secondSigner);
        bytes32 secondDigest = controller.hashRecovery(second);
        _setFreshClaim(secondDigest);
        controller.schedule(second, secondSigner, _sign(0xD00D, secondDigest), hex"02");

        assertEq(controller.getPending(address(account)).digest, secondDigest);
    }

    function test_identityRecoveryCanBePermanentlyDisabled() public {
        vm.prank(vm.addr(currentPk));
        account.disableIdentityRecovery();

        bytes memory newSigner = abi.encodePacked(vm.addr(replacementPk));
        OIDCRecoveryController.RecoveryRequest memory request = _request(newSigner);
        bytes32 digest = controller.hashRecovery(request);
        _setFreshClaim(digest);

        vm.expectRevert(OIDCRecoveryController.InvalidRecoveryRequest.selector);
        controller.schedule(request, newSigner, _sign(replacementPk, digest), hex"01");

        bytes32 currentSignerHash = account.signerHash();
        uint256 currentSignerEpoch = account.signerEpoch();
        vm.expectRevert(OIDCAccount.IdentityRecoveryIsDisabled.selector);
        vm.prank(address(controller));
        account.replaceSignerFromIdentity(currentSignerHash, currentSignerEpoch, newSigner);
    }

    function test_hashRecoveryMatchesTypeScriptGoldenVector() public {
        vm.chainId(1);
        address goldenController = 0x3333333333333333333333333333333333333333;
        vm.etch(goldenController, address(controller).code);
        OIDCRecoveryController.RecoveryRequest memory request =
            OIDCRecoveryController.RecoveryRequest({
                account: 0x1111111111111111111111111111111111111111,
                expectedSignerHash: bytes32(
                    uint256(0x0505050505050505050505050505050505050505050505050505050505050505)
                ),
                expectedSignerEpoch: 6,
                newSignerHash: bytes32(
                    uint256(0x0606060606060606060606060606060606060606060606060606060606060606)
                ),
                nonce: 7,
                validAfter: 1_700_000_000,
                validUntil: 1_700_000_600
            });

        assertEq(
            OIDCRecoveryController(goldenController).hashRecovery(request),
            0x3a54924d67fac035e66338cb6b3f15715a09804057930d4069bc09ad8f9532f5
        );
    }

    function _request(bytes memory newSigner)
        internal
        view
        returns (OIDCRecoveryController.RecoveryRequest memory)
    {
        return OIDCRecoveryController.RecoveryRequest({
            account: address(account),
            expectedSignerHash: account.signerHash(),
            expectedSignerEpoch: account.signerEpoch(),
            newSignerHash: keccak256(newSigner),
            nonce: controller.recoveryNonces(address(account)),
            validAfter: uint64(block.timestamp),
            validUntil: uint64(block.timestamp + 10 minutes)
        });
    }

    function _setFreshClaim(bytes32 nonce) internal {
        claimVerifier.setClaim(
            IOIDCClaimVerifier.VerifiedOIDCClaim({
                providerPolicyId: policy,
                identityCommitment: identity,
                nonce: nonce,
                issuedAt: uint64(block.timestamp),
                expiresAt: uint64(block.timestamp + 10 minutes)
            })
        );
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
