// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { OIDCAccount } from "../src/OIDCAccount.sol";
import { TestERC7913Verifier } from "./helpers/TestVerifiers.sol";

contract AccountTarget {
    error DeliberateFailure();

    uint256 public value;

    function setValue(uint256 next) external payable returns (uint256) {
        value = next;
        return next + 1;
    }

    function fail() external pure {
        revert DeliberateFailure();
    }
}

contract OIDCAccountTest is Test {
    uint256 internal signerPk = 0xA11CE;
    address internal signer;
    OIDCAccount internal account;
    AccountTarget internal target;

    function setUp() public {
        signer = vm.addr(signerPk);
        account = new OIDCAccount(
            address(0xC011),
            keccak256("google-policy"),
            keccak256("google-user-commitment"),
            abi.encodePacked(signer)
        );
        target = new AccountTarget();
    }

    function test_accountStoresExactIdentityBindingAndIndependentSigner() public view {
        assertEq(account.identityController(), address(0xC011));
        assertEq(account.providerPolicyId(), keccak256("google-policy"));
        assertEq(account.identityCommitment(), keccak256("google-user-commitment"));
        assertEq(account.signer(), abi.encodePacked(signer));
        assertEq(account.signerHash(), keccak256(abi.encodePacked(signer)));
    }

    function test_addressSignerExecutesDirectly() public {
        vm.prank(signer);
        bytes memory result =
            account.execute(address(target), 0, abi.encodeCall(AccountTarget.setValue, (41)));

        assertEq(target.value(), 41);
        assertEq(abi.decode(result, (uint256)), 42);
    }

    function test_anyoneRelaysExactSignedExecution() public {
        bytes memory data = abi.encodeCall(AccountTarget.setValue, (77));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes32 digest = account.hashExecution(address(target), 0, data, 0, deadline);
        bytes memory signature = _sign(signerPk, digest);

        vm.prank(address(0xBEEF));
        account.executeSigned(address(target), 0, data, 0, deadline, signature);

        assertEq(target.value(), 77);
        assertEq(account.executionNonce(), 1);

        vm.expectRevert(abi.encodeWithSelector(OIDCAccount.InvalidExecutionNonce.selector, 0, 1));
        account.executeSigned(address(target), 0, data, 0, deadline, signature);
    }

    function test_signedSelfCallRotatesSignerAndOldSignerStopsWorking() public {
        address replacement = vm.addr(0xB0B);
        bytes memory rotate =
            abi.encodeCall(OIDCAccount.rotateSigner, (abi.encodePacked(replacement)));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes32 digest = account.hashExecution(address(account), 0, rotate, 0, deadline);

        account.executeSigned(address(account), 0, rotate, 0, deadline, _sign(signerPk, digest));

        assertEq(account.signer(), abi.encodePacked(replacement));
        vm.expectRevert(abi.encodeWithSelector(OIDCAccount.UnauthorizedSigner.selector, signer));
        vm.prank(signer);
        account.execute(address(target), 0, abi.encodeCall(AccountTarget.setValue, (1)));
    }

    function test_identityControllerCanOnlyReplaceExpectedSigner() public {
        bytes memory replacement = abi.encodePacked(vm.addr(0xB0B));
        bytes32 expected = account.signerHash();

        vm.expectRevert(OIDCAccount.StaleSigner.selector);
        vm.prank(address(0xC011));
        account.replaceSignerFromIdentity(keccak256("wrong"), 0, replacement);

        vm.prank(address(0xC011));
        account.replaceSignerFromIdentity(expected, 0, replacement);
        assertEq(account.signer(), replacement);
    }

    function test_rotatingAwayAndBackDoesNotReviveOldSignedExecution() public {
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory callData = abi.encodeCall(AccountTarget.setValue, (77));
        bytes32 oldDigest = account.hashExecution(
            address(target), 0, callData, account.executionNonce(), deadline
        );
        bytes memory oldSignature = _sign(signerPk, oldDigest);

        address replacement = vm.addr(0xB0B);
        vm.prank(signer);
        account.rotateSigner(abi.encodePacked(replacement));
        vm.prank(replacement);
        account.rotateSigner(abi.encodePacked(signer));

        assertEq(account.signerEpoch(), 2);
        vm.expectRevert(OIDCAccount.InvalidSignature.selector);
        account.executeSigned(
            address(target), 0, callData, account.executionNonce(), deadline, oldSignature
        );
    }

    function test_addresslessERC7913SignerAuthorizesRelayedExecution() public {
        uint256 keyPk = 0x9191;
        TestERC7913Verifier verifier = new TestERC7913Verifier();
        bytes memory addresslessSigner = abi.encodePacked(address(verifier), vm.addr(keyPk));
        OIDCAccount addresslessAccount = new OIDCAccount(
            address(0xC011),
            keccak256("google-policy"),
            keccak256("addressless-user"),
            addresslessSigner
        );
        bytes memory data = abi.encodeCall(AccountTarget.setValue, (88));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes32 digest = addresslessAccount.hashExecution(address(target), 0, data, 0, deadline);

        vm.prank(address(0xBEEF));
        addresslessAccount.executeSigned(
            address(target), 0, data, 0, deadline, _sign(keyPk, digest)
        );

        assertEq(target.value(), 88);
    }

    function test_signedExecutionRejectsMutationExpiryCrossAccountAndCrossChain() public {
        bytes memory data = abi.encodeCall(AccountTarget.setValue, (11));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes32 digest = account.hashExecution(address(target), 0, data, 0, deadline);
        bytes memory signature = _sign(signerPk, digest);

        vm.expectRevert(OIDCAccount.InvalidExecutionSignature.selector);
        account.executeSigned(address(target), 1, data, 0, deadline, signature);

        OIDCAccount other = new OIDCAccount(
            address(0xC011),
            keccak256("google-policy"),
            keccak256("other-user"),
            abi.encodePacked(signer)
        );
        vm.expectRevert(OIDCAccount.InvalidExecutionSignature.selector);
        other.executeSigned(address(target), 0, data, 0, deadline, signature);

        vm.chainId(block.chainid + 1);
        vm.expectRevert(OIDCAccount.InvalidExecutionSignature.selector);
        account.executeSigned(address(target), 0, data, 0, deadline, signature);

        vm.warp(deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(OIDCAccount.ExecutionExpired.selector, deadline));
        account.executeSigned(address(target), 0, data, 0, deadline, signature);
    }

    function test_failedCallRollsBackNonceAndEtherCanBeReceivedAndTransferred() public {
        vm.deal(address(account), 2 ether);
        bytes memory failData = abi.encodeCall(AccountTarget.fail, ());
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes32 digest = account.hashExecution(address(target), 0, failData, 0, deadline);

        vm.expectRevert(AccountTarget.DeliberateFailure.selector);
        account.executeSigned(address(target), 0, failData, 0, deadline, _sign(signerPk, digest));
        assertEq(account.executionNonce(), 0);

        address recipient = address(0xCAFE);
        vm.prank(signer);
        account.execute(recipient, 1 ether, "");
        assertEq(recipient.balance, 1 ether);
        assertEq(address(account).balance, 1 ether);
    }

    function test_erc1271UsesCurrentSigner() public view {
        bytes32 digest = keccak256("protocol-message");
        bytes memory signature = _sign(signerPk, digest);
        assertEq(account.isValidSignature(digest, signature), IERC1271.isValidSignature.selector);
        assertEq(account.isValidSignature(keccak256("other"), signature), bytes4(0xffffffff));
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
