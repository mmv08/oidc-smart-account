// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { IERC7913SignatureVerifier } from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IndependentKeyAccount } from "../src/IndependentKeyAccount.sol";

contract MockTarget {
    uint256 public value;
    error DeliberateFailure();

    function setValue(uint256 newValue) external payable returns (uint256) {
        value = newValue;
        return newValue + 1;
    }

    function fail() external pure {
        revert DeliberateFailure();
    }
}

contract OwnerERC1271Wallet is IERC1271 {
    address internal immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        return ECDSA.recover(hash, signature) == owner
            ? IERC1271.isValidSignature.selector
            : bytes4(0xffffffff);
    }
}

contract AddresslessTestVerifier is IERC7913SignatureVerifier {
    function verify(bytes calldata key, bytes32 hash, bytes calldata signature)
        external
        pure
        returns (bytes4)
    {
        if (key.length != 20) return bytes4(0xffffffff);
        return ECDSA.recover(hash, signature) == address(bytes20(key))
            ? this.verify.selector
            : bytes4(0xffffffff);
    }
}

contract IndependentKeyAccountTest is Test {
    uint256 internal signerPk = 0x5151;
    address internal signerAddress;
    bytes internal signer;
    IndependentKeyAccount internal account;
    MockTarget internal target;

    function setUp() public {
        signerAddress = vm.addr(signerPk);
        signer = abi.encodePacked(signerAddress);
        account = new IndependentKeyAccount(address(0xDEAD), keccak256("opaque-identity"), signer);
        target = new MockTarget();
    }

    function _rawSignature(uint256 pk, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _multiSignature(bytes memory signer_, bytes memory innerSignature)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory signers = new bytes[](1);
        signers[0] = signer_;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = innerSignature;
        return abi.encode(signers, signatures);
    }

    function _signedExecution(
        IndependentKeyAccount account_,
        uint256 pk,
        bytes memory signer_,
        address target_,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint64 deadline
    ) internal returns (bytes memory) {
        bytes32 digest = account_.hashExecution(target_, value, data, nonce, deadline);
        return _multiSignature(signer_, _rawSignature(pk, digest));
    }

    function test_directSignerExecutesWithoutRecoveryInfrastructure() public {
        vm.etch(address(0xDEAD), hex"60006000fd");
        vm.prank(signerAddress);
        bytes memory result =
            account.execute(address(target), 0, abi.encodeCall(MockTarget.setValue, (42)));
        assertEq(abi.decode(result, (uint256)), 43);
        assertEq(target.value(), 42);

        vm.prank(address(0xBEEF));
        vm.expectRevert(
            abi.encodeWithSelector(
                IndependentKeyAccount.UnauthorizedSigner.selector, address(0xBEEF)
            )
        );
        account.execute(address(target), 0, abi.encodeCall(MockTarget.setValue, (99)));
    }

    function test_relayerExecutesExactSignedCallAndReplayMutationAndExpiryFail() public {
        bytes memory data = abi.encodeCall(MockTarget.setValue, (7));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory signature =
            _signedExecution(account, signerPk, signer, address(target), 0, data, 0, deadline);

        vm.prank(address(0xF00D));
        account.executeSigned(address(target), 0, data, 0, deadline, signature);
        assertEq(target.value(), 7);
        assertEq(account.executionNonce(), 1);

        vm.expectRevert(
            abi.encodeWithSelector(IndependentKeyAccount.InvalidExecutionNonce.selector, 0, 1)
        );
        account.executeSigned(address(target), 0, data, 0, deadline, signature);

        bytes memory mutationSignature =
            _signedExecution(account, signerPk, signer, address(target), 0, data, 1, deadline);
        vm.expectRevert(IndependentKeyAccount.InvalidExecutionSignature.selector);
        account.executeSigned(address(target), 1, data, 1, deadline, mutationSignature);

        bytes memory expiringSignature =
            _signedExecution(account, signerPk, signer, address(target), 0, data, 1, deadline);
        vm.warp(deadline + 1);
        vm.expectRevert(
            abi.encodeWithSelector(IndependentKeyAccount.ExecutionExpired.selector, deadline)
        );
        account.executeSigned(address(target), 0, data, 1, deadline, expiringSignature);
    }

    function test_signedSelfCallManagesSigners() public {
        bytes memory newSigner = abi.encodePacked(address(0x1234));
        bytes memory managementCall = abi.encodeCall(IndependentKeyAccount.addSigner, (newSigner));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory signature = _signedExecution(
            account, signerPk, signer, address(account), 0, managementCall, 0, deadline
        );

        vm.prank(address(0xF00D));
        account.executeSigned(address(account), 0, managementCall, 0, deadline, signature);
        assertTrue(account.isSigner(newSigner));

        vm.expectRevert(
            abi.encodeWithSelector(
                IndependentKeyAccount.UnauthorizedSigner.selector, address(0xBEEF)
            )
        );
        vm.prank(address(0xBEEF));
        account.removeSigner(newSigner);

        vm.prank(signerAddress);
        account.removeSigner(newSigner);
        vm.expectRevert();
        vm.prank(signerAddress);
        account.removeSigner(signer);
    }

    function test_erc1271ContractSignerCanAuthorizeRelayedExecution() public {
        uint256 ownerPk = 0x7777;
        OwnerERC1271Wallet wallet = new OwnerERC1271Wallet(vm.addr(ownerPk));
        bytes memory contractSigner = abi.encodePacked(address(wallet));
        IndependentKeyAccount contractSignerAccount = new IndependentKeyAccount(
            address(0xDEAD), keccak256("other-identity"), contractSigner
        );
        bytes memory data = abi.encodeCall(MockTarget.setValue, (88));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory signature = _signedExecution(
            contractSignerAccount, ownerPk, contractSigner, address(target), 0, data, 0, deadline
        );

        contractSignerAccount.executeSigned(address(target), 0, data, 0, deadline, signature);
        assertEq(target.value(), 88);
        bytes32 digest = keccak256("external-protocol-message");
        assertEq(
            contractSignerAccount.isValidSignature(
                digest, _multiSignature(contractSigner, _rawSignature(ownerPk, digest))
            ),
            IERC1271.isValidSignature.selector
        );
    }

    function test_addresslessERC7913SignerAuthorizesRelayedExecution() public {
        uint256 keyPk = 0x9191;
        AddresslessTestVerifier addresslessVerifier = new AddresslessTestVerifier();
        bytes memory addresslessSigner =
            abi.encodePacked(address(addresslessVerifier), vm.addr(keyPk));
        IndependentKeyAccount addresslessAccount = new IndependentKeyAccount(
            address(0xDEAD), keccak256("addressless-identity"), addresslessSigner
        );
        bytes memory data = abi.encodeCall(MockTarget.setValue, (91));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory signature = _signedExecution(
            addresslessAccount, keyPk, addresslessSigner, address(target), 0, data, 0, deadline
        );

        vm.prank(address(0xF00D));
        addresslessAccount.executeSigned(address(target), 0, data, 0, deadline, signature);
        assertEq(target.value(), 91);
    }

    function test_signedExecutionCannotReplayAcrossAccounts() public {
        IndependentKeyAccount otherAccount =
            new IndependentKeyAccount(address(0xDEAD), keccak256("another-identity"), signer);
        bytes memory data = abi.encodeCall(MockTarget.setValue, (123));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory signature =
            _signedExecution(account, signerPk, signer, address(target), 0, data, 0, deadline);

        vm.expectRevert(IndependentKeyAccount.InvalidExecutionSignature.selector);
        otherAccount.executeSigned(address(target), 0, data, 0, deadline, signature);
    }

    function test_signedExecutionCannotReplayAcrossChains() public {
        bytes memory data = abi.encodeCall(MockTarget.setValue, (124));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory signature =
            _signedExecution(account, signerPk, signer, address(target), 0, data, 0, deadline);

        vm.chainId(block.chainid + 1);
        vm.expectRevert(IndependentKeyAccount.InvalidExecutionSignature.selector);
        account.executeSigned(address(target), 0, data, 0, deadline, signature);
    }

    function test_failedSignedCallRollsBackExecutionNonce() public {
        bytes memory data = abi.encodeCall(MockTarget.fail, ());
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes memory signature =
            _signedExecution(account, signerPk, signer, address(target), 0, data, 0, deadline);

        vm.expectRevert(MockTarget.DeliberateFailure.selector);
        account.executeSigned(address(target), 0, data, 0, deadline, signature);
        assertEq(account.executionNonce(), 0);
    }

    function test_directExecutionTransfersEtherAndRejectsZeroTargetAndDangerousSigner() public {
        address payable recipient = payable(address(0xBEEF));
        vm.deal(address(account), 1 ether);
        vm.prank(signerAddress);
        account.execute(recipient, 0.25 ether, bytes(""));
        assertEq(recipient.balance, 0.25 ether);

        vm.prank(signerAddress);
        vm.expectRevert(IndependentKeyAccount.InvalidTarget.selector);
        account.execute(address(0), 0, bytes(""));

        vm.expectRevert();
        new IndependentKeyAccount(address(0xDEAD), keccak256("x"), abi.encodePacked(address(4)));
    }

    function test_accountCanReceiveEtherWithoutCallingExecution() public {
        address sender = address(0xABCD);
        vm.deal(sender, 1 ether);
        vm.prank(sender);
        (bool success,) = address(account).call{ value: 0.5 ether }("");
        assertTrue(success);
        assertEq(address(account).balance, 0.5 ether);
    }
}
