// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { PackedUserOperation, IAccount } from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IndependentKeyAccount } from "../src/IndependentKeyAccount.sol";

contract MockEntryPoint {
    mapping(address => uint256) public nonce;

    function getNonce(address sender, uint192) external view returns (uint256) {
        return nonce[sender];
    }

    function validate(IAccount account, PackedUserOperation calldata op, bytes32 hash)
        external
        returns (uint256)
    {
        return account.validateUserOp(op, hash, 0);
    }

    function callAccount(address account, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory result) = account.call(data);
        if (!ok) assembly ("memory-safe") { revert(add(result, 32), mload(result)) }
        return result;
    }
}

contract MockTarget {
    uint256 public value;

    function setValue(uint256 newValue) external payable {
        value = newValue;
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

contract IndependentKeyAccountTest is Test {
    uint256 internal signerPk = 0x5151;
    MockEntryPoint internal entryPoint;
    IndependentKeyAccount internal account;
    MockTarget internal target;

    function setUp() public {
        entryPoint = new MockEntryPoint();
        bytes memory signer = abi.encodePacked(vm.addr(signerPk));
        account = new IndependentKeyAccount(
            address(entryPoint), address(0xDEAD), keccak256("opaque-identity"), signer
        );
        target = new MockTarget();
    }

    function _signature(bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        bytes[] memory signers = new bytes[](1);
        signers[0] = abi.encodePacked(vm.addr(signerPk));
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = abi.encodePacked(r, s, v);
        return abi.encode(signers, signatures);
    }

    function test_ordinaryOperationAndERC1271NeedOnlyIndependentSigner() public {
        vm.etch(address(0xDEAD), hex"60006000fd"); // unavailable/reverting recovery infrastructure
        bytes32 opHash = keccak256("user-operation");
        PackedUserOperation memory op;
        op.sender = address(account);
        op.signature = _signature(opHash);
        assertEq(entryPoint.validate(account, op, opHash), 0);
        assertEq(account.isValidSignature(opHash, op.signature), IERC1271.isValidSignature.selector);

        entryPoint.callAccount(
            address(account),
            abi.encodeCall(
                IndependentKeyAccount.execute,
                (address(target), 0, abi.encodeCall(MockTarget.setValue, (42)))
            )
        );
        assertEq(target.value(), 42);
    }

    function test_erc1271ContractCanBeTheIndependentERC7913Signer() public {
        uint256 ownerPk = 0x7777;
        OwnerERC1271Wallet wallet = new OwnerERC1271Wallet(vm.addr(ownerPk));
        IndependentKeyAccount contractSignerAccount = new IndependentKeyAccount(
            address(entryPoint),
            address(0xDEAD),
            keccak256("other-identity"),
            abi.encodePacked(address(wallet))
        );
        bytes32 digest = keccak256("contract-signer-op");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes[] memory signers = new bytes[](1);
        signers[0] = abi.encodePacked(address(wallet));
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = abi.encodePacked(r, s, v);
        PackedUserOperation memory op;
        op.sender = address(contractSignerAccount);
        op.signature = abi.encode(signers, signatures);
        assertEq(entryPoint.validate(contractSignerAccount, op, digest), 0);
        assertEq(
            contractSignerAccount.isValidSignature(digest, op.signature),
            IERC1271.isValidSignature.selector
        );
    }

    function test_onlyEntryPointOrSelfManagesSignersAndDangerousSignersAreRejected() public {
        vm.expectRevert();
        account.addSigner(abi.encodePacked(address(0x1234)));
        vm.expectRevert();
        new IndependentKeyAccount(
            address(entryPoint), address(0xDEAD), keccak256("x"), abi.encodePacked(address(4))
        );

        bytes memory onlySigner = abi.encodePacked(vm.addr(signerPk));
        vm.expectRevert();
        entryPoint.callAccount(
            address(account), abi.encodeCall(IndependentKeyAccount.removeSigner, (onlySigner))
        );
    }

    function test_executeCanTransferEtherToAnEoa() public {
        address payable recipient = payable(address(0xBEEF));
        vm.deal(address(account), 1 ether);
        entryPoint.callAccount(
            address(account),
            abi.encodeCall(IndependentKeyAccount.execute, (recipient, 0.25 ether, bytes("")))
        );
        assertEq(recipient.balance, 0.25 ether);
    }
}
