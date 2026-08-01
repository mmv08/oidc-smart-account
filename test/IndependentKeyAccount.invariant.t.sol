// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { IndependentKeyAccount } from "../src/IndependentKeyAccount.sol";

contract AccountSignerHandler is Test {
    IndependentKeyAccount internal immutable account;
    address internal immutable owner;
    bytes32 internal immutable ownerSignerHash;

    constructor(IndependentKeyAccount account_, address owner_) {
        account = account_;
        owner = owner_;
        ownerSignerHash = keccak256(abi.encodePacked(owner_));
    }

    function addSigner(uint160 rawSigner) external {
        if (rawSigner <= 0xff || address(rawSigner) == address(account)) return;
        bytes memory signer = abi.encodePacked(address(rawSigner));
        vm.prank(owner);
        try account.addSigner(signer) { } catch { }
    }

    function removeSigner(uint256 seed) external {
        bytes[] memory signers = account.getSigners(0, type(uint64).max);
        if (signers.length <= 1) return;
        bytes memory signer = signers[seed % signers.length];
        if (keccak256(signer) == ownerSignerHash) return;
        vm.prank(owner);
        try account.removeSigner(signer) { } catch { }
    }
}

contract IndependentKeyAccountInvariantTest is Test {
    IndependentKeyAccount internal account;

    function setUp() public {
        address owner = address(0xBEEF);
        account = new IndependentKeyAccount(
            address(0xDEAD), keccak256("opaque-invariant-identity"), abi.encodePacked(owner)
        );
        targetContract(address(new AccountSignerHandler(account, owner)));
    }

    function invariant_signerThresholdIsAlwaysOneAndReachable() public view {
        assertEq(account.threshold(), 1);
        assertGe(account.getSignerCount(), 1);
    }

    function invariant_signerCountNeverExceedsTheAccountCap() public view {
        assertLe(account.getSignerCount(), account.MAX_SIGNERS());
    }
}
