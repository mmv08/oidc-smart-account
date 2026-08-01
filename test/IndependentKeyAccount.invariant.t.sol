// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { IndependentKeyAccount } from "../src/IndependentKeyAccount.sol";

contract InvariantEntryPoint {
    function getNonce(address, uint192) external pure returns (uint256) {
        return 0;
    }

    function callAccount(address account, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory result) = account.call(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
        return result;
    }
}

contract AccountSignerHandler {
    InvariantEntryPoint internal immutable entryPoint;
    IndependentKeyAccount internal immutable account;

    constructor(InvariantEntryPoint entryPoint_, IndependentKeyAccount account_) {
        entryPoint = entryPoint_;
        account = account_;
    }

    function addSigner(uint160 rawSigner) external {
        if (rawSigner <= 0xff) return;
        bytes memory signer = abi.encodePacked(address(rawSigner));
        try entryPoint.callAccount(
            address(account), abi.encodeCall(IndependentKeyAccount.addSigner, (signer))
        ) { }
            catch { }
    }

    function removeSigner(uint256 seed) external {
        bytes[] memory signers = account.getSigners(0, type(uint64).max);
        if (signers.length <= 1) return;
        bytes memory signer = signers[seed % signers.length];
        try entryPoint.callAccount(
            address(account), abi.encodeCall(IndependentKeyAccount.removeSigner, (signer))
        ) { }
            catch { }
    }
}

contract IndependentKeyAccountInvariantTest is Test {
    IndependentKeyAccount internal account;

    function setUp() public {
        InvariantEntryPoint entryPoint = new InvariantEntryPoint();
        account = new IndependentKeyAccount(
            address(entryPoint),
            address(0xDEAD),
            keccak256("opaque-invariant-identity"),
            abi.encodePacked(address(0xBEEF))
        );
        targetContract(address(new AccountSignerHandler(entryPoint, account)));
    }

    function invariant_signerThresholdIsAlwaysOneAndReachable() public view {
        assertEq(account.threshold(), 1);
        assertGe(account.getSignerCount(), 1);
    }

    function invariant_signerCountNeverExceedsTheAccountCap() public view {
        assertLe(account.getSignerCount(), account.MAX_SIGNERS());
    }
}
