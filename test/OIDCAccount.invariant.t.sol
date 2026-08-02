// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { OIDCAccount } from "../src/OIDCAccount.sol";

contract OIDCAccountSignerHandler is Test {
    OIDCAccount internal immutable account;
    uint256 public rotations;

    constructor(OIDCAccount account_) {
        account = account_;
    }

    function rotate(uint160 candidate) external {
        bytes memory current = account.signer();
        address currentAddress = address(bytes20(current));
        address next = address(uint160(bound(candidate, 0x100, type(uint160).max)));
        if (next == currentAddress || next == address(account)) return;
        vm.prank(currentAddress);
        account.rotateSigner(abi.encodePacked(next));
        rotations++;
    }
}

contract OIDCAccountInvariantTest is Test {
    bytes32 internal constant POLICY = keccak256("google-policy");
    bytes32 internal constant IDENTITY = keccak256("google-user");
    address internal constant CONTROLLER = address(0xC011);

    OIDCAccount internal account;
    OIDCAccountSignerHandler internal handler;

    function setUp() public {
        account = new OIDCAccount(CONTROLLER, POLICY, IDENTITY, abi.encodePacked(address(0xA11CE)));
        handler = new OIDCAccountSignerHandler(account);
        targetContract(address(handler));
    }

    function invariant_identityBindingAndControllerNeverChange() public view {
        assertEq(account.providerPolicyId(), POLICY);
        assertEq(account.identityCommitment(), IDENTITY);
        assertEq(account.identityController(), CONTROLLER);
    }

    function invariant_oneValidIndependentSignerAlwaysRemains() public view {
        bytes memory current = account.signer();
        assertEq(current.length, 20);
        assertGt(uint160(address(bytes20(current))), 0xff);
        assertEq(account.signerHash(), keccak256(current));
    }

    function invariant_signerEpochCountsEverySuccessfulRotation() public view {
        assertEq(account.signerEpoch(), handler.rotations());
    }
}
