// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { OIDCAccount } from "../src/OIDCAccount.sol";
import { MockIssuer } from "./helpers/MockIssuer.sol";
import { TestBase } from "./helpers/TestBase.sol";

contract Target {
    error Failed();

    uint256 public value;

    function set(uint256 newValue) external payable returns (uint256) {
        value = newValue;
        return newValue + 1;
    }

    function fail() external pure {
        revert Failed();
    }
}

contract OIDCAccountTest is TestBase {
    OIDCAccount internal account;
    Target internal target;
    address internal signer = makeAddr("signer");

    function setUp() public override {
        super.setUp();
        account = new OIDCAccount(verifier, keccak256("alice"));
        target = new Target();
    }

    function test_jwtSetsSignerAndSignerExecutes() public {
        string memory jwt = _token("alice", signer);
        vm.prank(makeAddr("relayer"));
        account.setSigner(jwt, signer);
        assertEq(account.signer(), signer);
        assertEq(account.nonce(), 1);

        vm.deal(address(account), 1 ether);
        vm.prank(signer);
        bytes memory result =
            account.execute(address(target), 0.4 ether, abi.encodeCall(Target.set, (41)));

        assertEq(abi.decode(result, (uint256)), 42);
        assertEq(target.value(), 41);
        assertEq(address(target).balance, 0.4 ether);
    }

    function test_rejectsJwtOfOtherUser() public {
        string memory jwt = _token("mallory", signer);
        vm.expectRevert(OIDCAccount.InvalidJWT.selector);
        account.setSigner(jwt, signer);
    }

    function test_rejectsJwtWithOtherSigner() public {
        string memory jwt = _token("alice", signer);
        vm.expectRevert(OIDCAccount.InvalidJWT.selector);
        account.setSigner(jwt, makeAddr("attacker"));
    }

    function test_rejectsJwtReplay() public {
        string memory jwt = _token("alice", signer);
        account.setSigner(jwt, signer);

        vm.expectRevert(OIDCAccount.InvalidJWT.selector);
        account.setSigner(jwt, signer);
    }

    function test_rejectsJwtForOtherAccountOrChain() public {
        OIDCAccount other = new OIDCAccount(verifier, keccak256("alice"));
        string memory jwt = _token("alice", signer);
        vm.expectRevert(OIDCAccount.InvalidJWT.selector);
        other.setSigner(jwt, signer);

        vm.chainId(block.chainid + 1);
        vm.expectRevert(OIDCAccount.InvalidJWT.selector);
        account.setSigner(jwt, signer);
    }

    function test_newJwtReplacesSigner() public {
        account.setSigner(_token("alice", signer), signer);
        address newSigner = makeAddr("new-signer");
        account.setSigner(_token("alice", newSigner), newSigner);

        vm.expectRevert(OIDCAccount.NotSigner.selector);
        vm.prank(signer);
        account.execute(address(target), 0, abi.encodeCall(Target.set, (1)));

        vm.prank(newSigner);
        account.execute(address(target), 0, abi.encodeCall(Target.set, (2)));
        assertEq(target.value(), 2);
    }

    function test_onlySignerExecutes() public {
        vm.expectRevert(OIDCAccount.NotSigner.selector);
        account.execute(address(target), 0, abi.encodeCall(Target.set, (1)));
    }

    function test_executeRevertsWithTargetError() public {
        account.setSigner(_token("alice", signer), signer);

        vm.expectRevert(Target.Failed.selector);
        vm.prank(signer);
        account.execute(address(target), 0, abi.encodeCall(Target.fail, ()));
    }

    /// @dev Returns a JWT from the mock issuer that approves `newSigner` on `account`.
    function _token(string memory sub, address newSigner) internal view returns (string memory) {
        return MockIssuer.token(sub, account.jwtNonce(newSigner), block.timestamp + 600);
    }
}
