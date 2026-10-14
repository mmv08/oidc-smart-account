// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import { OIDCAccount } from "../src/OIDCAccount.sol";
import { MockIssuer } from "./helpers/MockIssuer.sol";
import { TestBase } from "./helpers/TestBase.sol";

contract Target {
    error Failed();

    uint256 public value;

    function set(uint256 newValue) external payable {
        value = newValue;
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
        vm.deal(address(account), 1 ether);
        vm.expectRevert(OIDCAccount.NotSigner.selector);
        vm.prank(signer);
        account.execute(address(target), 0, abi.encodeCall(Target.set, (1)));

        string memory jwt = _token("alice", signer);
        vm.prank(makeAddr("relayer"));
        account.setSigner(jwt, signer);
        assertEq(account.signer(), signer);
        assertEq(account.nonce(), 1);

        vm.prank(signer);
        account.execute(address(target), 0.4 ether, abi.encodeCall(Target.set, (41)));
        assertEq(target.value(), 41);
        assertEq(address(target).balance, 0.4 ether);
    }

    function test_rejectsJwtOfOtherUser() public {
        string memory jwt = _token("mallory", signer);
        vm.expectRevert(OIDCAccount.InvalidJWT.selector);
        account.setSigner(jwt, signer);
    }

    /// @dev The nonce binds the JWT to one signer, one account, and one chain.
    function test_rejectsJwtForOtherSignerAccountOrChain() public {
        string memory jwt = _token("alice", signer);
        vm.expectRevert(OIDCAccount.InvalidJWT.selector);
        account.setSigner(jwt, makeAddr("attacker"));

        OIDCAccount other = new OIDCAccount(verifier, keccak256("alice"));
        vm.expectRevert(OIDCAccount.InvalidJWT.selector);
        other.setSigner(jwt, signer);

        vm.chainId(block.chainid + 1);
        vm.expectRevert(OIDCAccount.InvalidJWT.selector);
        account.setSigner(jwt, signer);
    }

    function test_rejectsJwtReplay() public {
        string memory jwt = _token("alice", signer);
        account.setSigner(jwt, signer);

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
