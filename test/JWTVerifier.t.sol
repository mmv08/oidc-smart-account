// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import { Bytes } from "@openzeppelin/contracts/utils/Bytes.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { JWKSRegistry } from "../src/JWKSRegistry.sol";
import { JWTParser } from "../src/JWTParser.sol";
import { JWTVerifier } from "../src/JWTVerifier.sol";
import { MockIssuer } from "./helpers/MockIssuer.sol";
import { TestBase } from "./helpers/TestBase.sol";

contract JWTVerifierTest is TestBase {
    using Bytes for bytes;

    /// @dev The verifier ignores `iat` and unknown claims, also escaped strings and nested values.
    function test_returnsSubjectAndNonceHashes() public view {
        string memory payload = string.concat(
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"alice","nonce":"n","nbf":',
            Strings.toString(block.timestamp),
            ',"iat":1699999000,"exp":1700000600,',
            '"name":"A \\"quoted\\" name","extra":{"nonce":"nested","list":[1,true,null]}}'
        );

        (bytes32 subjectHash, bytes32 nonceHash) =
            verifier.verify(MockIssuer.sign(MockIssuer.HEADER, payload));
        assertEq(subjectHash, keccak256("alice"));
        assertEq(nonceHash, keccak256("n"));
    }

    function test_rejectsWrongIssuerOrAudience() public {
        _expectRevert(
            '{"iss":"https://other.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600}',
            JWTVerifier.InvalidClaims.selector
        );
        _expectRevert(
            '{"iss":"https://issuer.example","aud":"other-client","sub":"a","nonce":"n","exp":1700000600}',
            JWTVerifier.InvalidClaims.selector
        );
    }

    function test_rejectsExpiredOrNotYetValidToken() public {
        uint256 exp = block.timestamp + 600;
        string memory jwt = MockIssuer.token("alice", "n", exp);
        vm.warp(exp);
        vm.expectRevert(JWTVerifier.InvalidClaims.selector);
        verifier.verify(jwt);

        _expectRevert(
            string.concat(
                '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","nbf":',
                Strings.toString(exp + 1),
                ',"exp":',
                Strings.toString(exp + 600),
                "}"
            ),
            JWTVerifier.InvalidClaims.selector
        );
    }

    function test_rejectsChangedPayload() public {
        bytes memory token = bytes(MockIssuer.token("alice", "n", block.timestamp + 600));
        bytes memory other = bytes(MockIssuer.token("mallory", "n", block.timestamp + 600));
        // Use the header and the payload of `other` with the signature of `token`.
        bytes memory forged = bytes.concat(
            other.slice(0, other.lastIndexOf(".")), token.slice(token.lastIndexOf("."))
        );

        vm.expectRevert(JWTVerifier.InvalidSignature.selector);
        verifier.verify(string(forged));
    }

    function test_rejectsKeyThatIsNotInTheRegistry() public {
        string memory payload = MockIssuer.claims("alice", "n", block.timestamp + 600);

        _expectRevert(
            '{"alg":"RS256","kid":"other-key"}', payload, JWKSRegistry.UnknownKey.selector
        );
    }

    function test_rejectsInvalidHeader() public {
        string memory payload = MockIssuer.claims("alice", "n", block.timestamp + 600);

        _expectRevert(
            '{"alg":"HS256","kid":"test-key-1"}', payload, JWTVerifier.InvalidJWT.selector
        );
        _expectRevert('{"alg":"none","kid":"test-key-1"}', payload, JWTVerifier.InvalidJWT.selector);
        _expectRevert(
            '{"alg":"RS256","kid":"test-key-1","crit":["exp"]}',
            payload,
            JWTParser.InvalidJSON.selector
        );
        _expectRevert('{"alg":"RS256"}', payload, JWTParser.InvalidJSON.selector);
        _expectRevert('{"alg":"RS256","kid":"test-key-1",', payload, JWTParser.InvalidJSON.selector);
    }

    function test_rejectsInvalidOrAmbiguousClaims() public {
        string[11] memory payloads = [
            // Duplicate nonce.
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","nonce":"m","exp":1700000600}',
            // Escaped member name ("nonce" is "nonce").
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","\\u006eonce":"m","exp":1700000600}',
            // Escaped value.
            '{"iss":"https:\\/\\/issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600}',
            // Audience array.
            '{"iss":"https://issuer.example","aud":["demo-client"],"sub":"a","nonce":"n","exp":1700000600}',
            // Missing exp.
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n"}',
            // Expiry as a string.
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":"1700000600"}',
            // Comma before the closing brace.
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600,}',
            // Comma and no closing brace.
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600,',
            // No closing brace.
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600',
            // Data after the object.
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600}x',
            // No colon.
            '{"iss" "https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600}'
        ];
        for (uint256 i = 0; i < payloads.length; ++i) {
            _expectRevert(payloads[i], JWTParser.InvalidJSON.selector);
        }
    }

    function test_rejectsTokenWithoutThreeParts() public {
        vm.expectRevert(JWTVerifier.InvalidJWT.selector);
        verifier.verify("no-dots");
        vm.expectRevert(JWTVerifier.InvalidJWT.selector);
        verifier.verify("one.dot");
    }

    function _expectRevert(string memory payload, bytes4 selector) internal {
        _expectRevert(MockIssuer.HEADER, payload, selector);
    }

    /// @dev Signs the JWT before `expectRevert`, because the signature uses the modexp precompile.
    function _expectRevert(string memory header, string memory payload, bytes4 selector) internal {
        string memory jwt = MockIssuer.sign(header, payload);
        vm.expectRevert(selector);
        verifier.verify(jwt);
    }
}
