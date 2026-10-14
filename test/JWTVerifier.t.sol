// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Bytes } from "@openzeppelin/contracts/utils/Bytes.sol";
import { JWKSRegistry } from "../src/JWKSRegistry.sol";
import { JWTParser } from "../src/JWTParser.sol";
import { JWTVerifier } from "../src/JWTVerifier.sol";
import { MockIssuer } from "./helpers/MockIssuer.sol";
import { TestBase } from "./helpers/TestBase.sol";

contract JWTVerifierTest is TestBase {
    using Bytes for bytes;

    string internal constant NONCE =
        "0x1111111111111111111111111111111111111111111111111111111111111111";

    function test_returnsSubjectAndNonceHashes() public view {
        string memory jwt = MockIssuer.token("alice", NONCE, block.timestamp + 600);

        (bytes32 subjectHash, bytes32 nonceHash) = verifier.verify(jwt);
        assertEq(subjectHash, keccak256("alice"));
        assertEq(nonceHash, keccak256(bytes(NONCE)));
    }

    function test_acceptsMatchingAzpPastNbfAndUnknownClaims() public view {
        string memory payload = string.concat(
            '{"iss":"https://issuer.example","azp":"demo-client","aud":"demo-client",',
            '"sub":"alice","nonce":"n","nbf":1699999000,"iat":1699999000,"exp":1700000600,',
            '"name":"A \\"quoted\\" name","extra":{"nonce":"nested","list":[1,true,null]}}'
        );

        (, bytes32 nonceHash) = verifier.verify(MockIssuer.sign(MockIssuer.HEADER, payload));
        assertEq(nonceHash, keccak256("n"));
    }

    function test_rejectsWrongIssuerAudienceOrAuthorizedParty() public {
        _expectRevert(
            '{"iss":"https://other.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600}',
            JWTVerifier.InvalidClaims.selector
        );
        _expectRevert(
            '{"iss":"https://issuer.example","aud":"other-client","sub":"a","nonce":"n","exp":1700000600}',
            JWTVerifier.InvalidClaims.selector
        );
        _expectRevert(
            '{"iss":"https://issuer.example","aud":"demo-client","azp":"other-client","sub":"a","nonce":"n","exp":1700000600}',
            JWTVerifier.InvalidClaims.selector
        );
    }

    function test_rejectsExpiredOrNotYetValidToken() public {
        string memory jwt = MockIssuer.token("alice", NONCE, block.timestamp + 600);
        vm.warp(block.timestamp + 600);
        vm.expectRevert(JWTVerifier.InvalidClaims.selector);
        verifier.verify(jwt);

        _expectRevert(
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","nbf":1700000601,"exp":1700001200}',
            JWTVerifier.InvalidClaims.selector
        );
    }

    function test_rejectsAlgorithmOtherThanRS256() public {
        string memory payload = MockIssuer.claims("alice", NONCE, block.timestamp + 600);

        _expectRevert(
            '{"alg":"HS256","kid":"test-key-1"}', payload, JWTVerifier.InvalidJWT.selector
        );
        _expectRevert('{"alg":"none","kid":"test-key-1"}', payload, JWTVerifier.InvalidJWT.selector);
    }

    function test_rejectsCriticalHeaderExtension() public {
        string memory payload = MockIssuer.claims("alice", NONCE, block.timestamp + 600);

        _expectRevert(
            '{"alg":"RS256","kid":"test-key-1","crit":["exp"]}',
            payload,
            JWTParser.InvalidJSON.selector
        );
    }

    function test_rejectsChangedPayload() public {
        string memory jwt = MockIssuer.token("alice", NONCE, block.timestamp + 600);
        string memory otherJwt = MockIssuer.token("mallory", NONCE, block.timestamp + 600);
        bytes memory token = bytes(jwt);
        bytes memory other = bytes(otherJwt);
        // Use the header and the payload of `otherJwt` with the signature of `jwt`.
        bytes memory forged = bytes.concat(
            other.slice(0, other.lastIndexOf(".")), token.slice(token.lastIndexOf("."))
        );

        vm.expectRevert(JWTVerifier.InvalidSignature.selector);
        verifier.verify(string(forged));
    }

    function test_rejectsKeyThatIsNotInTheRegistry() public {
        string memory payload = MockIssuer.claims("alice", NONCE, block.timestamp + 600);

        _expectRevert(
            '{"alg":"RS256","kid":"other-key"}', payload, JWKSRegistry.UnknownKey.selector
        );
    }

    function test_rejectsTokenWhenKeySetIsStale() public {
        uint256 staleTime = registry.fetchedAt() + registry.MAX_KEY_SET_AGE() + 1;
        vm.warp(staleTime);
        string memory jwt = MockIssuer.token("alice", NONCE, staleTime + 600);

        vm.expectRevert(JWKSRegistry.StaleKeySet.selector);
        verifier.verify(jwt);
    }

    function test_rejectsAmbiguousClaims() public {
        // Duplicate nonce.
        _expectRevert(
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","nonce":"m","exp":1700000600}',
            JWTParser.InvalidJSON.selector
        );
        // Escaped member name ("nonce" is "nonce").
        _expectRevert(
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","\\u006eonce":"m","exp":1700000600}',
            JWTParser.InvalidJSON.selector
        );
        // Escaped value.
        _expectRevert(
            '{"iss":"https:\\/\\/issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600}',
            JWTParser.InvalidJSON.selector
        );
        // Audience array.
        _expectRevert(
            '{"iss":"https://issuer.example","aud":["demo-client"],"sub":"a","nonce":"n","exp":1700000600}',
            JWTParser.InvalidJSON.selector
        );
        // Missing exp.
        _expectRevert(
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n"}',
            JWTParser.InvalidJSON.selector
        );
        // Empty authorized party.
        _expectRevert(
            '{"iss":"https://issuer.example","aud":"demo-client","azp":"","sub":"a","nonce":"n","exp":1700000600}',
            JWTParser.InvalidJSON.selector
        );
        // Expiry as a string.
        _expectRevert(
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":"1700000600"}',
            JWTParser.InvalidJSON.selector
        );
    }

    function test_rejectsMalformedJson() public {
        string[4] memory payloads = [
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600,}',
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600}x',
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600',
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
