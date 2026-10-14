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

    string internal constant NONCE =
        "0x1111111111111111111111111111111111111111111111111111111111111111";

    function test_returnsSubjectAndNonceHashes() public view {
        string memory jwt = MockIssuer.token("alice", NONCE, block.timestamp + 600);

        (bytes32 subjectHash, bytes32 nonceHash) = verifier.verify(jwt);
        assertEq(subjectHash, keccak256("alice"));
        assertEq(nonceHash, keccak256(bytes(NONCE)));
    }

    function test_acceptsMatchingAzpCurrentNbfAndUnknownClaims() public view {
        string memory payload = string.concat(
            '{"iss":"https://issuer.example","azp":"demo-client","aud":"demo-client",',
            '"sub":"alice","nonce":"n","nbf":',
            Strings.toString(block.timestamp),
            ',"iat":1699999000,"exp":1700000600,',
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
        uint256 exp = block.timestamp + 600;
        string memory jwt = MockIssuer.token("alice", NONCE, exp);
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

    function test_rejectsAlgorithmOtherThanRS256() public {
        string memory payload = MockIssuer.claims("alice", NONCE, block.timestamp + 600);

        _expectRevert(
            '{"alg":"HS256","kid":"test-key-1"}', payload, JWTVerifier.InvalidJWT.selector
        );
        _expectRevert('{"alg":"none","kid":"test-key-1"}', payload, JWTVerifier.InvalidJWT.selector);
    }

    function test_rejectsInvalidHeader() public {
        string memory payload = MockIssuer.claims("alice", NONCE, block.timestamp + 600);
        string[5] memory headers = [
            '{"alg":"RS256","kid":"test-key-1","crit":["exp"]}',
            '{"alg":"RS256","alg":"RS256","kid":"test-key-1"}',
            '{"alg":"RS256","kid":"test-key-1","kid":"test-key-1"}',
            '{"alg":"RS256","kid":""}',
            '{"alg":"RS256"}'
        ];
        for (uint256 i = 0; i < headers.length; ++i) {
            _expectRevert(headers[i], payload, JWTParser.InvalidJSON.selector);
        }
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
        string[9] memory payloads = [
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","nonce":"m","exp":1700000600}',
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","\\u006eonce":"m","exp":1700000600}',
            '{"iss":"https:\\/\\/issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600}',
            '{"iss":"https://issuer.example","aud":["demo-client"],"sub":"a","nonce":"n","exp":1700000600}',
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n"}',
            '{"iss":"https://issuer.example","aud":"demo-client","azp":"","sub":"a","nonce":"n","exp":1700000600}',
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":"1700000600"}',
            MockIssuer.claims("", "n", block.timestamp + 600),
            MockIssuer.claims("a", "", block.timestamp + 600)
        ];
        for (uint256 i = 0; i < payloads.length; ++i) {
            _expectRevert(payloads[i], JWTParser.InvalidJSON.selector);
        }
    }

    function test_rejectsMalformedJson() public {
        string[6] memory payloads = [
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600,}',
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600}x',
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600',
            '{"iss" "https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":1700000600}',
            '{"iss":"https://issuer.example","aud":"demo-client","sub":"a","nonce":"n","exp":01700000600}',
            MockIssuer.claims("alice\n", NONCE, block.timestamp + 600)
        ];
        for (uint256 i = 0; i < payloads.length; ++i) {
            _expectRevert(payloads[i], JWTParser.InvalidJSON.selector);
        }
    }

    function test_rejectsTokenWithoutThreeNonemptyParts() public {
        string[7] memory tokens = ["", "no-dots", "one.dot", ".p.s", "h..s", "h.p.", "h.p.s.x"];
        for (uint256 i = 0; i < tokens.length; ++i) {
            vm.expectRevert(JWTVerifier.InvalidJWT.selector);
            verifier.verify(tokens[i]);
        }
    }

    function test_rejectsNoncanonicalBase64URL() public {
        bytes memory token = bytes(MockIssuer.token("alice", NONCE, block.timestamp + 600));
        vm.expectRevert(JWTVerifier.InvalidJWT.selector);
        verifier.verify(string(bytes.concat(token, "==")));

        // RSA-2048 ends with two Base64URL characters. The last four bits must be zero.
        token[token.length - 1] = token[token.length - 1] == "A" ? bytes1("B") : bytes1("R");
        vm.expectRevert(JWTVerifier.InvalidJWT.selector);
        verifier.verify(string(token));
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
