// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { Base64Url } from "../src/Base64Url.sol";
import { GoogleJWTJson } from "../src/GoogleJWTJson.sol";

contract GoogleJWTParsingHarness {
    function decode(bytes memory input) external pure returns (bytes memory) {
        return Base64Url.decode(input);
    }

    function parseHeader(bytes memory input)
        external
        pure
        returns (bytes memory algorithm, bytes memory keyId)
    {
        GoogleJWTJson.Header memory header = GoogleJWTJson.parseHeader(input);
        return (header.algorithm, header.keyId);
    }

    function parseClaims(bytes memory input)
        external
        pure
        returns (uint256 audienceCount, uint64 issuedAt, uint64 expiresAt, uint64 notBefore)
    {
        GoogleJWTJson.Claims memory claims = GoogleJWTJson.parseClaims(input);
        return (claims.audiences.length, claims.issuedAt, claims.expiresAt, claims.notBefore);
    }
}

contract GoogleJWTParsingTest is Test {
    GoogleJWTParsingHarness private harness;

    function setUp() public {
        harness = new GoogleJWTParsingHarness();
    }

    function test_base64UrlDecodesAllRemaindersAndRejectsNonCanonicalInput() public view {
        assertEq(harness.decode(bytes("Zg")), bytes("f"));
        assertEq(harness.decode(bytes("Zm8")), bytes("fo"));
        assertEq(harness.decode(bytes("Zm9v")), bytes("foo"));
    }

    function test_base64UrlRejectsBadLengthCharactersPaddingAndPadBits() public {
        vm.expectRevert(Base64Url.InvalidBase64Url.selector);
        harness.decode(bytes("A"));
        vm.expectRevert(Base64Url.InvalidBase64Url.selector);
        harness.decode(bytes("Z="));
        vm.expectRevert(Base64Url.InvalidBase64Url.selector);
        harness.decode(bytes("Zh"));
        vm.expectRevert(Base64Url.InvalidBase64Url.selector);
        harness.decode(bytes("Zm9"));
    }

    function test_parserAcceptsBoundedUnknownNestedJSONValues() public view {
        (bytes memory algorithm, bytes memory keyId) = harness.parseHeader(
            bytes('{"alg":"RS256","kid":"k","x":{"a":[true,false,null,-12.3e+4,"\\u0041"]}}')
        );
        assertEq(algorithm, bytes("RS256"));
        assertEq(keyId, bytes("k"));

        (uint256 audiences, uint64 issuedAt, uint64 expiresAt, uint64 notBefore) = harness.parseClaims(
            bytes(
                '{ "iss":"https://accounts.google.com", "aud":["client","other"], "azp":"client", "sub":"s", "nonce":"n", "iat":1, "exp":2, "nbf":0, "unknown":[{"s":"line\\n"}] }'
            )
        );
        assertEq(audiences, 2);
        assertEq(issuedAt, 1);
        assertEq(expiresAt, 2);
        assertEq(notBefore, 0);
    }

    function test_parserRejectsDuplicateMissingEscapedAndTrailingProtectedMembers() public {
        vm.expectRevert(GoogleJWTJson.DuplicateClaim.selector);
        harness.parseClaims(
            bytes('{"iss":"i","aud":"a","aud":"b","sub":"s","nonce":"n","iat":1,"exp":2}')
        );
        _expectInvalidClaims('{"iss":"i","aud":"a","sub":"s","nonce":"n","iat":1}');
        _expectInvalidClaims('{"iss":"i","\\u0061ud":"a","sub":"s","nonce":"n","iat":1,"exp":2}');
        _expectInvalidClaims('{"iss":"i","aud":"a","sub":"s","nonce":"n","iat":1,"exp":2}x');
    }

    function test_parserRejectsMalformedOrOutOfRangeNumbersAndUnknownValues() public {
        _expectInvalidClaims('{"iss":"i","aud":"a","sub":"s","nonce":"n","iat":1.5,"exp":2}');
        _expectInvalidClaims('{"iss":"i","aud":"a","sub":"s","nonce":"n","iat":01,"exp":2}');
        _expectIntegerRange(
            '{"iss":"i","aud":"a","sub":"s","nonce":"n","iat":18446744073709551616,"exp":2}'
        );

        vm.expectRevert(GoogleJWTJson.InvalidJSON.selector);
        harness.parseHeader(bytes('{"alg":"RS256","kid":"k","x":1e}'));
        vm.expectRevert(GoogleJWTJson.InvalidJSON.selector);
        harness.parseHeader(bytes('{"alg":"RS256","kid":"k","x":"unterminated}'));
    }

    function test_parserRejectsEmptyTooManyOrMalformedAudienceArrays() public {
        _expectInvalidClaims('{"iss":"i","aud":[],"sub":"s","nonce":"n","iat":1,"exp":2}');
        vm.expectRevert(GoogleJWTJson.TooManyAudiences.selector);
        harness.parseClaims(
            bytes(
                '{"iss":"i","aud":["1","2","3","4","5","6","7","8","9"],"sub":"s","nonce":"n","iat":1,"exp":2}'
            )
        );
        _expectInvalidClaims('{"iss":"i","aud":["a",],"sub":"s","nonce":"n","iat":1,"exp":2}');
    }

    function test_parserValidatesUtf8InKnownAndUnknownStrings() public {
        harness.parseHeader(_headerWithUnknownString(hex"f09f9880"));

        bytes[4] memory malformed =
            [bytes(hex"c0af"), bytes(hex"80"), bytes(hex"eda080"), bytes(hex"f4908080")];
        for (uint256 i = 0; i < malformed.length; ++i) {
            vm.expectRevert(GoogleJWTJson.InvalidJSON.selector);
            harness.parseHeader(_headerWithUnknownString(malformed[i]));
        }

        vm.expectRevert(GoogleJWTJson.InvalidJSON.selector);
        harness.parseHeader(abi.encodePacked('{"alg":"RS256","kid":"', hex"c0af", '"}'));

        harness.parseHeader(bytes('{"alg":"RS256","kid":"k","x":"\\uD83D\\uDE00"}'));
        string[3] memory malformedEscapes = [
            '{"alg":"RS256","kid":"k","x":"\\uD800"}',
            '{"alg":"RS256","kid":"k","x":"\\uDE00"}',
            '{"alg":"RS256","kid":"k","x":"\\uD800\\u0041"}'
        ];
        for (uint256 i = 0; i < malformedEscapes.length; ++i) {
            vm.expectRevert(GoogleJWTJson.InvalidJSON.selector);
            harness.parseHeader(bytes(malformedEscapes[i]));
        }
    }

    function _headerWithUnknownString(bytes memory raw) private pure returns (bytes memory) {
        return abi.encodePacked('{"alg":"RS256","kid":"k","x":"', raw, '"}');
    }

    function test_parserRejectsUnknownValuesDeeperThanBound() public {
        vm.expectRevert(GoogleJWTJson.InvalidJSON.selector);
        harness.parseHeader(bytes('{"alg":"RS256","kid":"k","x":[[[[[[[[[[0]]]]]]]]]]}'));
    }

    function test_parserRejectsUnsupportedCriticalJwsExtensions() public {
        vm.expectRevert(GoogleJWTJson.InvalidJSON.selector);
        harness.parseHeader(bytes('{"alg":"RS256","kid":"k","crit":["b64"],"b64":false}'));
    }

    function test_parserRejectsPresentButEmptyAuthorizedParty() public {
        vm.expectRevert(GoogleJWTJson.InvalidJSON.selector);
        harness.parseClaims(
            bytes('{"iss":"i","aud":"a","azp":"","sub":"s","nonce":"n","iat":1,"exp":2}')
        );
    }

    function _expectInvalidClaims(string memory json) private {
        vm.expectRevert(GoogleJWTJson.InvalidJSON.selector);
        harness.parseClaims(bytes(json));
    }

    function _expectIntegerRange(string memory json) private {
        vm.expectRevert(GoogleJWTJson.IntegerOutOfRange.selector);
        harness.parseClaims(bytes(json));
    }
}
