// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Bytes } from "@openzeppelin/contracts/utils/Bytes.sol";

/// @title Google JWT JSON Parser
/// @notice Parses the protected header and security-relevant claims used by `GoogleJWTVerifier`.
/// @dev Rejects duplicate or escaped top-level names, escaped protected values, invalid UTF-8,
/// malformed unknown values, excessive nesting, and trailing input.
library GoogleJWTJson {
    using Bytes for bytes;

    /// @dev Maximum nesting accepted while validating unknown values.
    uint256 private constant MAX_DEPTH = 8;
    /// @dev Maximum number of values accepted in an `aud` array.
    uint256 private constant MAX_AUDIENCES = 8;

    bytes32 private constant ALG = keccak256("alg");
    bytes32 private constant KID = keccak256("kid");
    bytes32 private constant CRIT = keccak256("crit");
    bytes32 private constant B64 = keccak256("b64");
    bytes32 private constant ISS = keccak256("iss");
    bytes32 private constant AUD = keccak256("aud");
    bytes32 private constant AZP = keccak256("azp");
    bytes32 private constant SUB = keccak256("sub");
    bytes32 private constant NONCE = keccak256("nonce");
    bytes32 private constant IAT = keccak256("iat");
    bytes32 private constant EXP = keccak256("exp");
    bytes32 private constant NBF = keccak256("nbf");

    uint256 private constant SEEN_ALG = 1 << 0;
    uint256 private constant SEEN_KID = 1 << 1;
    uint256 private constant REQUIRED_HEADER = SEEN_ALG | SEEN_KID;
    uint256 private constant SEEN_ISS = 1 << 0;
    uint256 private constant SEEN_AUD = 1 << 1;
    uint256 private constant SEEN_AZP = 1 << 2;
    uint256 private constant SEEN_SUB = 1 << 3;
    uint256 private constant SEEN_NONCE = 1 << 4;
    uint256 private constant SEEN_IAT = 1 << 5;
    uint256 private constant SEEN_EXP = 1 << 6;
    uint256 private constant SEEN_NBF = 1 << 7;
    uint256 private constant REQUIRED_CLAIMS =
        SEEN_ISS | SEEN_AUD | SEEN_SUB | SEEN_NONCE | SEEN_IAT | SEEN_EXP;

    /// @dev Mutable in-memory cursor shared by parser helpers.
    /// @param input Complete JSON document.
    /// @param position Index of the next byte to parse.
    struct Cursor {
        bytes input;
        uint256 position;
    }

    /// @notice Protected JWS header fields required by the verifier.
    /// @param algorithm Exact `alg` string.
    /// @param keyId Exact `kid` string.
    struct Header {
        bytes algorithm;
        bytes keyId;
    }

    /// @notice Signed Google claim fields consumed by the verifier.
    /// @param issuer Exact `iss` value.
    /// @param audiences One or more exact `aud` values.
    /// @param authorizedParty Exact nonempty `azp`, or empty bytes when absent.
    /// @param subject Stable nonempty provider `sub` value.
    /// @param nonce Exact provider nonce string.
    /// @param issuedAt Integer `iat` timestamp.
    /// @param expiresAt Integer `exp` timestamp.
    /// @param notBefore Integer `nbf` timestamp when present.
    struct Claims {
        bytes issuer;
        bytes[] audiences;
        bytes authorizedParty;
        bytes subject;
        bytes nonce;
        uint64 issuedAt;
        uint64 expiresAt;
        uint64 notBefore;
    }

    /// @dev Thrown when JSON syntax or a protected field representation is invalid.
    error InvalidJSON();
    /// @dev Thrown when a security-relevant top-level member appears more than once.
    error DuplicateClaim();
    /// @dev Thrown when an audience array exceeds `MAX_AUDIENCES`.
    error TooManyAudiences();
    /// @dev Thrown when a protected integer exceeds `uint64`.
    error IntegerOutOfRange();

    /// @notice Parses and validates the protected fields required from a JWS header.
    /// @dev Requires exactly one `alg` and one nonempty `kid`; the verifier checks the algorithm value.
    /// Rejects `crit` and `b64` because no critical extensions or unencoded-payload mode are supported.
    /// Unknown members are syntax-checked.
    /// @param json Decoded protected-header JSON bytes.
    /// @return header Parsed algorithm and key identifier.
    function parseHeader(bytes memory json) internal pure returns (Header memory header) {
        Cursor memory cursor = Cursor(json, 0);
        _expectObjectStart(cursor);
        uint256 seen = 0;
        bool first = true;
        while (true) {
            _skipWhitespace(cursor);
            if (_consume(cursor, 0x7d)) break;
            if (!first) _expect(cursor, 0x2c);
            first = false;
            _skipWhitespace(cursor);

            bytes memory key = _parsePlainString(cursor);
            _skipWhitespace(cursor);
            _expect(cursor, 0x3a);
            _skipWhitespace(cursor);
            bytes32 keyHash = keccak256(key);
            if (keyHash == ALG) {
                seen = _mark(seen, SEEN_ALG);
                header.algorithm = _parsePlainString(cursor);
            } else if (keyHash == KID) {
                seen = _mark(seen, SEEN_KID);
                header.keyId = _parsePlainString(cursor);
            } else if (keyHash == CRIT || keyHash == B64) {
                revert InvalidJSON();
            } else {
                _skipValue(cursor, 1);
            }
        }
        _finish(cursor);
        if (seen != REQUIRED_HEADER || header.keyId.length == 0 || header.keyId.length > 128) {
            revert InvalidJSON();
        }
    }

    /// @notice Parses the signed claim fields required by the Google verifier.
    /// @dev Requires `iss`, `aud`, `sub`, `nonce`, `iat`, and `exp`; `azp` and `nbf` are optional. This
    /// function validates representation and presence, while policy and time checks remain in the verifier.
    /// @param json Decoded signed-payload JSON bytes.
    /// @return claims Parsed security-relevant claims.
    function parseClaims(bytes memory json) internal pure returns (Claims memory claims) {
        Cursor memory cursor = Cursor(json, 0);
        _expectObjectStart(cursor);
        uint256 seen = 0;
        bool first = true;
        while (true) {
            _skipWhitespace(cursor);
            if (_consume(cursor, 0x7d)) break;
            if (!first) _expect(cursor, 0x2c);
            first = false;
            _skipWhitespace(cursor);

            bytes memory key = _parsePlainString(cursor);
            _skipWhitespace(cursor);
            _expect(cursor, 0x3a);
            _skipWhitespace(cursor);
            bytes32 keyHash = keccak256(key);
            if (keyHash == ISS) {
                seen = _mark(seen, SEEN_ISS);
                claims.issuer = _parsePlainString(cursor);
            } else if (keyHash == AUD) {
                seen = _mark(seen, SEEN_AUD);
                claims.audiences = _parseAudience(cursor);
            } else if (keyHash == AZP) {
                seen = _mark(seen, SEEN_AZP);
                claims.authorizedParty = _parsePlainString(cursor);
                if (claims.authorizedParty.length == 0) revert InvalidJSON();
            } else if (keyHash == SUB) {
                seen = _mark(seen, SEEN_SUB);
                claims.subject = _parsePlainString(cursor);
            } else if (keyHash == NONCE) {
                seen = _mark(seen, SEEN_NONCE);
                claims.nonce = _parsePlainString(cursor);
            } else if (keyHash == IAT) {
                seen = _mark(seen, SEEN_IAT);
                claims.issuedAt = _parseUint64(cursor);
            } else if (keyHash == EXP) {
                seen = _mark(seen, SEEN_EXP);
                claims.expiresAt = _parseUint64(cursor);
            } else if (keyHash == NBF) {
                seen = _mark(seen, SEEN_NBF);
                claims.notBefore = _parseUint64(cursor);
            } else {
                _skipValue(cursor, 1);
            }
        }
        _finish(cursor);
        if (
            seen & REQUIRED_CLAIMS != REQUIRED_CLAIMS || claims.issuer.length == 0
                || claims.audiences.length == 0 || claims.subject.length == 0
                || claims.subject.length > 255
        ) revert InvalidJSON();
    }

    /// @dev Parses `aud` as one nonempty string or a bounded array of nonempty strings.
    function _parseAudience(Cursor memory cursor) private pure returns (bytes[] memory audiences) {
        _skipWhitespace(cursor);
        if (_peek(cursor) == 0x22) {
            audiences = new bytes[](1);
            audiences[0] = _parsePlainString(cursor);
            if (audiences[0].length == 0) revert InvalidJSON();
            return audiences;
        }

        _expect(cursor, 0x5b);
        bytes[] memory parsedAudiences = new bytes[](MAX_AUDIENCES);
        uint256 count = 0;
        bool first = true;
        while (true) {
            _skipWhitespace(cursor);
            if (_consume(cursor, 0x5d)) break;
            if (!first) _expect(cursor, 0x2c);
            first = false;
            _skipWhitespace(cursor);
            if (count == MAX_AUDIENCES) revert TooManyAudiences();
            bytes memory audience = _parsePlainString(cursor);
            if (audience.length == 0) revert InvalidJSON();
            parsedAudiences[count++] = audience;
        }
        if (count == 0) revert InvalidJSON();
        audiences = new bytes[](count);
        for (uint256 i = 0; i < count; ++i) {
            audiences[i] = parsedAudiences[i];
        }
    }

    /// @dev Rejects duplicate protected claims while updating the seen-field bitmap.
    function _mark(uint256 seen, uint256 flag) private pure returns (uint256) {
        if (seen & flag != 0) revert DuplicateClaim();
        return seen | flag;
    }

    function _expectObjectStart(Cursor memory cursor) private pure {
        _skipWhitespace(cursor);
        _expect(cursor, 0x7b);
    }

    /// @dev Rejects non-whitespace content after the top-level object.
    function _finish(Cursor memory cursor) private pure {
        _skipWhitespace(cursor);
        if (cursor.position != cursor.input.length) revert InvalidJSON();
    }

    /// @dev Parses a protected string without escapes. This gives `alg`, `kid`, and signed claim values
    /// one exact byte representation for comparison and hashing.
    function _parsePlainString(Cursor memory cursor) private pure returns (bytes memory value) {
        _expect(cursor, 0x22);
        uint256 start = cursor.position;
        while (cursor.position < cursor.input.length) {
            uint8 character = uint8(cursor.input[cursor.position]);
            if (character == 0x22) {
                value = cursor.input.slice(start, cursor.position);
                ++cursor.position;
                return value;
            }
            if (character < 0x20 || character == 0x5c) revert InvalidJSON();
            if (character < 0x80) {
                ++cursor.position;
            } else {
                cursor.position = _nextUtf8(cursor.input, cursor.position);
            }
        }
        revert InvalidJSON();
    }

    /// @dev Parses a nonnegative decimal integer with no leading zeros and checks `uint64` range.
    function _parseUint64(Cursor memory cursor) private pure returns (uint64 result) {
        uint256 start = cursor.position;
        if (start >= cursor.input.length) revert InvalidJSON();
        uint8 first = uint8(cursor.input[cursor.position]);
        if (first < 0x30 || first > 0x39) revert InvalidJSON();
        if (first == 0x30) {
            ++cursor.position;
            if (
                cursor.position < cursor.input.length
                    && uint8(cursor.input[cursor.position]) >= 0x30
                    && uint8(cursor.input[cursor.position]) <= 0x39
            ) revert InvalidJSON();
            return 0;
        }

        uint256 number = 0;
        while (cursor.position < cursor.input.length) {
            uint8 character = uint8(cursor.input[cursor.position]);
            if (character < 0x30 || character > 0x39) break;
            number = number * 10 + character - 0x30;
            if (number > type(uint64).max) revert IntegerOutOfRange();
            ++cursor.position;
        }
        if (cursor.position == start) revert InvalidJSON();
        return uint64(number);
    }

    /// @dev Validates and skips an unknown JSON value while enforcing `MAX_DEPTH`.
    function _skipValue(Cursor memory cursor, uint256 depth) private pure {
        if (depth > MAX_DEPTH) revert InvalidJSON();
        _skipWhitespace(cursor);
        uint8 character = _peek(cursor);
        if (character == 0x22) {
            _skipString(cursor);
        } else if (character == 0x7b) {
            _skipObject(cursor, depth + 1);
        } else if (character == 0x5b) {
            _skipArray(cursor, depth + 1);
        } else if (character == 0x74) {
            _expectLiteral(cursor, "true");
        } else if (character == 0x66) {
            _expectLiteral(cursor, "false");
        } else if (character == 0x6e) {
            _expectLiteral(cursor, "null");
        } else {
            _skipNumber(cursor);
        }
    }

    function _skipObject(Cursor memory cursor, uint256 depth) private pure {
        _expect(cursor, 0x7b);
        bool first = true;
        while (true) {
            _skipWhitespace(cursor);
            if (_consume(cursor, 0x7d)) return;
            if (!first) _expect(cursor, 0x2c);
            first = false;
            _skipWhitespace(cursor);
            _skipString(cursor);
            _skipWhitespace(cursor);
            _expect(cursor, 0x3a);
            _skipValue(cursor, depth);
        }
    }

    function _skipArray(Cursor memory cursor, uint256 depth) private pure {
        _expect(cursor, 0x5b);
        bool first = true;
        while (true) {
            _skipWhitespace(cursor);
            if (_consume(cursor, 0x5d)) return;
            if (!first) _expect(cursor, 0x2c);
            first = false;
            _skipValue(cursor, depth);
        }
    }

    /// @dev Validates a general JSON string, including UTF-8 and standard JSON escapes.
    function _skipString(Cursor memory cursor) private pure {
        _expect(cursor, 0x22);
        while (cursor.position < cursor.input.length) {
            uint8 character = uint8(cursor.input[cursor.position]);
            if (character == 0x22) {
                ++cursor.position;
                return;
            }
            if (character < 0x20) revert InvalidJSON();
            if (character == 0x5c) {
                ++cursor.position;
                if (cursor.position >= cursor.input.length) revert InvalidJSON();
                uint8 escaped = uint8(cursor.input[cursor.position++]);
                if (
                    escaped == 0x22 || escaped == 0x5c || escaped == 0x2f || escaped == 0x62
                        || escaped == 0x66 || escaped == 0x6e || escaped == 0x72 || escaped == 0x74
                ) continue;
                if (escaped != 0x75 || cursor.position + 4 > cursor.input.length) {
                    revert InvalidJSON();
                }
                _skipUnicodeEscape(cursor);
            } else if (character < 0x80) {
                ++cursor.position;
            } else {
                cursor.position = _nextUtf8(cursor.input, cursor.position);
            }
        }
        revert InvalidJSON();
    }

    /// @dev Validates one canonical UTF-8 scalar and returns the next byte position. Overlong encodings,
    /// encoded surrogates, out-of-range code points, invalid continuation bytes, and truncation revert.
    function _nextUtf8(bytes memory input, uint256 position) private pure returns (uint256) {
        uint8 first = uint8(input[position]);
        if (first >= 0xc2 && first <= 0xdf) {
            if (position + 1 >= input.length || !_isContinuation(uint8(input[position + 1]))) {
                revert InvalidJSON();
            }
            return position + 2;
        }
        if (first >= 0xe0 && first <= 0xef) {
            if (position + 2 >= input.length) revert InvalidJSON();
            uint8 second = uint8(input[position + 1]);
            uint8 third = uint8(input[position + 2]);
            if (
                !_isContinuation(third) || (first == 0xe0 && (second < 0xa0 || second > 0xbf))
                    || (first == 0xed && (second < 0x80 || second > 0x9f))
                    || (first != 0xe0 && first != 0xed && !_isContinuation(second))
            ) revert InvalidJSON();
            return position + 3;
        }
        if (first >= 0xf0 && first <= 0xf4) {
            if (position + 3 >= input.length) revert InvalidJSON();
            uint8 second = uint8(input[position + 1]);
            if (
                (first == 0xf0 && (second < 0x90 || second > 0xbf))
                    || (first == 0xf4 && (second < 0x80 || second > 0x8f))
                    || (first != 0xf0 && first != 0xf4 && !_isContinuation(second))
                    || !_isContinuation(uint8(input[position + 2]))
                    || !_isContinuation(uint8(input[position + 3]))
            ) revert InvalidJSON();
            return position + 4;
        }
        revert InvalidJSON();
    }

    function _isContinuation(uint8 character) private pure returns (bool) {
        return character >= 0x80 && character <= 0xbf;
    }

    /// @dev Validates one `\uXXXX` escape and consumes the required low surrogate after a high surrogate.
    function _skipUnicodeEscape(Cursor memory cursor) private pure {
        uint256 codepoint = _readHex4(cursor.input, cursor.position);
        cursor.position += 4;
        if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
            if (
                cursor.position + 6 > cursor.input.length
                    || uint8(cursor.input[cursor.position]) != 0x5c
                    || uint8(cursor.input[cursor.position + 1]) != 0x75
            ) revert InvalidJSON();
            uint256 low = _readHex4(cursor.input, cursor.position + 2);
            if (low < 0xdc00 || low > 0xdfff) revert InvalidJSON();
            cursor.position += 6;
        } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
            revert InvalidJSON();
        }
    }

    function _readHex4(bytes memory input, uint256 position) private pure returns (uint256 value) {
        if (position + 4 > input.length) revert InvalidJSON();
        for (uint256 i = 0; i < 4; ++i) {
            value = value * 16 + _hexNibble(uint8(input[position + i]));
        }
    }

    function _hexNibble(uint8 character) private pure returns (uint8) {
        if (_isDigit(character)) return character - 0x30;
        if (character >= 0x41 && character <= 0x46) return character - 0x41 + 10;
        if (character >= 0x61 && character <= 0x66) return character - 0x61 + 10;
        revert InvalidJSON();
    }

    /// @dev Validates the complete JSON number grammar for unknown numeric values.
    function _skipNumber(Cursor memory cursor) private pure {
        uint256 start = cursor.position;
        if (_consume(cursor, 0x2d)) { }
        if (cursor.position >= cursor.input.length) revert InvalidJSON();
        if (_consume(cursor, 0x30)) {
            if (
                cursor.position < cursor.input.length
                    && _isDigit(uint8(cursor.input[cursor.position]))
            ) {
                revert InvalidJSON();
            }
        } else {
            if (!_isDigitOneToNine(_peek(cursor))) revert InvalidJSON();
            while (
                cursor.position < cursor.input.length
                    && _isDigit(uint8(cursor.input[cursor.position]))
            ) {
                ++cursor.position;
            }
        }
        if (_consume(cursor, 0x2e)) {
            uint256 fractionStart = cursor.position;
            while (
                cursor.position < cursor.input.length
                    && _isDigit(uint8(cursor.input[cursor.position]))
            ) {
                ++cursor.position;
            }
            if (cursor.position == fractionStart) revert InvalidJSON();
        }
        if (_consume(cursor, 0x65) || _consume(cursor, 0x45)) {
            _consume(cursor, 0x2b) || _consume(cursor, 0x2d);
            uint256 exponentStart = cursor.position;
            while (
                cursor.position < cursor.input.length
                    && _isDigit(uint8(cursor.input[cursor.position]))
            ) {
                ++cursor.position;
            }
            if (cursor.position == exponentStart) revert InvalidJSON();
        }
        if (cursor.position == start) revert InvalidJSON();
    }

    function _expectLiteral(Cursor memory cursor, bytes memory literal) private pure {
        if (cursor.position + literal.length > cursor.input.length) revert InvalidJSON();
        for (uint256 i = 0; i < literal.length; ++i) {
            if (cursor.input[cursor.position + i] != literal[i]) revert InvalidJSON();
        }
        cursor.position += literal.length;
    }

    function _skipWhitespace(Cursor memory cursor) private pure {
        while (cursor.position < cursor.input.length) {
            uint8 character = uint8(cursor.input[cursor.position]);
            if (character != 0x20 && character != 0x09 && character != 0x0a && character != 0x0d) {
                break;
            }
            ++cursor.position;
        }
    }

    function _peek(Cursor memory cursor) private pure returns (uint8) {
        if (cursor.position >= cursor.input.length) revert InvalidJSON();
        return uint8(cursor.input[cursor.position]);
    }

    function _expect(Cursor memory cursor, uint8 expected) private pure {
        if (
            cursor.position >= cursor.input.length
                || uint8(cursor.input[cursor.position]) != expected
        ) {
            revert InvalidJSON();
        }
        ++cursor.position;
    }

    function _consume(Cursor memory cursor, uint8 expected) private pure returns (bool) {
        if (
            cursor.position < cursor.input.length
                && uint8(cursor.input[cursor.position]) == expected
        ) {
            ++cursor.position;
            return true;
        }
        return false;
    }

    function _isDigit(uint8 character) private pure returns (bool) {
        return character >= 0x30 && character <= 0x39;
    }

    function _isDigitOneToNine(uint8 character) private pure returns (bool) {
        return character >= 0x31 && character <= 0x39;
    }
}
