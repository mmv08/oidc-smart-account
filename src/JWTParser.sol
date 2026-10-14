// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import { Bytes } from "@openzeppelin/contracts/utils/Bytes.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

/// @title JWT JSON Parser
/// @notice Reads the members of a JWT header and payload that `JWTVerifier` uses.
/// @dev The parser reads only the top-level members of one JSON object. It finds the end of the
/// other values, but it does not validate their content: the issuer signature covers the JSON. A
/// member that the verifier uses must be a string without escapes, or an unsigned integer. A
/// duplicate member that the verifier uses, or an escape in a member name, causes a revert.
library JWTParser {
    using Bytes for bytes;

    /// @notice The JSON is not valid, or a necessary member is missing.
    error InvalidJSON();

    /// @notice JWT claims that `JWTVerifier` uses.
    /// @param iss Issuer.
    /// @param aud Audience. The parser accepts only one string, not an array.
    /// @param sub Subject: the ID of the user at the issuer.
    /// @param nonce Value that binds the JWT to one action.
    /// @param exp Expiry time in Unix seconds.
    /// @param nbf Not-before time in Unix seconds, or zero if the claim is missing.
    struct Claims {
        bytes iss;
        bytes aud;
        bytes sub;
        bytes nonce;
        uint256 exp;
        uint256 nbf;
    }

    /// @notice Reads the `alg` and `kid` members of a JWT header.
    /// @dev Reverts if the header has a `crit` member, because the verifier knows no extensions.
    function parseHeader(bytes memory json)
        internal
        pure
        returns (bytes memory alg, bytes memory kid)
    {
        uint256 seen = 0;
        for (uint256 i = _open(json); i != 0;) {
            bytes32 name;
            uint256 start;
            uint256 end;
            (name, start, end, i) = _member(json, i);
            if (name == keccak256("alg")) {
                seen = _mark(seen, 1);
                alg = _string(json, start, end);
            } else if (name == keccak256("kid")) {
                seen = _mark(seen, 2);
                kid = _string(json, start, end);
            } else if (name == keccak256("crit")) {
                revert InvalidJSON();
            }
        }
        require(seen == 3, InvalidJSON());
    }

    /// @notice Reads the claims of a JWT payload.
    /// @dev `iss`, `aud`, `sub`, `nonce`, and `exp` are necessary. `nbf` is optional.
    function parseClaims(bytes memory json) internal pure returns (Claims memory claims) {
        uint256 seen = 0;
        for (uint256 i = _open(json); i != 0;) {
            bytes32 name;
            uint256 start;
            uint256 end;
            (name, start, end, i) = _member(json, i);
            if (name == keccak256("iss")) {
                seen = _mark(seen, 1);
                claims.iss = _string(json, start, end);
            } else if (name == keccak256("aud")) {
                seen = _mark(seen, 2);
                claims.aud = _string(json, start, end);
            } else if (name == keccak256("sub")) {
                seen = _mark(seen, 4);
                claims.sub = _string(json, start, end);
            } else if (name == keccak256("nonce")) {
                seen = _mark(seen, 8);
                claims.nonce = _string(json, start, end);
            } else if (name == keccak256("exp")) {
                seen = _mark(seen, 16);
                claims.exp = _uint(json, start, end);
            } else if (name == keccak256("nbf")) {
                seen = _mark(seen, 32);
                claims.nbf = _uint(json, start, end);
            }
        }
        require(seen & 31 == 31, InvalidJSON());
    }

    /// @dev Returns the index of the first member of the top-level object.
    function _open(bytes memory json) private pure returns (uint256 i) {
        i = _skipSpace(json, 0);
        require(_at(json, i) == "{", InvalidJSON());
        i = _skipSpace(json, i + 1);
    }

    /// @dev Reads the member `"name": value` that starts at `i`. Returns the name hash, the start and
    /// the end of the value, and the start of the next member. After the last member, `next` is zero.
    /// After a comma, the caller always reads one more member. Thus a comma at the end reverts.
    function _member(bytes memory json, uint256 i)
        private
        pure
        returns (bytes32 name, uint256 start, uint256 end, uint256 next)
    {
        end = _skipString(json, i);
        name = keccak256(_string(json, i, end));
        i = _skipSpace(json, end);
        require(_at(json, i) == ":", InvalidJSON());
        start = _skipSpace(json, i + 1);
        end = _skipValue(json, start);
        next = _skipSpace(json, end);
        if (_at(json, next) == ",") return (name, start, end, _skipSpace(json, next + 1));
        require(json[next] == "}" && _skipSpace(json, next + 1) == json.length, InvalidJSON());
        next = 0;
    }

    /// @dev Returns the end of the value that starts at `i`. For an object or an array, it finds the
    /// closing bracket. It does not validate the content.
    function _skipValue(bytes memory json, uint256 i) private pure returns (uint256) {
        bytes1 c = _at(json, i);
        if (c == '"') return _skipString(json, i);
        if (c == "{" || c == "[") {
            uint256 depth = 0;
            while (true) {
                c = _at(json, i);
                if (c == '"') {
                    i = _skipString(json, i);
                    continue;
                }
                if (c == "{" || c == "[") ++depth;
                else if ((c == "}" || c == "]") && --depth == 0) return i + 1;
                ++i;
            }
        }
        // A number, `true`, `false`, or `null`.
        uint256 start = i;
        while (i < json.length && !_isDelimiter(json[i])) {
            ++i;
        }
        require(i > start, InvalidJSON());
        return i;
    }

    /// @dev Returns the index after the closing quote of the string that starts at `i`.
    function _skipString(bytes memory json, uint256 i) private pure returns (uint256) {
        require(_at(json, i) == '"', InvalidJSON());
        for (++i; _at(json, i) != '"'; ++i) {
            if (json[i] == "\\") ++i;
        }
        return i + 1;
    }

    /// @dev Returns the content of a string value. Reverts for other values and for escapes.
    function _string(bytes memory json, uint256 start, uint256 end)
        private
        pure
        returns (bytes memory value)
    {
        require(json[start] == '"', InvalidJSON());
        value = json.slice(start + 1, end - 1);
        require(value.indexOf("\\") == type(uint256).max, InvalidJSON());
    }

    /// @dev Returns the value of an unsigned integer. Reverts for other values.
    function _uint(bytes memory json, uint256 start, uint256 end)
        private
        pure
        returns (uint256 value)
    {
        bool success;
        (success, value) = Strings.tryParseUint(string(json), start, end);
        require(success, InvalidJSON());
    }

    /// @dev Reverts if the member flag is already set. This stops duplicate members.
    function _mark(uint256 seen, uint256 flag) private pure returns (uint256) {
        require(seen & flag == 0, InvalidJSON());
        return seen | flag;
    }

    function _skipSpace(bytes memory json, uint256 i) private pure returns (uint256) {
        while (i < json.length && _isSpace(json[i])) {
            ++i;
        }
        return i;
    }

    function _at(bytes memory json, uint256 i) private pure returns (bytes1) {
        require(i < json.length, InvalidJSON());
        return json[i];
    }

    function _isSpace(bytes1 c) private pure returns (bool) {
        return c == " " || c == "\t" || c == "\n" || c == "\r";
    }

    function _isDelimiter(bytes1 c) private pure returns (bool) {
        return c == "," || c == "}" || c == "]" || _isSpace(c);
    }
}
