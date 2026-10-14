// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Base64 } from "@openzeppelin/contracts/utils/Base64.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
import { JWKSRegistry } from "../../src/JWKSRegistry.sol";

/// @notice Test OIDC issuer. It signs RS256 JWTs with a fixed RSA-2048 test key.
/// @dev The private exponent of this key is public. Use the key only in tests.
library MockIssuer {
    string internal constant ISSUER = "https://issuer.example";
    string internal constant AUDIENCE = "demo-client";
    string internal constant KID = "test-key-1";
    string internal constant HEADER = '{"alg":"RS256","kid":"test-key-1","typ":"JWT"}';

    bytes internal constant MODULUS = hex"e5e153ede151459a41ad77d701a6241e83b81885323f6529944aa159262ead85"
        hex"63fd85bbded852647ed4a310588c09166e1a24d040c7a75c204f537c88757716"
        hex"d786eebc14a3de872751ea7c221a1e0eaeed67ac30cf41bdfed50794301de657"
        hex"d26232acaf5fd8e0722d050008a498cf23ce192e8dab503a36e1da2818844f00"
        hex"3f37ca87a4fc759e0c755dd0eab69d5693f25bc14867049f27f9f214f5723de3"
        hex"60d8c07545c77d4ee181b09076b65eb8491e8679042282193d1df88cba7d6043"
        hex"44dce940113193c575c4a2ff66df8b7d8c1457b02ca6e383e1b981a006aec76a"
        hex"b3e388676d9e3e6f2f7bb4175a510d4bc0c31d31dde752ec1400bbb892ec38a5";

    bytes internal constant PRIVATE_EXPONENT = hex"5a6e32ab1088fd1d7a9ab7daffce10c56441a67bb7519305314dce7d18752253"
        hex"a80b1271de6f30b251e66a2343020b8d2450ea8c75ff5489fc37d87ad3df89b2"
        hex"95a48203c106d9c24728855ac1bb8e796e3cfc1c93b2e484ce5b9538a95909c5"
        hex"2080fab84de1219ae1af6e191e4d49c3aaad27e0d56040163682d0641788ecde"
        hex"48131f31794ba3f096b08878752e8d1a01ead3c00a9f4303e44584c30e84760b"
        hex"abb80da2ecf77d8278496b0240917704a10dcf4f215baac7b692a399121d93be"
        hex"a49f4d54fc4bdab95525a3a829301d49456ac1358109126097bad4bd372a2697"
        hex"dfe3169b9b92f6d96e249fc89c7d3415ad69812174aaacf5dbe02995d63f99a1";

    /// @notice Returns the JWKS of the issuer: one key.
    function keys() internal pure returns (JWKSRegistry.Key[] memory result) {
        result = new JWKSRegistry.Key[](1);
        result[0] = JWKSRegistry.Key({ kid: KID, modulus: MODULUS });
    }

    /// @notice Returns a JWT for `sub` with `nonce` that expires at `exp`.
    function token(string memory sub, string memory nonce, uint256 exp)
        internal
        view
        returns (string memory)
    {
        return sign(HEADER, claims(sub, nonce, exp));
    }

    /// @notice Returns the JSON claims that the issuer usually puts in a JWT.
    function claims(string memory sub, string memory nonce, uint256 exp)
        internal
        pure
        returns (string memory)
    {
        return string.concat(
            '{"iss":"',
            ISSUER,
            '","aud":"',
            AUDIENCE,
            '","sub":"',
            sub,
            '","nonce":"',
            nonce,
            '","exp":',
            Strings.toString(exp),
            "}"
        );
    }

    /// @notice Signs any header and payload with the RS256 algorithm.
    function sign(string memory header, string memory payload)
        internal
        view
        returns (string memory)
    {
        string memory signingInput = string.concat(
            Base64.encodeURL(bytes(header)), ".", Base64.encodeURL(bytes(payload))
        );
        // EMSA-PKCS1-v1_5 encoding of the SHA-256 digest (RFC 8017, section 9.2).
        bytes memory padding = new bytes(202);
        for (uint256 i = 0; i < padding.length; ++i) {
            padding[i] = 0xff;
        }
        bytes memory encoded = abi.encodePacked(
            hex"0001",
            padding,
            hex"003031300d060960864801650304020105000420",
            sha256(bytes(signingInput))
        );
        bytes memory signature = Math.modExp(encoded, PRIVATE_EXPONENT, MODULUS);
        return string.concat(signingInput, ".", Base64.encodeURL(signature));
    }
}
