// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import { Base64 } from "@openzeppelin/contracts/utils/Base64.sol";
import { Bytes } from "@openzeppelin/contracts/utils/Bytes.sol";
import { RSA } from "@openzeppelin/contracts/utils/cryptography/RSA.sol";
import { JWKSRegistry } from "./JWKSRegistry.sol";
import { JWTParser } from "./JWTParser.sol";

/// @title JWT Verifier
/// @notice Examines RS256 JWTs from one OIDC issuer for one audience.
/// @dev The verifier gets the issuer keys from `registry`. It does not know which action a JWT
/// approves: the caller must compare the returned nonce hash with its action.
contract JWTVerifier {
    using Bytes for bytes;

    /// @notice Registry that keeps the RSA keys of the issuer.
    JWKSRegistry public immutable registry;
    /// @notice Hash of the `iss` claim that a JWT must have.
    bytes32 public immutable issuerHash;
    /// @notice Hash of the `aud` claim (the OAuth client ID) that a JWT must have.
    bytes32 public immutable audienceHash;

    /// @notice The JWT has fewer than three parts, or its algorithm is not RS256.
    error InvalidJWT();
    /// @notice The RSA signature is not valid for the key that the JWT header selects.
    error InvalidSignature();
    /// @notice The issuer, the audience, or the time is not correct.
    error InvalidClaims();

    /// @param registry_ Registry that keeps the RSA keys of the issuer.
    /// @param issuer Exact `iss` value, for example `https://accounts.google.com`.
    /// @param audience Exact `aud` value. This is the OAuth client ID of the application.
    constructor(JWKSRegistry registry_, string memory issuer, string memory audience) {
        registry = registry_;
        issuerHash = keccak256(bytes(issuer));
        audienceHash = keccak256(bytes(audience));
    }

    /// @notice Examines a compact JWT and returns the hashes of its `sub` and `nonce` claims.
    /// @dev Reverts if the JWT is not valid at the current block time. The verifier does not use
    /// `iat`.
    /// @param jwt JWT in the format `base64url(header).base64url(payload).base64url(signature)`.
    /// @return subjectHash Keccak-256 hash of the `sub` claim.
    /// @return nonceHash Keccak-256 hash of the `nonce` claim.
    function verify(string calldata jwt)
        external
        view
        returns (bytes32 subjectHash, bytes32 nonceHash)
    {
        bytes memory token = bytes(jwt);
        uint256 dot1 = token.indexOf(".");
        require(dot1 != type(uint256).max, InvalidJWT());
        uint256 dot2 = token.indexOf(".", dot1 + 1);
        require(dot2 != type(uint256).max, InvalidJWT());

        (bytes memory alg, bytes memory kid) = JWTParser.parseHeader(_decode(token, 0, dot1));
        require(alg.equal("RS256"), InvalidJWT());

        // The signature covers the Base64URL text. Thus the decoded header and payload are exactly
        // what the issuer signed.
        bytes memory modulus = registry.getKey(keccak256(kid));
        bytes memory signature = _decode(token, dot2 + 1, token.length);
        require(
            RSA.pkcs1Sha256(token.slice(0, dot2), signature, hex"010001", modulus),
            InvalidSignature()
        );

        JWTParser.Claims memory claims = JWTParser.parseClaims(_decode(token, dot1 + 1, dot2));
        require(
            keccak256(claims.iss) == issuerHash && keccak256(claims.aud) == audienceHash
                && claims.exp > block.timestamp && claims.nbf <= block.timestamp,
            InvalidClaims()
        );

        return (keccak256(claims.sub), keccak256(claims.nonce));
    }

    /// @dev Decodes the Base64URL part of `token` from `start` to `end`.
    function _decode(bytes memory token, uint256 start, uint256 end)
        private
        pure
        returns (bytes memory)
    {
        return Base64.decode(string(token.slice(start, end)));
    }
}
