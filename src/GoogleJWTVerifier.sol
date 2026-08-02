// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { RSA } from "@openzeppelin/contracts/utils/cryptography/RSA.sol";
import { Base64Url } from "./Base64Url.sol";
import { GoogleJWTJson } from "./GoogleJWTJson.sol";
import { IGoogleKeyRegistry } from "./IGoogleKeyRegistry.sol";
import { IOIDCClaimVerifier } from "./IOIDCClaimVerifier.sol";
import { OIDCIdentity } from "./OIDCIdentity.sol";

/// @notice Direct on-chain verifier for Google RS256 ID tokens.
/// @dev Proof encoding is abi.encode(bytes compactJwt, bytes32 identitySalt). The raw JWT and salt
/// become public calldata. The key-registry owner is an explicit recovery trust root.
contract GoogleJWTVerifier is IOIDCClaimVerifier {
    uint256 public constant MAX_JWT_LENGTH = 4096;
    uint256 public constant MAX_PROOF_LENGTH = 8192;
    uint256 private constant MAX_HEADER_LENGTH = 768;
    uint256 private constant MAX_PAYLOAD_LENGTH = 3072;

    bytes32 private constant GOOGLE_PROVIDER = keccak256("https://accounts.google.com");
    bytes32 private constant GOOGLE_ISSUER = keccak256("https://accounts.google.com");
    bytes32 private constant GOOGLE_ISSUER_LEGACY = keccak256("accounts.google.com");
    bytes32 private constant RS256 = keccak256("RS256");

    IGoogleKeyRegistry public immutable keyRegistry;
    bytes32 public immutable clientIdHash;
    bytes32 public immutable authorizedPartyHash;
    bytes32 public immutable providerPolicyId;

    error InvalidConfiguration();
    error InvalidJWT();
    error UnsupportedAlgorithm();
    error UnknownGoogleKey();
    error InvalidGoogleSignature();
    error InvalidGoogleClaims();

    constructor(
        IGoogleKeyRegistry keyRegistry_,
        string memory clientId,
        string memory authorizedParty
    ) {
        if (
            address(keyRegistry_) == address(0) || address(keyRegistry_).code.length == 0
                || bytes(clientId).length == 0 || bytes(clientId).length > 255
                || bytes(authorizedParty).length > 255
        ) revert InvalidConfiguration();

        keyRegistry = keyRegistry_;
        clientIdHash = keccak256(bytes(clientId));
        authorizedPartyHash =
            bytes(authorizedParty).length == 0 ? bytes32(0) : keccak256(bytes(authorizedParty));
        providerPolicyId = OIDCIdentity.policyId(GOOGLE_PROVIDER, clientIdHash, authorizedPartyHash);
    }

    function verifyClaim(bytes calldata proof)
        external
        view
        returns (VerifiedOIDCClaim memory claim)
    {
        if (proof.length > MAX_PROOF_LENGTH) revert InvalidJWT();
        (bytes memory jwt, bytes32 identitySalt) = abi.decode(proof, (bytes, bytes32));
        if (jwt.length == 0 || jwt.length > MAX_JWT_LENGTH) revert InvalidJWT();

        (
            bytes memory encodedHeader,
            bytes memory encodedPayload,
            bytes memory encodedSignature,
            bytes memory signingInput
        ) = _splitJWT(jwt);
        bytes memory headerJSON = Base64Url.decode(encodedHeader);
        bytes memory payloadJSON = Base64Url.decode(encodedPayload);
        bytes memory signature = Base64Url.decode(encodedSignature);
        if (
            headerJSON.length == 0 || headerJSON.length > MAX_HEADER_LENGTH
                || payloadJSON.length == 0 || payloadJSON.length > MAX_PAYLOAD_LENGTH
                || signature.length != 256
        ) revert InvalidJWT();

        GoogleJWTJson.Header memory header = GoogleJWTJson.parseHeader(headerJSON);
        if (keccak256(header.algorithm) != RS256) revert UnsupportedAlgorithm();

        (bytes memory exponent, bytes memory modulus, uint64 keyValidAfter, uint64 keyValidUntil) =
            keyRegistry.getKey(keccak256(header.keyId));
        if (exponent.length != 3 || modulus.length != 256) revert UnknownGoogleKey();
        if (!RSA.pkcs1Sha256(signingInput, signature, exponent, modulus)) {
            revert InvalidGoogleSignature();
        }

        GoogleJWTJson.Claims memory parsed = GoogleJWTJson.parseClaims(payloadJSON);
        if (
            parsed.issuedAt > block.timestamp || parsed.expiresAt <= block.timestamp
                || parsed.expiresAt <= parsed.issuedAt
                || (parsed.hasNotBefore && parsed.notBefore > block.timestamp)
                || parsed.issuedAt < keyValidAfter
                || (keyValidUntil != 0 && parsed.issuedAt >= keyValidUntil)
        ) revert InvalidGoogleClaims();

        bytes32 issuerHash = keccak256(parsed.issuer);
        if (issuerHash != GOOGLE_ISSUER && issuerHash != GOOGLE_ISSUER_LEGACY) {
            revert InvalidGoogleClaims();
        }
        _validateAudience(parsed.audiences, parsed.authorizedParty);

        bytes32 nonce = _parseBytes32Hex(parsed.nonce);
        bytes32 identity = OIDCIdentity.identityCommitment(
            providerPolicyId, keccak256(parsed.subject), identitySalt
        );
        return
            VerifiedOIDCClaim(providerPolicyId, identity, nonce, parsed.issuedAt, parsed.expiresAt);
    }

    function _validateAudience(bytes[] memory audiences, bytes memory tokenAuthorizedParty)
        private
        view
    {
        bool found = false;
        for (uint256 i = 0; i < audiences.length; ++i) {
            if (keccak256(audiences[i]) == clientIdHash) found = true;
        }
        if (!found) revert InvalidGoogleClaims();

        bytes32 tokenAuthorizedPartyHash =
            tokenAuthorizedParty.length == 0 ? bytes32(0) : keccak256(tokenAuthorizedParty);
        bytes32 expectedAuthorizedParty =
            authorizedPartyHash == bytes32(0) ? clientIdHash : authorizedPartyHash;
        if (
            ((audiences.length > 1 || authorizedPartyHash != bytes32(0))
                    && tokenAuthorizedPartyHash == bytes32(0))
                || (tokenAuthorizedPartyHash != bytes32(0)
                    && tokenAuthorizedPartyHash != expectedAuthorizedParty)
        ) revert InvalidGoogleClaims();
    }

    function _splitJWT(bytes memory jwt)
        private
        pure
        returns (
            bytes memory encodedHeader,
            bytes memory encodedPayload,
            bytes memory encodedSignature,
            bytes memory signingInput
        )
    {
        uint256 firstDot = type(uint256).max;
        uint256 secondDot = type(uint256).max;
        for (uint256 i = 0; i < jwt.length; ++i) {
            if (jwt[i] != 0x2e) continue;
            if (firstDot == type(uint256).max) firstDot = i;
            else if (secondDot == type(uint256).max) secondDot = i;
            else revert InvalidJWT();
        }
        if (
            firstDot == type(uint256).max || secondDot == type(uint256).max || firstDot == 0
                || secondDot <= firstDot + 1 || secondDot + 1 >= jwt.length
        ) revert InvalidJWT();

        encodedHeader = _slice(jwt, 0, firstDot);
        encodedPayload = _slice(jwt, firstDot + 1, secondDot - firstDot - 1);
        encodedSignature = _slice(jwt, secondDot + 1, jwt.length - secondDot - 1);
        signingInput = _slice(jwt, 0, secondDot);
    }

    function _slice(bytes memory input, uint256 start, uint256 length)
        private
        pure
        returns (bytes memory output)
    {
        output = new bytes(length);
        for (uint256 i = 0; i < length; ++i) {
            output[i] = input[start + i];
        }
    }

    function _parseBytes32Hex(bytes memory value) private pure returns (bytes32 result) {
        if (value.length != 66 || value[0] != 0x30 || value[1] != 0x78) {
            revert InvalidGoogleClaims();
        }
        uint256 parsed = 0;
        for (uint256 i = 2; i < 66; ++i) {
            uint8 character = uint8(value[i]);
            uint8 nibble = 0;
            if (character >= 0x30 && character <= 0x39) nibble = character - 0x30;
            else if (character >= 0x41 && character <= 0x46) nibble = character - 0x41 + 10;
            else if (character >= 0x61 && character <= 0x66) nibble = character - 0x61 + 10;
            else revert InvalidGoogleClaims();
            parsed = (parsed << 4) | nibble;
        }
        return bytes32(parsed);
    }
}
