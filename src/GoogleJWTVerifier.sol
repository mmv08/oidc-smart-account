// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { RSA } from "@openzeppelin/contracts/utils/cryptography/RSA.sol";
import { Bytes } from "@openzeppelin/contracts/utils/Bytes.sol";
import { Base64Url } from "./Base64Url.sol";
import { GoogleJWTJson } from "./GoogleJWTJson.sol";
import { IGoogleKeyRegistry } from "./IGoogleKeyRegistry.sol";
import { IOIDCClaimVerifier } from "./IOIDCClaimVerifier.sol";
import { OIDCIdentity } from "./OIDCIdentity.sol";

/// @title Google RS256 JWT Verifier
/// @notice Verifies a Google ID token on-chain and returns the normalized OIDC claim used by accounts.
/// @dev Proofs encode `(compactJwt, identitySalt)`; both values are public calldata. The registry owner
/// can authorize arbitrary signing keys.
contract GoogleJWTVerifier is IOIDCClaimVerifier {
    using Bytes for bytes;

    /// @notice Maximum accepted compact JWT length in bytes.
    uint256 public constant MAX_JWT_LENGTH = 4096;
    /// @notice Maximum accepted ABI-encoded proof length in bytes.
    uint256 public constant MAX_PROOF_LENGTH = 8192;
    uint256 private constant MAX_HEADER_LENGTH = 768;
    uint256 private constant MAX_PAYLOAD_LENGTH = 3072;

    bytes32 private constant GOOGLE_ISSUER_LEGACY = keccak256("accounts.google.com");
    bytes32 private constant RS256 = keccak256("RS256");

    /// @notice Registry that resolves signed Google `kid` values to RSA moduli.
    IGoogleKeyRegistry public immutable keyRegistry;
    /// @notice Hash of the configured OAuth client ID required in `aud`.
    bytes32 public immutable clientIdHash;
    /// @notice Hash of a separately required `azp`, or zero for an ordinary web-client policy.
    bytes32 public immutable authorizedPartyHash;
    /// @notice Policy identifier derived from canonical Google, audience, and authorized-party hashes.
    bytes32 public immutable providerPolicyId;

    /// @dev Thrown when a dependency or immutable client-policy input is invalid.
    error InvalidConfiguration();
    /// @dev Thrown when explicit proof or JWT bounds, segmentation, or decoded-length checks fail.
    error InvalidJWT();
    /// @dev Thrown when the protected header does not specify exactly `RS256`.
    error UnsupportedAlgorithm();
    /// @dev Thrown when `kid` does not resolve to a 256-byte modulus.
    error UnknownGoogleKey();
    /// @dev Thrown when the RSA PKCS#1 v1.5 SHA-256 signature is invalid.
    error InvalidGoogleSignature();
    /// @dev Thrown when signed claim values do not satisfy the configured policy or time checks.
    error InvalidGoogleClaims();

    /// @param keyRegistry_ Registry controlled by the project's Google key updater.
    /// @param clientId Exact OAuth client ID required in the signed `aud` claim.
    /// @param authorizedParty Exact signed `azp` required for a hybrid policy, or an empty string for
    /// an ordinary web-client policy.
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
        providerPolicyId =
            OIDCIdentity.policyId(OIDCIdentity.GOOGLE_PROVIDER, clientIdHash, authorizedPartyHash);
    }

    /// @inheritdoc IOIDCClaimVerifier
    /// @dev Verifies the original `header.payload` bytes. The policy commits to immutable verifier
    /// configuration; the identity commitment includes the proof salt.
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

        (bytes memory modulus, uint64 keyValidAfter, uint64 keyValidUntil) =
            keyRegistry.getKey(keccak256(header.keyId));
        if (modulus.length != 256) revert UnknownGoogleKey();
        if (!RSA.pkcs1Sha256(signingInput, signature, hex"010001", modulus)) {
            revert InvalidGoogleSignature();
        }

        GoogleJWTJson.Claims memory parsed = GoogleJWTJson.parseClaims(payloadJSON);
        if (
            parsed.issuedAt > block.timestamp || parsed.expiresAt <= block.timestamp
                || parsed.expiresAt <= parsed.issuedAt || parsed.notBefore > block.timestamp
                || parsed.issuedAt < keyValidAfter
                || (keyValidUntil != 0 && parsed.issuedAt >= keyValidUntil)
        ) revert InvalidGoogleClaims();

        bytes32 issuerHash = keccak256(parsed.issuer);
        if (issuerHash != OIDCIdentity.GOOGLE_PROVIDER && issuerHash != GOOGLE_ISSUER_LEGACY) {
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

    /// @dev Requires the configured client ID in `aud` and enforces Google's `azp` rules. Multiple
    /// audiences require `azp`. A present `azp` must match the client ID for an ordinary policy or the
    /// separately configured authorized party for a hybrid policy.
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
        if (authorizedPartyHash != bytes32(0)) {
            if (tokenAuthorizedPartyHash != authorizedPartyHash) revert InvalidGoogleClaims();
            return;
        }
        if (audiences.length > 1 && tokenAuthorizedPartyHash == bytes32(0)) {
            revert InvalidGoogleClaims();
        }
        if (tokenAuthorizedPartyHash != bytes32(0) && tokenAuthorizedPartyHash != clientIdHash) {
            revert InvalidGoogleClaims();
        }
    }

    /// @dev Splits a compact JWT into exactly three nonempty segments and preserves the original
    /// `header.payload` bytes as the RSA signing input.
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

        encodedHeader = jwt.slice(0, firstDot);
        encodedPayload = jwt.slice(firstDot + 1, secondDot);
        encodedSignature = jwt.slice(secondDot + 1, jwt.length);
        signingInput = jwt.slice(0, secondDot);
    }

    /// @dev Parses the provider nonce as exactly `0x` followed by 64 hexadecimal digits.
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
