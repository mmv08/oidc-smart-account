// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

/// @notice Boundary between the on-chain identity protocol and any mechanism that proves OIDC claims.
/// @dev Implementations may use direct JWT verification, an oracle, a proof registry, or another bridge.
interface IOIDCClaimVerifier {
    /// @notice Minimal claim facts consumed by the on-chain identity protocol.
    struct VerifiedOIDCClaim {
        bytes32 providerPolicyId;
        bytes32 identityCommitment;
        bytes32 nonce;
        uint64 issuedAt;
        uint64 expiresAt;
    }

    /// @notice Verifies opaque evidence and returns normalized authenticated OIDC claims.
    function verifyClaim(bytes calldata proof)
        external
        view
        returns (VerifiedOIDCClaim memory claim);
}
