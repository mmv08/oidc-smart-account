// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

/// @title OIDC Claim Verifier Interface
/// @notice Authenticates OIDC evidence and returns the claim fields consumed by the account protocol.
/// @dev Implementations define the proof format and trust model. Callers must compare every returned
/// field against the action and account state they intend to authorize.
interface IOIDCClaimVerifier {
    /// @notice Authenticated OIDC fields normalized across verifier implementations.
    /// @param providerPolicyId Identifier for the provider, audience, and authorized-party policy.
    /// @param identityCommitment Commitment to the provider subject and account identity salt.
    /// @param nonce Provider-signed nonce that binds the claim to one protocol action.
    /// @param issuedAt Token issue time as Unix seconds.
    /// @param expiresAt Token expiry time as Unix seconds.
    struct VerifiedOIDCClaim {
        bytes32 providerPolicyId;
        bytes32 identityCommitment;
        bytes32 nonce;
        uint64 issuedAt;
        uint64 expiresAt;
    }

    /// @notice Verifies implementation-specific evidence and returns authenticated claim fields.
    /// @dev This function authenticates claims but does not consume the nonce. The factory or recovery
    /// controller must bind the nonce to an exact EIP-712 action and enforce replay protection.
    /// @param proof Encoded evidence in the format defined by the verifier implementation.
    /// @return claim Normalized claim fields authenticated by `proof`.
    function verifyClaim(bytes calldata proof)
        external
        view
        returns (VerifiedOIDCClaim memory claim);
}
