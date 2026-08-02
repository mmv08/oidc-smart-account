// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

/// @title OIDC Identity Derivation
/// @notice Derives canonical provider policies and account identity commitments.
/// @dev This library only defines typed hashes. Claim verifiers remain responsible for authenticating
/// provider claims before passing their hashes into these functions.
library OIDCIdentity {
    /// @dev Thrown when a required provider or audience identifier is zero.
    error InvalidIdentityInput();

    /// @dev Canonical provider identifier for Google accounts.
    bytes32 internal constant GOOGLE_PROVIDER = keccak256("https://accounts.google.com");
    /// @dev Canonical provider identifier for Sign in with Apple.
    bytes32 internal constant APPLE_PROVIDER = keccak256("https://appleid.apple.com");

    bytes32 internal constant POLICY_TYPEHASH = keccak256(
        "OIDCPolicy(bytes32 providerId,bytes32 audienceHash,bytes32 authorizedPartyHash)"
    );
    bytes32 internal constant IDENTITY_TYPEHASH =
        keccak256("OIDCIdentity(bytes32 policyId,bytes32 subjectHash,bytes32 salt)");

    /// @notice Derives a policy without a separate authorized party.
    /// @param providerId Hash of the canonical OIDC issuer.
    /// @param audienceHash Hash of the exact client ID accepted as the token audience.
    /// @return policy Canonical policy identifier used by accounts and claim verifiers.
    function policyId(bytes32 providerId, bytes32 audienceHash) internal pure returns (bytes32) {
        return policyId(providerId, audienceHash, bytes32(0));
    }

    /// @notice Derives a policy that optionally binds a distinct authorized party.
    /// @dev Use a zero `authorizedPartyHash` for ordinary Google and Apple policies. For a Google
    /// hybrid policy, use the hash of the exact signed `azp` client ID.
    /// @param providerId Hash of the canonical OIDC issuer.
    /// @param audienceHash Hash of the exact accepted audience client ID.
    /// @param authorizedPartyHash Hash of the required `azp`, or zero when no separate party is used.
    /// @return policy Canonical policy identifier used by accounts and claim verifiers.
    function policyId(bytes32 providerId, bytes32 audienceHash, bytes32 authorizedPartyHash)
        internal
        pure
        returns (bytes32)
    {
        if (providerId == bytes32(0) || audienceHash == bytes32(0)) revert InvalidIdentityInput();
        return keccak256(abi.encode(POLICY_TYPEHASH, providerId, audienceHash, authorizedPartyHash));
    }

    /// @notice Creates a salted commitment to a stable provider subject under one policy.
    /// @dev The caller must hash the exact authenticated `sub` value before calling. The salt should be
    /// account-specific; the direct JWT verifier receives it in public calldata.
    /// @param policy Policy identifier returned by `policyId`.
    /// @param subjectHash Hash of the provider's stable subject identifier.
    /// @param salt Identity salt chosen for this account.
    /// @return commitment Typed identity commitment stored by the account.
    function identityCommitment(bytes32 policy, bytes32 subjectHash, bytes32 salt)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(IDENTITY_TYPEHASH, policy, subjectHash, salt));
    }
}
