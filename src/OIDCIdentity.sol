// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

/// @notice Canonical identifiers shared by OIDC-aware contracts and proof adapters.
/// @dev This library models identities and policies; it does not verify JWTs or prescribe a proof bridge.
library OIDCIdentity {
    error InvalidIdentityInput();

    bytes32 internal constant GOOGLE_PROVIDER = keccak256("https://accounts.google.com");
    bytes32 internal constant APPLE_PROVIDER = keccak256("https://appleid.apple.com");

    bytes32 internal constant POLICY_TYPEHASH = keccak256(
        "OIDCPolicy(bytes32 providerId,bytes32 audienceHash,bytes32 authorizedPartyHash)"
    );
    bytes32 internal constant IDENTITY_TYPEHASH =
        keccak256("OIDCIdentity(bytes32 policyId,bytes32 subjectHash,bytes32 salt)");

    function policyId(bytes32 providerId, bytes32 audienceHash) internal pure returns (bytes32) {
        return policyId(providerId, audienceHash, bytes32(0));
    }

    /// @notice Derives a policy for a Google hybrid client with an exact `azp` client ID.
    /// @dev `authorizedPartyHash` is zero for ordinary Google and Apple policies.
    function policyId(bytes32 providerId, bytes32 audienceHash, bytes32 authorizedPartyHash)
        internal
        pure
        returns (bytes32)
    {
        if (providerId == bytes32(0) || audienceHash == bytes32(0)) revert InvalidIdentityInput();
        return keccak256(abi.encode(POLICY_TYPEHASH, providerId, audienceHash, authorizedPartyHash));
    }

    /// @notice Creates an account-scoped commitment to a stable OIDC subject.
    function identityCommitment(bytes32 policy, bytes32 subjectHash, bytes32 salt)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(IDENTITY_TYPEHASH, policy, subjectHash, salt));
    }
}
