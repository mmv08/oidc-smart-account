// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { OIDCIdentity } from "../src/OIDCIdentity.sol";

contract OIDCIdentityTest is Test {
    function test_googleAndAppleUseCanonicalIssuerHashes() public pure {
        assertEq(OIDCIdentity.GOOGLE_PROVIDER, keccak256(bytes("https://accounts.google.com")));
        assertEq(OIDCIdentity.APPLE_PROVIDER, keccak256(bytes("https://appleid.apple.com")));
    }

    function test_policyBindsProviderAndExactAudience() public pure {
        bytes32 googleAudience = keccak256(bytes("google-client-id.apps.googleusercontent.com"));
        bytes32 appleAudience = keccak256(bytes("com.example.web"));

        bytes32 googlePolicy = OIDCIdentity.policyId(OIDCIdentity.GOOGLE_PROVIDER, googleAudience);
        bytes32 applePolicy = OIDCIdentity.policyId(OIDCIdentity.APPLE_PROVIDER, appleAudience);

        assertNotEq(googlePolicy, applePolicy);
        assertNotEq(
            googlePolicy,
            OIDCIdentity.policyId(OIDCIdentity.GOOGLE_PROVIDER, keccak256(bytes("other-client")))
        );
    }

    function test_googleHybridPolicyBindsAuthorizedParty() public pure {
        bytes32 audience = keccak256("server.apps.googleusercontent.com");
        bytes32 authorizedParty = keccak256("android.apps.googleusercontent.com");

        assertNotEq(
            OIDCIdentity.policyId(OIDCIdentity.GOOGLE_PROVIDER, audience),
            OIDCIdentity.policyId(OIDCIdentity.GOOGLE_PROVIDER, audience, authorizedParty)
        );
    }

    function test_matchesTypeScriptApplePolicyAndIdentityVector() public pure {
        bytes32 policy = OIDCIdentity.policyId(
            OIDCIdentity.APPLE_PROVIDER,
            0xe39f7e5dbc0b82d2fdb2584d5088132a46c027a5bbc451416f63d85cf0d1b9d1
        );
        assertEq(policy, 0xe3c5dbf05f1a583c83a9570ac37062708e7d6b2e6c115b15b1b85cdaf6340f74);
        assertEq(
            OIDCIdentity.identityCommitment(
                policy,
                0xc4a2a5f55aec322a0762d3159f21753dbac0dd1b601ab22bca69273096a8d34a,
                bytes32(uint256(0x2222222222222222222222222222222222222222222222222222222222222222))
            ),
            0xc401ed12736235e53dd81955260dc3ac300bea63dd01e496fe23c370387650ba
        );
    }

    function test_identityCommitmentBindsPolicySubjectAndAccountSalt() public pure {
        bytes32 policy = OIDCIdentity.policyId(
            OIDCIdentity.GOOGLE_PROVIDER,
            keccak256(bytes("google-client-id.apps.googleusercontent.com"))
        );
        bytes32 subjectHash = keccak256(bytes("provider-stable-subject"));
        bytes32 salt = keccak256("account-private-identity-salt");

        bytes32 commitment = OIDCIdentity.identityCommitment(policy, subjectHash, salt);

        assertNotEq(
            commitment, OIDCIdentity.identityCommitment(policy, subjectHash, bytes32(uint256(1)))
        );
        assertNotEq(
            commitment,
            OIDCIdentity.identityCommitment(policy, keccak256(bytes("other-subject")), salt)
        );
    }
}
