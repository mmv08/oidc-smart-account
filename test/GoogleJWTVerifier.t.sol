// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IOIDCClaimVerifier } from "../src/IOIDCClaimVerifier.sol";
import { OIDCIdentity } from "../src/OIDCIdentity.sol";
import { GoogleKeyRegistry } from "../src/GoogleKeyRegistry.sol";
import { GoogleJWTVerifier } from "../src/GoogleJWTVerifier.sol";

contract GoogleJWTVerifierTest is Test {
    string internal constant CLIENT_ID = "client.apps.googleusercontent.com";
    bytes32 internal constant KID_HASH = keccak256("test-google-key");
    bytes32 internal constant SALT = bytes32(uint256(0x7777));
    bytes32 internal constant NONCE =
        bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111));

    GoogleKeyRegistry internal registry;
    GoogleJWTVerifier internal verifier;
    string internal fixture;

    function setUp() public {
        fixture = vm.readFile("test/fixtures/google-jwt.json");
        registry = new GoogleKeyRegistry(address(this));
        registry.setKey(KID_HASH, vm.parseJsonBytes(fixture, ".modulus"), 1_699_999_900, 0);
        verifier = new GoogleJWTVerifier(registry, CLIENT_ID, "");
        vm.warp(1_700_000_100);
    }

    function test_verifiesRealRS256GoogleJWTIntoNormalizedClaim() public view {
        bytes memory jwt = bytes(vm.parseJsonString(fixture, ".valid"));
        IOIDCClaimVerifier.VerifiedOIDCClaim memory claim =
            verifier.verifyClaim(abi.encode(jwt, SALT));

        bytes32 policy = OIDCIdentity.policyId(
            keccak256("https://accounts.google.com"), keccak256(bytes(CLIENT_ID))
        );
        assertEq(claim.providerPolicyId, policy);
        assertEq(
            claim.identityCommitment,
            OIDCIdentity.identityCommitment(policy, keccak256("google-subject-123"), SALT)
        );
        assertEq(claim.nonce, NONCE);
        assertEq(claim.issuedAt, 1_700_000_000);
        assertEq(claim.expiresAt, 1_700_000_600);
    }

    function test_acceptsGoogleLegacyIssuerRepresentation() public view {
        IOIDCClaimVerifier.VerifiedOIDCClaim memory claim = verifier.verifyClaim(
            abi.encode(bytes(vm.parseJsonString(fixture, ".alternateIssuer")), SALT)
        );
        assertEq(claim.nonce, NONCE);
    }

    function test_rejectsSignedTokenForWrongAudience() public {
        vm.expectRevert(GoogleJWTVerifier.InvalidGoogleClaims.selector);
        verifier.verifyClaim(abi.encode(bytes(vm.parseJsonString(fixture, ".wrongAudience")), SALT));
    }

    function test_acceptsConfiguredGoogleHybridAudienceAndAzp() public {
        GoogleJWTVerifier hybridVerifier =
            new GoogleJWTVerifier(registry, CLIENT_ID, "mobile.apps.googleusercontent.com");
        IOIDCClaimVerifier.VerifiedOIDCClaim memory claim = hybridVerifier.verifyClaim(
            abi.encode(bytes(vm.parseJsonString(fixture, ".hybrid")), SALT)
        );
        assertEq(
            claim.providerPolicyId,
            OIDCIdentity.policyId(
                keccak256("https://accounts.google.com"),
                keccak256(bytes(CLIENT_ID)),
                keccak256("mobile.apps.googleusercontent.com")
            )
        );
    }

    function test_enforcesAzpAcrossOrdinaryAndHybridPolicies() public {
        GoogleJWTVerifier hybridVerifier =
            new GoogleJWTVerifier(registry, CLIENT_ID, "mobile.apps.googleusercontent.com");
        vm.expectRevert(GoogleJWTVerifier.InvalidGoogleClaims.selector);
        hybridVerifier.verifyClaim(abi.encode(bytes(vm.parseJsonString(fixture, ".valid")), SALT));

        vm.expectRevert(GoogleJWTVerifier.InvalidGoogleClaims.selector);
        verifier.verifyClaim(abi.encode(bytes(vm.parseJsonString(fixture, ".hybrid")), SALT));

        GoogleJWTVerifier ordinaryMobileVerifier =
            new GoogleJWTVerifier(registry, "mobile.apps.googleusercontent.com", "");
        IOIDCClaimVerifier.VerifiedOIDCClaim memory claim = ordinaryMobileVerifier.verifyClaim(
            abi.encode(bytes(vm.parseJsonString(fixture, ".hybrid")), SALT)
        );
        assertEq(
            claim.providerPolicyId,
            OIDCIdentity.policyId(
                keccak256("https://accounts.google.com"),
                keccak256("mobile.apps.googleusercontent.com")
            )
        );
    }

    function test_rejectsMultipleAudiencesWithoutAzp() public {
        vm.expectRevert(GoogleJWTVerifier.InvalidGoogleClaims.selector);
        verifier.verifyClaim(
            abi.encode(bytes(vm.parseJsonString(fixture, ".multiAudienceWithoutAzp")), SALT)
        );
    }

    function test_rejectsTokenBeforeNbf() public {
        vm.expectRevert(GoogleJWTVerifier.InvalidGoogleClaims.selector);
        verifier.verifyClaim(abi.encode(bytes(vm.parseJsonString(fixture, ".futureNbf")), SALT));
    }

    function test_rejectsOverlongSubject() public {
        vm.expectRevert();
        verifier.verifyClaim(
            abi.encode(bytes(vm.parseJsonString(fixture, ".overlongSubject")), SALT)
        );
    }

    function test_rejectsAlgorithmConfusionAndDuplicateProtectedAlgorithm() public {
        vm.expectRevert(GoogleJWTVerifier.UnsupportedAlgorithm.selector);
        verifier.verifyClaim(
            abi.encode(bytes(vm.parseJsonString(fixture, ".wrongAlgorithm")), SALT)
        );

        vm.expectRevert();
        verifier.verifyClaim(
            abi.encode(bytes(vm.parseJsonString(fixture, ".duplicateHeaderAlgorithm")), SALT)
        );
    }

    function test_rejectsDuplicateOrEscapedSecurityClaimNames() public {
        vm.expectRevert();
        verifier.verifyClaim(
            abi.encode(bytes(vm.parseJsonString(fixture, ".duplicateNonce")), SALT)
        );

        vm.expectRevert();
        verifier.verifyClaim(
            abi.encode(bytes(vm.parseJsonString(fixture, ".escapedAudienceKey")), SALT)
        );
    }

    function test_rejectsNonIntegerSecurityTimestamp() public {
        vm.expectRevert();
        verifier.verifyClaim(
            abi.encode(bytes(vm.parseJsonString(fixture, ".decimalIssuedAt")), SALT)
        );
    }

    function test_rejectsTamperedSignatureUnknownKeyAndInvalidKeyEpoch() public {
        bytes memory tampered = bytes(vm.parseJsonString(fixture, ".valid"));
        tampered[tampered.length - 1] =
            tampered[tampered.length - 1] == bytes1("A") ? bytes1("B") : bytes1("A");
        vm.expectRevert();
        verifier.verifyClaim(abi.encode(tampered, SALT));

        registry.removeKey(KID_HASH);
        vm.expectRevert(GoogleJWTVerifier.UnknownGoogleKey.selector);
        verifier.verifyClaim(abi.encode(bytes(vm.parseJsonString(fixture, ".valid")), SALT));

        registry.setKey(KID_HASH, vm.parseJsonBytes(fixture, ".modulus"), 1_700_000_001, 0);
        vm.expectRevert(GoogleJWTVerifier.InvalidGoogleClaims.selector);
        verifier.verifyClaim(abi.encode(bytes(vm.parseJsonString(fixture, ".valid")), SALT));
    }

    function test_registryUpdaterIsExplicitOwnerAndKeysAreConstrained() public {
        assertEq(vm.parseJsonBytes(fixture, ".exponent"), hex"010001");
        (bytes memory modulus, uint64 validAfter, uint64 validUntil) = registry.getKey(KID_HASH);
        assertEq(modulus, vm.parseJsonBytes(fixture, ".modulus"));
        assertEq(validAfter, 1_699_999_900);
        assertEq(validUntil, 0);

        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker)
        );
        registry.removeKey(KID_HASH);

        vm.expectRevert(GoogleKeyRegistry.InvalidKey.selector);
        registry.setKey(bytes32(0), new bytes(256), 0, 0);
        vm.expectRevert(GoogleKeyRegistry.InvalidKey.selector);
        registry.setKey(KID_HASH, new bytes(255), 0, 0);
        vm.expectRevert(GoogleKeyRegistry.InvalidKey.selector);
        registry.setKey(KID_HASH, new bytes(256), 10, 10);
    }

    function test_rejectsMalformedCompactJWTAndOversizedProofBeforeDecoding() public {
        vm.expectRevert(GoogleJWTVerifier.InvalidJWT.selector);
        verifier.verifyClaim(abi.encode(bytes("one.two.three.four"), SALT));

        uint256 maxProofLength = verifier.MAX_PROOF_LENGTH();
        vm.expectRevert(GoogleJWTVerifier.InvalidJWT.selector);
        verifier.verifyClaim(new bytes(maxProofLength + 1));
    }
}
