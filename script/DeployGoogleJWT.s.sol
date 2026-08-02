// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Script, console2 } from "forge-std/Script.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { GoogleJWTVerifier } from "../src/GoogleJWTVerifier.sol";
import { TEEGoogleKeyUpdater } from "../src/TEEGoogleKeyUpdater.sol";

/// @title TEE-backed Google JWT Verifier Deployment Script
/// @notice Deploys the freshness-gated TEE key registry and direct RS256 verifier.
/// @dev The initial attestor must be enrolled only after independently verifying its AWS Nitro evidence.
contract DeployGoogleJWT is Script {
    using SafeCast for uint256;

    /// @notice Broadcasts the complete Google key-provenance deployment from `DEPLOYER_PRIVATE_KEY`.
    /// @dev The verifier consumes the updater directly; there is no bypassable raw registry.
    function run() external returns (TEEGoogleKeyUpdater updater, GoogleJWTVerifier verifier) {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address governance = vm.envAddress("TEE_GOVERNANCE");
        address guardian = vm.envAddress("TEE_GUARDIAN");
        uint64 rotationDelay = vm.envUint("TEE_ATTESTOR_ROTATION_DELAY").toUint64();
        uint64 maxObservationAge = vm.envUint("TEE_MAX_OBSERVATION_AGE").toUint64();
        uint64 maxRegistryStaleness = vm.envUint("TEE_MAX_REGISTRY_STALENESS").toUint64();
        string memory clientId = vm.envString("GOOGLE_CLIENT_ID");
        string memory authorizedParty = vm.envOr("GOOGLE_AUTHORIZED_PARTY", string(""));

        vm.startBroadcast(deployerKey);
        updater = new TEEGoogleKeyUpdater(
            governance, guardian, rotationDelay, maxObservationAge, maxRegistryStaleness
        );
        verifier = new GoogleJWTVerifier(updater, clientId, authorizedParty);
        vm.stopBroadcast();

        console2.log("TEEGoogleKeyUpdater (key registry)", address(updater));
        console2.log("GoogleJWTVerifier", address(verifier));
        console2.logBytes32(verifier.providerPolicyId());
    }
}
