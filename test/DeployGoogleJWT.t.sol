// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { DeployGoogleJWT } from "../script/DeployGoogleJWT.s.sol";
import { GoogleJWTVerifier } from "../src/GoogleJWTVerifier.sol";
import { TEEGoogleKeyUpdater } from "../src/TEEGoogleKeyUpdater.sol";

contract DeployGoogleJWTTest is Test {
    function test_deploysOneFreshnessGatedRegistryWithoutABypassStore() public {
        uint256 deployerKey = 0xA11CE;
        address governance = makeAddr("governance");
        address guardian = makeAddr("guardian");

        vm.setEnv("DEPLOYER_PRIVATE_KEY", vm.toString(deployerKey));
        vm.setEnv("TEE_GOVERNANCE", vm.toString(governance));
        vm.setEnv("TEE_GUARDIAN", vm.toString(guardian));
        vm.setEnv("TEE_ATTESTOR_ROTATION_DELAY", vm.toString(uint256(2 days)));
        vm.setEnv("TEE_MAX_OBSERVATION_AGE", vm.toString(uint256(15 minutes)));
        vm.setEnv("TEE_MAX_REGISTRY_STALENESS", vm.toString(uint256(24 hours)));
        vm.setEnv("GOOGLE_CLIENT_ID", "client.example.apps.googleusercontent.com");
        vm.setEnv("GOOGLE_AUTHORIZED_PARTY", "");

        DeployGoogleJWT script = new DeployGoogleJWT();
        (TEEGoogleKeyUpdater updater, GoogleJWTVerifier verifier) = script.run();

        assertEq(address(verifier.keyRegistry()), address(updater));
        assertEq(updater.owner(), governance);
        assertEq(updater.guardian(), guardian);
        assertEq(updater.attestor(), address(0));
        assertEq(updater.attestorEpoch(), 0);
    }
}
