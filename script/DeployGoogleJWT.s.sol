// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Script, console2 } from "forge-std/Script.sol";
import { GoogleKeyRegistry } from "../src/GoogleKeyRegistry.sol";
import { GoogleJWTVerifier } from "../src/GoogleJWTVerifier.sol";

/// @notice Deploys the direct Google JWT adapter and its explicitly trusted key updater.
contract DeployGoogleJWT is Script {
    function run() external returns (GoogleKeyRegistry registry, GoogleJWTVerifier verifier) {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address updater = vm.envAddress("GOOGLE_KEY_UPDATER");
        string memory clientId = vm.envString("GOOGLE_CLIENT_ID");
        string memory authorizedParty = vm.envOr("GOOGLE_AUTHORIZED_PARTY", string(""));

        vm.startBroadcast(deployerKey);
        registry = new GoogleKeyRegistry(updater);
        verifier = new GoogleJWTVerifier(registry, clientId, authorizedParty);
        vm.stopBroadcast();

        console2.log("GoogleKeyRegistry", address(registry));
        console2.log("GoogleJWTVerifier", address(verifier));
        console2.logBytes32(verifier.providerPolicyId());
    }
}
