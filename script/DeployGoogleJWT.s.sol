// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Script, console2 } from "forge-std/Script.sol";
import { GoogleKeyRegistry } from "../src/GoogleKeyRegistry.sol";
import { GoogleJWTVerifier } from "../src/GoogleJWTVerifier.sol";

/// @title Google JWT Verifier Deployment Script
/// @notice Deploys an empty Google key registry and its direct RS256 verifier.
/// @dev `GOOGLE_KEY_UPDATER` can authorize arbitrary signing keys. Add Google keys before using the verifier.
contract DeployGoogleJWT is Script {
    /// @notice Broadcasts the Google verifier deployment from `DEPLOYER_PRIVATE_KEY`.
    /// @dev Reads `GOOGLE_KEY_UPDATER`, `GOOGLE_CLIENT_ID`, and optional `GOOGLE_AUTHORIZED_PARTY`.
    /// @return registry Empty registry owned by the configured updater.
    /// @return verifier Verifier bound to the registry and immutable client policy.
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
