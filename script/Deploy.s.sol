// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Script, console2 } from "forge-std/Script.sol";
import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";
import { IOIDCClaimVerifier } from "../src/IOIDCClaimVerifier.sol";
import { OIDCRecoveryController } from "../src/OIDCRecoveryController.sol";
import { OIDCAccountFactory } from "../src/OIDCAccountFactory.sol";

/// @notice Deploys the immutable on-chain identity protocol around an existing OIDC proof verifier.
/// @dev The verifier address is an explicit trust boundary. Its implementation is outside this project.
contract Deploy is Script {
    function run()
        external
        returns (
            OIDCRecoveryController controller,
            OIDCAccountFactory factory,
            ERC7913WebAuthnVerifier webAuthnVerifier
        )
    {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        IOIDCClaimVerifier claimVerifier = IOIDCClaimVerifier(vm.envAddress("OIDC_CLAIM_VERIFIER"));
        uint64 recoveryDelay = uint64(vm.envUint("RECOVERY_DELAY"));
        uint64 recoveryWindow = uint64(vm.envUint("RECOVERY_WINDOW"));
        uint64 maxClaimAge = uint64(vm.envUint("MAX_CLAIM_AGE"));

        vm.startBroadcast(deployerKey);
        controller =
            new OIDCRecoveryController(claimVerifier, recoveryDelay, recoveryWindow, maxClaimAge);
        factory = new OIDCAccountFactory(controller);
        webAuthnVerifier = new ERC7913WebAuthnVerifier();
        vm.stopBroadcast();

        console2.log("OIDCClaimVerifier", address(claimVerifier));
        console2.log("OIDCRecoveryController", address(controller));
        console2.log("OIDCAccountFactory", address(factory));
        console2.log("ERC7913WebAuthnVerifier", address(webAuthnVerifier));
    }
}
