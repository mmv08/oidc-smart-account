// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Script, console2 } from "forge-std/Script.sol";
import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";
import { ProviderKeyRegistry } from "../src/ProviderKeyRegistry.sol";
import { IdentityIntentVerifier } from "../src/IdentityIntentVerifier.sol";
import { IdentityRecoveryManager } from "../src/IdentityRecoveryManager.sol";
import { IdentityAccountFactory } from "../src/IdentityAccountFactory.sol";

/// @notice Deploys the non-upgradeable reference contracts and starts two-step governance transfer.
/// @dev GOVERNANCE_OWNER should be an audited timelock in production. It must call acceptOwnership on
///      ProviderKeyRegistry, IdentityIntentVerifier, and IdentityRecoveryManager after deployment.
contract Deploy is Script {
    function run()
        external
        returns (
            ProviderKeyRegistry registry,
            IdentityIntentVerifier intentVerifier,
            IdentityRecoveryManager recoveryManager,
            IdentityAccountFactory factory,
            ERC7913WebAuthnVerifier webAuthnVerifier
        )
    {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);
        address governanceOwner = vm.envAddress("GOVERNANCE_OWNER");
        address entryPoint = vm.envAddress("ENTRY_POINT");
        address[] memory attestors = vm.envAddress("ATTESTORS", ",");
        uint8 threshold = uint8(vm.envUint("ATTESTOR_THRESHOLD"));
        uint64 maxAttestationTTL = uint64(vm.envUint("MAX_ATTESTATION_TTL"));
        uint64 recoveryDelay = uint64(vm.envUint("RECOVERY_DELAY"));
        uint64 recoveryWindow = uint64(vm.envUint("RECOVERY_WINDOW"));

        vm.startBroadcast(deployerKey);
        registry = new ProviderKeyRegistry(deployer);
        intentVerifier = new IdentityIntentVerifier(
            registry, attestors, threshold, maxAttestationTTL, deployer
        );
        recoveryManager =
            new IdentityRecoveryManager(intentVerifier, recoveryDelay, recoveryWindow, deployer);
        webAuthnVerifier = new ERC7913WebAuthnVerifier();
        recoveryManager.setSignerVerifierPolicy(address(webAuthnVerifier), true);
        factory = new IdentityAccountFactory(entryPoint, recoveryManager, intentVerifier);

        if (governanceOwner != deployer) {
            registry.transferOwnership(governanceOwner);
            intentVerifier.transferOwnership(governanceOwner);
            recoveryManager.transferOwnership(governanceOwner);
        }
        vm.stopBroadcast();

        console2.log("ProviderKeyRegistry", address(registry));
        console2.log("IdentityIntentVerifier", address(intentVerifier));
        console2.log("IdentityRecoveryManager", address(recoveryManager));
        console2.log("IdentityAccountFactory", address(factory));
        console2.log("ERC7913WebAuthnVerifier", address(webAuthnVerifier));
        if (governanceOwner != deployer) {
            console2.log("Pending governance owner (must accept ownership)", governanceOwner);
        }
    }
}
