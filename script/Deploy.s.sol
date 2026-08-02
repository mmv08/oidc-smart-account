// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Script, console2 } from "forge-std/Script.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";
import { IOIDCClaimVerifier } from "../src/IOIDCClaimVerifier.sol";
import { OIDCRecoveryController } from "../src/OIDCRecoveryController.sol";
import { OIDCAccountFactory } from "../src/OIDCAccountFactory.sol";

/// @title Core OIDC Account Deployment Script
/// @notice Deploys the recovery controller, account factory, and WebAuthn signer verifier.
/// @dev Reads the claim verifier and bounded timing parameters from the environment. The verifier is an
/// explicit trust boundary and may be the included Google verifier or another compatible implementation.
contract Deploy is Script {
    using SafeCast for uint256;

    uint256 private constant MIN_RECOVERY_DELAY = 1 hours;
    uint256 private constant MAX_RECOVERY_DELAY = 30 days;
    uint256 private constant MIN_RECOVERY_WINDOW = 1 days;
    uint256 private constant MAX_RECOVERY_WINDOW = 90 days;
    uint256 private constant MIN_CLAIM_AGE = 1 minutes;
    uint256 private constant MAX_CLAIM_AGE = 1 days;

    /// @dev Thrown when an environment duration falls outside the deployment safety bounds.
    /// @param variableName Name of the invalid environment variable.
    /// @param value Supplied duration in seconds.
    error UnsafeTimingConfiguration(string variableName, uint256 value);

    /// @notice Broadcasts the core protocol deployment from `DEPLOYER_PRIVATE_KEY`.
    /// @dev Reads `OIDC_CLAIM_VERIFIER`, `RECOVERY_DELAY`, `RECOVERY_WINDOW`, and `MAX_CLAIM_AGE`.
    /// @return controller Deployed recovery controller.
    /// @return factory Deployed deterministic account factory.
    /// @return webAuthnVerifier Deployed ERC-7913 WebAuthn signer verifier.
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
        uint64 recoveryDelay =
            _readDuration("RECOVERY_DELAY", MIN_RECOVERY_DELAY, MAX_RECOVERY_DELAY);
        uint64 recoveryWindow =
            _readDuration("RECOVERY_WINDOW", MIN_RECOVERY_WINDOW, MAX_RECOVERY_WINDOW);
        uint64 maxClaimAge = _readDuration("MAX_CLAIM_AGE", MIN_CLAIM_AGE, MAX_CLAIM_AGE);

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

    /// @dev Reads a duration from the environment and enforces inclusive deployment bounds.
    /// @param variableName Environment variable to read.
    /// @param minimum Minimum accepted value in seconds.
    /// @param maximum Maximum accepted value in seconds.
    /// @return duration Validated duration narrowed to `uint64`.
    function _readDuration(string memory variableName, uint256 minimum, uint256 maximum)
        private
        view
        returns (uint64)
    {
        uint256 value = vm.envUint(variableName);
        if (value < minimum || value > maximum) {
            revert UnsafeTimingConfiguration(variableName, value);
        }
        return value.toUint64();
    }
}
