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

/// @notice Deploys the immutable on-chain identity protocol around an existing OIDC proof verifier.
/// @dev The verifier address is an explicit trust boundary; it may be the included direct Google
/// verifier or another independently reviewed adapter.
contract Deploy is Script {
    using SafeCast for uint256;

    uint256 private constant MIN_RECOVERY_DELAY = 1 hours;
    uint256 private constant MAX_RECOVERY_DELAY = 30 days;
    uint256 private constant MIN_RECOVERY_WINDOW = 1 days;
    uint256 private constant MAX_RECOVERY_WINDOW = 90 days;
    uint256 private constant MIN_CLAIM_AGE = 1 minutes;
    uint256 private constant MAX_CLAIM_AGE = 1 days;

    error UnsafeTimingConfiguration(string variableName, uint256 value);

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
