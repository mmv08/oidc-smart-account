// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { IERC7913SignatureVerifier } from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IOIDCClaimVerifier } from "../../src/IOIDCClaimVerifier.sol";

contract TestOIDCClaimVerifier is IOIDCClaimVerifier {
    VerifiedOIDCClaim private _claim;
    bool public shouldReject;

    function setClaim(VerifiedOIDCClaim memory claim) external {
        _claim = claim;
    }

    function setShouldReject(bool reject_) external {
        shouldReject = reject_;
    }

    function verifyClaim(bytes calldata) external view returns (VerifiedOIDCClaim memory) {
        require(!shouldReject, "proof rejected");
        return _claim;
    }
}

contract TestERC7913Verifier is IERC7913SignatureVerifier {
    function verify(bytes calldata key, bytes32 hash, bytes calldata signature)
        external
        pure
        returns (bytes4)
    {
        if (key.length != 20) return bytes4(0xffffffff);
        address expected = address(bytes20(key));
        (address recovered, ECDSA.RecoverError recoverError,) = ECDSA.tryRecover(hash, signature);
        return recoverError == ECDSA.RecoverError.NoError && recovered == expected
            ? IERC7913SignatureVerifier.verify.selector
            : bytes4(0xffffffff);
    }
}

contract RevocableTestERC7913Verifier is IERC7913SignatureVerifier {
    bool public enabled = true;

    function setEnabled(bool enabled_) external {
        enabled = enabled_;
    }

    function verify(bytes calldata key, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        if (!enabled || key.length != 20) return bytes4(0xffffffff);
        address expected = address(bytes20(key));
        (address recovered, ECDSA.RecoverError recoverError,) = ECDSA.tryRecover(hash, signature);
        return recoverError == ECDSA.RecoverError.NoError && recovered == expected
            ? IERC7913SignatureVerifier.verify.selector
            : bytes4(0xffffffff);
    }
}
