// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Account } from "@openzeppelin/contracts/account/Account.sol";
import { IEntryPoint } from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {
    MultiSignerERC7913
} from "@openzeppelin/contracts/utils/cryptography/signers/MultiSignerERC7913.sol";

/// @notice Immutable ERC-4337 account whose ordinary authorization is independent of OIDC infrastructure.
/// @dev OIDC can only reach the narrow recovery functions through the immutable recovery manager.
contract IndependentKeyAccount is Account, MultiSignerERC7913, IERC1271 {
    uint256 public constant MAX_SIGNERS = 16;

    IEntryPoint private immutable _entryPoint;
    address public immutable recoveryManager;
    bytes32 public immutable identityCommitment;
    bool public recoveryEnabled = true;

    event Executed(address indexed target, uint256 value, bytes data);
    event RecoveryDisabled();

    error InvalidConfiguration();
    error InvalidSignerEncoding(bytes signer);
    error TooManySigners();
    error UnauthorizedRecoveryManager(address caller);
    error RecoveryIsDisabled();
    error InvalidTarget();
    error ExecutionFailed();

    constructor(
        address entryPoint_,
        address recoveryManager_,
        bytes32 identityCommitment_,
        bytes memory initialSigner
    ) MultiSignerERC7913(_singleton(initialSigner), 1) {
        if (
            entryPoint_ == address(0) || recoveryManager_ == address(0)
                || identityCommitment_ == bytes32(0)
        ) {
            revert InvalidConfiguration();
        }
        _entryPoint = IEntryPoint(entryPoint_);
        recoveryManager = recoveryManager_;
        identityCommitment = identityCommitment_;
        _validateSigner(initialSigner);
    }

    modifier onlyRecoveryManager() {
        if (msg.sender != recoveryManager) revert UnauthorizedRecoveryManager(msg.sender);
        if (!recoveryEnabled) revert RecoveryIsDisabled();
        _;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    /// @notice Arbitrary ordinary execution; authorization is exclusively EntryPoint/self signer authorization.
    function execute(address target, uint256 value, bytes calldata data)
        external
        onlyEntryPointOrSelf
        returns (bytes memory)
    {
        if (target == address(0)) revert InvalidTarget();
        (bool success, bytes memory result) = target.call{ value: value }(data);
        if (!success) {
            if (result.length == 0) revert ExecutionFailed();
            assembly ("memory-safe") {
                revert(add(result, 0x20), mload(result))
            }
        }
        emit Executed(target, value, data);
        return result;
    }

    function addSigner(bytes calldata signer) external onlyEntryPointOrSelf {
        _addOne(signer);
    }

    function removeSigner(bytes calldata signer) external onlyEntryPointOrSelf {
        bytes[] memory signers = _singleton(signer);
        _removeSigners(signers);
    }

    function disableRecovery() external onlyEntryPointOrSelf {
        recoveryEnabled = false;
        emit RecoveryDisabled();
    }

    function recoveryAddSigner(bytes calldata signer) external onlyRecoveryManager {
        _addOne(signer);
    }

    function recoveryReplaceSigner(bytes calldata currentSigner, bytes calldata newSigner)
        external
        onlyRecoveryManager
    {
        _validateSigner(newSigner);
        if (keccak256(currentSigner) == keccak256(newSigner)) {
            revert InvalidSignerEncoding(newSigner);
        }
        // Add before remove so threshold 1 is never transiently unreachable; the whole transition is atomic.
        bytes[] memory additions = _singleton(newSigner);
        _addSigners(additions);
        bytes[] memory removals = _singleton(currentSigner);
        _removeSigners(removals);
    }

    /// @notice Canonical hash of the complete signer set, independent of EnumerableSet ordering.
    function signerSetHash() public view returns (bytes32) {
        bytes[] memory signers = getSigners(0, type(uint64).max);
        bytes32[] memory ids = new bytes32[](signers.length);
        for (uint256 i; i < signers.length; ++i) {
            ids[i] = keccak256(signers[i]);
        }
        for (uint256 i = 1; i < ids.length; ++i) {
            bytes32 value = ids[i];
            uint256 j = i;
            while (j > 0 && ids[j - 1] > value) {
                ids[j] = ids[j - 1];
                --j;
            }
            ids[j] = value;
        }
        return keccak256(abi.encode(ids));
    }

    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        return _rawSignatureValidation(hash, signature)
            ? IERC1271.isValidSignature.selector
            : bytes4(0xffffffff);
    }

    function _addOne(bytes memory signer) private {
        if (getSignerCount() >= MAX_SIGNERS) revert TooManySigners();
        _validateSigner(signer);
        _addSigners(_singleton(signer));
    }

    function _validateSigner(bytes memory signer) internal view {
        if (signer.length < 20) revert InvalidSignerEncoding(signer);
        address verifier = address(bytes20(signer));
        // Reserve the low address range: it includes current and future protocol/precompile addresses.
        if (uint160(verifier) <= 0xff || verifier == address(this)) {
            revert InvalidSignerEncoding(signer);
        }
    }

    function _singleton(bytes memory signer) private pure returns (bytes[] memory result) {
        result = new bytes[](1);
        result[0] = signer;
    }
}
