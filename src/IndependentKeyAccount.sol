// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {
    MultiSignerERC7913
} from "@openzeppelin/contracts/utils/cryptography/signers/MultiSignerERC7913.sol";

/// @notice Smart account controlled directly by independent ERC-7913 signers.
/// @dev Address signers may call directly. Address-less signers authorize EIP-712 executions that
///      any untrusted relayer can submit. OIDC can only reach the narrow recovery functions.
contract IndependentKeyAccount is EIP712, ReentrancyGuard, MultiSignerERC7913, IERC1271 {
    uint256 public constant MAX_SIGNERS = 16;
    bytes32 public constant EXECUTION_TYPEHASH = keccak256(
        "Execution(address target,uint256 value,bytes32 dataHash,uint256 nonce,uint64 deadline)"
    );

    address public immutable recoveryManager;
    bytes32 public immutable identityCommitment;
    uint256 public executionNonce;
    bool public recoveryEnabled = true;

    event Executed(address indexed target, uint256 value, bytes data);
    event RecoveryDisabled();

    error InvalidConfiguration();
    error InvalidSignerEncoding(bytes signer);
    error TooManySigners();
    error UnauthorizedSigner(address caller);
    error UnauthorizedRecoveryManager(address caller);
    error RecoveryIsDisabled();
    error InvalidTarget();
    error InvalidExecutionNonce(uint256 supplied, uint256 expected);
    error ExecutionExpired(uint64 deadline);
    error InvalidExecutionSignature();
    error ExecutionFailed();

    constructor(address recoveryManager_, bytes32 identityCommitment_, bytes memory initialSigner)
        EIP712("IndependentKeyAccount", "1")
        MultiSignerERC7913(_singleton(initialSigner), 1)
    {
        if (recoveryManager_ == address(0) || identityCommitment_ == bytes32(0)) {
            revert InvalidConfiguration();
        }
        recoveryManager = recoveryManager_;
        identityCommitment = identityCommitment_;
        _validateSigner(initialSigner);
    }

    modifier onlySignerOrSelf() {
        if (msg.sender != address(this) && !isSigner(abi.encodePacked(msg.sender))) {
            revert UnauthorizedSigner(msg.sender);
        }
        _;
    }

    modifier onlyRecoveryManager() {
        if (msg.sender != recoveryManager) revert UnauthorizedRecoveryManager(msg.sender);
        if (!recoveryEnabled) revert RecoveryIsDisabled();
        _;
    }

    receive() external payable { }

    /// @notice Executes directly when called by an installed 20-byte address signer.
    /// @dev Address-less signers use executeSigned instead because they cannot originate an EVM call.
    function execute(address target, uint256 value, bytes calldata data)
        external
        nonReentrant
        onlySignerOrSelf
        returns (bytes memory)
    {
        return _execute(target, value, data);
    }

    /// @notice Executes an exact EIP-712 request authorized by the installed ERC-7913 signer set.
    /// @dev Any address may relay this call. The relayer has no authority over its signed fields.
    function executeSigned(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        uint64 deadline,
        bytes calldata signature
    ) external nonReentrant returns (bytes memory) {
        uint256 expectedNonce = executionNonce;
        if (nonce != expectedNonce) revert InvalidExecutionNonce(nonce, expectedNonce);
        if (block.timestamp > deadline) revert ExecutionExpired(deadline);
        bytes32 digest = hashExecution(target, value, data, nonce, deadline);
        if (!_rawSignatureValidation(digest, signature)) revert InvalidExecutionSignature();

        executionNonce = expectedNonce + 1;
        return _execute(target, value, data);
    }

    /// @notice Returns the EIP-712 digest signed for a relayed execution.
    /// @dev The EIP-712 domain additionally binds the current chain and this exact account address.
    function hashExecution(
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint64 deadline
    ) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(EXECUTION_TYPEHASH, target, value, keccak256(data), nonce, deadline)
            )
        );
    }

    function addSigner(bytes calldata signer) external onlySignerOrSelf {
        _addOne(signer);
    }

    function removeSigner(bytes calldata signer) external onlySignerOrSelf {
        bytes[] memory signers = _singleton(signer);
        _removeSigners(signers);
    }

    function disableRecovery() external onlySignerOrSelf {
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
        // Add before remove so threshold 1 is never transiently unreachable; the transition is atomic.
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

    function _execute(address target, uint256 value, bytes calldata data)
        private
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
