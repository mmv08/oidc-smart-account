// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { LowLevelCall } from "@openzeppelin/contracts/utils/LowLevelCall.sol";

/// @title OIDC-Recoverable Account
/// @notice Executes calls for one signer and allows one configured controller to replace that signer.
/// @dev Routine execution is independent of OIDC. The controller is a signer-replacement trust boundary;
/// the included `OIDCRecoveryController` enforces delayed, action-bound recovery.
contract OIDCAccount is EIP712, ReentrancyGuard, IERC1271 {
    using SignatureChecker for bytes;

    /// @dev EIP-712 type hash for relayed account execution.
    bytes32 public constant EXECUTION_TYPEHASH = keccak256(
        "Execution(address target,uint256 value,bytes32 dataHash,uint256 signerEpoch,uint256 nonce,uint64 deadline)"
    );

    /// @notice Controller authorized to replace the signer while identity recovery remains enabled.
    address public immutable identityController;
    /// @notice Immutable OIDC provider and client policy bound to this account.
    bytes32 public immutable providerPolicyId;
    /// @notice Immutable commitment to this account's provider subject and identity salt.
    bytes32 public immutable identityCommitment;

    /// @dev Signer encoding accepted by OpenZeppelin's ERC-7913-aware `SignatureChecker`.
    bytes private _signer;
    /// @notice Monotonic signer version included in every signed execution digest.
    uint256 public signerEpoch;
    /// @notice Sequential nonce consumed by successful relayed executions.
    uint256 public executionNonce;
    /// @notice Whether the identity controller may still replace the signer.
    bool public identityRecoveryEnabled = true;

    /// @dev Emitted after an account call completes successfully.
    /// @param target Contract or account called by this account.
    /// @param value Ether sent with the call.
    /// @param data Calldata sent with the call.
    event Executed(address indexed target, uint256 value, bytes data);
    /// @dev Emitted after the signer is replaced and the signer epoch increments.
    /// @param oldSignerHash Keccak-256 hash of the previous signer encoding.
    /// @param newSignerEpoch Epoch assigned to `newSigner`.
    /// @param newSigner Complete new signer encoding.
    event SignerRotated(
        bytes32 indexed oldSignerHash, uint256 indexed newSignerEpoch, bytes newSigner
    );
    /// @dev Emitted when identity recovery is disabled permanently.
    event IdentityRecoveryDisabled();

    /// @dev Thrown when immutable account configuration is invalid.
    error InvalidConfiguration();
    /// @dev Thrown when a signer encoding is malformed, unchanged, or unsupported.
    /// @param signer Rejected signer encoding.
    error InvalidSigner(bytes signer);
    /// @dev Thrown when `caller` is neither the direct signer nor the account itself.
    /// @param caller Unauthorized caller.
    error UnauthorizedSigner(address caller);
    /// @dev Thrown when a caller other than `identityController` requests identity recovery.
    /// @param caller Unauthorized caller.
    error UnauthorizedIdentityController(address caller);
    /// @dev Thrown when identity recovery has been disabled permanently.
    error IdentityRecoveryIsDisabled();
    /// @dev Thrown when signer hash or epoch no longer matches the authorized state.
    error StaleSigner();
    /// @dev Thrown when an execution targets the zero address.
    error InvalidTarget();
    /// @dev Thrown when a relayed execution does not use the current sequential nonce.
    /// @param supplied Nonce supplied by the relayer.
    /// @param expected Current account execution nonce.
    error InvalidExecutionNonce(uint256 supplied, uint256 expected);
    /// @dev Thrown when the relayed execution deadline has passed.
    /// @param deadline Expired signature deadline.
    error ExecutionExpired(uint64 deadline);
    /// @dev Thrown when the current signer does not validate a relayed execution signature.
    error InvalidExecutionSignature();
    /// @dev Thrown when a target call fails without revert data.
    error ExecutionFailed();

    /// @param identityController_ Controller trusted to authorize identity-based signer replacements.
    /// @param providerPolicyId_ Immutable provider/client policy identifier.
    /// @param identityCommitment_ Immutable commitment to the provider subject and identity salt.
    /// @param initialSigner Initial 20-byte address signer or ERC-7913 verifier-and-key encoding.
    constructor(
        address identityController_,
        bytes32 providerPolicyId_,
        bytes32 identityCommitment_,
        bytes memory initialSigner
    ) EIP712("OIDCAccount", "1") {
        if (
            identityController_ == address(0) || providerPolicyId_ == bytes32(0)
                || identityCommitment_ == bytes32(0)
        ) revert InvalidConfiguration();
        identityController = identityController_;
        providerPolicyId = providerPolicyId_;
        identityCommitment = identityCommitment_;
        _setSigner(initialSigner);
    }

    /// @dev Allows the account to receive Ether for later execution.
    receive() external payable { }

    /// @dev Restricts direct management calls to an address signer or an account self-call. An
    /// addressless ERC-7913 signer uses `executeSigned`, which can call the account itself.
    modifier onlySignerOrSelf() {
        if (msg.sender != address(this) && !_isDirectSigner(msg.sender)) {
            revert UnauthorizedSigner(msg.sender);
        }
        _;
    }

    /// @notice Returns the complete current signer encoding.
    /// @return Current 20-byte address signer or ERC-7913 verifier-and-key encoding.
    function signer() external view returns (bytes memory) {
        return _signer;
    }

    /// @notice Returns the hash used to bind management actions to the current signer.
    /// @return Keccak-256 hash of the complete signer encoding.
    function signerHash() public view returns (bytes32) {
        return keccak256(_signer);
    }

    /// @notice Executes one call authorized directly by an address signer or by the account itself.
    /// @dev Addressless ERC-7913 signers must use `executeSigned`. Target revert data is propagated.
    /// @param target Address called by the account.
    /// @param value Ether sent with the call.
    /// @param data Calldata sent with the call.
    /// @return result Return data from `target`.
    function execute(address target, uint256 value, bytes calldata data)
        external
        nonReentrant
        onlySignerOrSelf
        returns (bytes memory)
    {
        return _execute(target, value, data);
    }

    /// @notice Executes one EIP-712 call authorized by the current signer and relayed by any caller.
    /// @dev The digest binds the account, chain, target, value, calldata hash, signer epoch, nonce, and
    /// deadline. The nonce increment reverts with the target call if execution fails.
    /// @param target Address called by the account.
    /// @param value Ether sent with the call.
    /// @param data Calldata sent with the call.
    /// @param nonce Current `executionNonce`.
    /// @param deadline Last timestamp at which the signature is accepted.
    /// @param signature Signature validated against the current signer encoding.
    /// @return result Return data from `target`.
    function executeSigned(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        uint64 deadline,
        bytes calldata signature
    ) external nonReentrant returns (bytes memory) {
        uint256 expected = executionNonce;
        if (nonce != expected) revert InvalidExecutionNonce(nonce, expected);
        if (block.timestamp > deadline) revert ExecutionExpired(deadline);

        bytes32 digest = hashExecution(target, value, data, nonce, deadline);
        if (!_signer.isValidSignatureNow(digest, signature)) {
            revert InvalidExecutionSignature();
        }

        executionNonce = expected + 1;
        return _execute(target, value, data);
    }

    /// @notice Computes the EIP-712 digest for one relayed execution.
    /// @dev Uses the current signer epoch, preventing signatures from becoming valid again after an
    /// A-to-B-to-A signer rotation.
    /// @param target Address to call.
    /// @param value Ether to send.
    /// @param data Calldata to send.
    /// @param nonce Expected sequential execution nonce.
    /// @param deadline Signature deadline.
    /// @return digest EIP-712 execution digest for this account and chain.
    function hashExecution(
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint64 deadline
    ) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    EXECUTION_TYPEHASH, target, value, keccak256(data), signerEpoch, nonce, deadline
                )
            )
        );
    }

    /// @notice Replaces the signer under authority of the current signer.
    /// @dev The signer epoch increments on every successful replacement.
    /// @param newSigner Complete 20-byte address signer or ERC-7913 verifier-and-key encoding.
    function rotateSigner(bytes calldata newSigner) external onlySignerOrSelf {
        _replaceSigner(signerHash(), signerEpoch, newSigner);
    }

    /// @notice Permanently disables identity-based signer recovery.
    /// @dev This operation is irreversible. Ordinary signer execution and rotation remain available.
    function disableIdentityRecovery() external onlySignerOrSelf {
        identityRecoveryEnabled = false;
        emit IdentityRecoveryDisabled();
    }

    /// @notice Replaces the signer at the request of the configured identity controller.
    /// @dev The account checks the caller, recovery-enabled state, current signer hash, and signer epoch.
    /// The controller is responsible for deciding whether the replacement is authorized.
    /// @param expectedSignerHash Signer hash captured when recovery was scheduled.
    /// @param expectedSignerEpoch Signer epoch captured when recovery was scheduled.
    /// @param newSigner Replacement 20-byte address signer or ERC-7913 verifier-and-key encoding.
    function replaceSignerFromIdentity(
        bytes32 expectedSignerHash,
        uint256 expectedSignerEpoch,
        bytes calldata newSigner
    ) external {
        if (msg.sender != identityController) {
            revert UnauthorizedIdentityController(msg.sender);
        }
        if (!identityRecoveryEnabled) revert IdentityRecoveryIsDisabled();
        _replaceSigner(expectedSignerHash, expectedSignerEpoch, newSigner);
    }

    /// @inheritdoc IERC1271
    /// @dev Delegates validation to the current signer encoding.
    /// @return ERC-1271 magic value on success, or `0xffffffff` on failure.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        return _signer.isValidSignatureNow(hash, signature)
            ? IERC1271.isValidSignature.selector
            : bytes4(0xffffffff);
    }

    /// @dev Replaces an exact signer state and advances the epoch.
    function _replaceSigner(
        bytes32 expectedSignerHash,
        uint256 expectedSignerEpoch,
        bytes memory newSigner
    ) private {
        bytes32 oldSignerHash = signerHash();
        if (oldSignerHash != expectedSignerHash || signerEpoch != expectedSignerEpoch) {
            revert StaleSigner();
        }
        if (keccak256(newSigner) == oldSignerHash) revert InvalidSigner(newSigner);
        _setSigner(newSigner);
        uint256 newSignerEpoch = signerEpoch + 1;
        signerEpoch = newSignerEpoch;
        emit SignerRotated(oldSignerHash, newSignerEpoch, newSigner);
    }

    /// @dev Validates and stores a 20-byte address signer or ERC-7913 signer encoding.
    function _setSigner(bytes memory newSigner) private {
        if (newSigner.length < 20) revert InvalidSigner(newSigner);
        address verifier = address(bytes20(newSigner));
        if (uint160(verifier) <= 0xff || verifier == address(this)) {
            revert InvalidSigner(newSigner);
        }
        if (newSigner.length > 20 && verifier.code.length == 0) {
            revert InvalidSigner(newSigner);
        }
        _signer = newSigner;
    }

    /// @dev Returns true only when the signer is encoded as the caller's 20-byte address.
    function _isDirectSigner(address caller) private view returns (bool) {
        return _signer.length == 20 && address(bytes20(_signer)) == caller;
    }

    /// @dev Calls `target`, propagates revert data, and emits the successful execution.
    function _execute(address target, uint256 value, bytes calldata data)
        private
        returns (bytes memory)
    {
        if (target == address(0)) revert InvalidTarget();
        (bool success, bytes memory result) = target.call{ value: value }(data);
        if (!success) {
            if (result.length == 0) revert ExecutionFailed();
            LowLevelCall.bubbleRevert(result);
        }
        emit Executed(target, value, data);
        return result;
    }
}
