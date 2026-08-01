// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @notice A small account controlled by one independent ERC-7913-compatible signer.
/// @dev OIDC never authorizes ordinary execution. It can only reach replaceSignerFromIdentity.
contract OIDCAccount is EIP712, ReentrancyGuard, IERC1271 {
    using SignatureChecker for bytes;

    bytes32 public constant EXECUTION_TYPEHASH = keccak256(
        "Execution(address target,uint256 value,bytes32 dataHash,uint256 signerEpoch,uint256 nonce,uint64 deadline)"
    );

    address public immutable identityController;
    bytes32 public immutable providerPolicyId;
    bytes32 public immutable identityCommitment;

    bytes private _signer;
    uint256 public signerEpoch;
    uint256 public executionNonce;
    bool public identityRecoveryEnabled = true;

    event Executed(address indexed target, uint256 value, bytes data);
    event SignerRotated(bytes32 indexed oldSignerHash, uint256 indexed newSignerEpoch, bytes newSigner);
    event IdentityRecoveryDisabled();

    error InvalidConfiguration();
    error InvalidSigner(bytes signer);
    error UnauthorizedSigner(address caller);
    error UnauthorizedIdentityController(address caller);
    error IdentityRecoveryIsDisabled();
    error StaleSigner();
    error InvalidTarget();
    error InvalidExecutionNonce(uint256 supplied, uint256 expected);
    error ExecutionExpired(uint64 deadline);
    error InvalidExecutionSignature();
    error ExecutionFailed();

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

    receive() external payable { }

    modifier onlySignerOrSelf() {
        if (msg.sender != address(this) && !_isDirectSigner(msg.sender)) {
            revert UnauthorizedSigner(msg.sender);
        }
        _;
    }

    function signer() external view returns (bytes memory) {
        return _signer;
    }

    function signerHash() public view returns (bytes32) {
        return keccak256(_signer);
    }

    function execute(address target, uint256 value, bytes calldata data)
        external
        nonReentrant
        onlySignerOrSelf
        returns (bytes memory)
    {
        return _execute(target, value, data);
    }

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
                    EXECUTION_TYPEHASH,
                    target,
                    value,
                    keccak256(data),
                    signerEpoch,
                    nonce,
                    deadline
                )
            )
        );
    }

    function rotateSigner(bytes calldata newSigner) external onlySignerOrSelf {
        _replaceSigner(signerHash(), signerEpoch, newSigner);
    }

    function disableIdentityRecovery() external onlySignerOrSelf {
        identityRecoveryEnabled = false;
        emit IdentityRecoveryDisabled();
    }

    /// @notice The identity controller's only account capability: replace one exact current signer.
    function replaceSignerFromIdentity(
        bytes32 expectedSignerHash,
        uint256 expectedSignerEpoch,
        bytes calldata newSigner
    ) external {
        if (msg.sender != identityController) revert UnauthorizedIdentityController(msg.sender);
        if (!identityRecoveryEnabled) revert IdentityRecoveryIsDisabled();
        _replaceSigner(expectedSignerHash, expectedSignerEpoch, newSigner);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        return _signer.isValidSignatureNow(hash, signature)
            ? IERC1271.isValidSignature.selector
            : bytes4(0xffffffff);
    }

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

    function _isDirectSigner(address caller) private view returns (bool) {
        return _signer.length == 20 && address(bytes20(_signer)) == caller;
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
}
