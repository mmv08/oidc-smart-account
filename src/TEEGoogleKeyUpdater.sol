// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { IGoogleKeyRegistry } from "./IGoogleKeyRegistry.sol";

/// @title TEE-backed Google Key Updater
/// @notice Publishes complete Google JWKS snapshots signed by an enrolled TEE application key.
/// @dev Native TEE attestation is verified by a public off-chain enrollment ceremony. This contract
/// verifies the resulting application-key signature, not AWS attestation itself. Every JWT verifier must
/// read this contract so that pause and freshness checks cannot be bypassed.
contract TEEGoogleKeyUpdater is Ownable, EIP712, IGoogleKeyRegistry {
    using SafeCast for uint256;

    /// @notice Google RSA key material contained in one observed JWKS snapshot.
    struct GoogleKey {
        bytes32 kidHash;
        bytes modulus;
    }

    struct StoredKey {
        bytes modulus;
        uint64 validAfter;
        uint64 validUntil;
    }

    bytes32 public constant GOOGLE_KEY_TYPEHASH =
        keccak256("GoogleKey(bytes32 kidHash,bytes modulus)");
    bytes32 public constant GOOGLE_KEY_SET_TYPEHASH = keccak256(
        "GoogleKeySet(bytes32 keysHash,uint64 fetchedAt,uint64 attestorEpoch,uint256 nonce)"
    );
    uint64 public constant MAX_FUTURE_SKEW = 5 minutes;
    uint64 public constant MIN_ROTATION_DELAY = 1 days;
    uint64 public constant MIN_OBSERVATION_AGE = 1 minutes;
    uint64 public constant MAX_OBSERVATION_AGE = 1 hours;
    uint64 public constant MIN_REGISTRY_STALENESS = 1 hours;
    uint64 public constant MAX_REGISTRY_STALENESS = 7 days;
    uint256 public constant MAX_KEYS = 8;

    address public immutable guardian;
    uint64 public immutable attestorRotationDelay;
    uint64 public immutable maxObservationAge;
    uint64 public immutable maxRegistryStaleness;

    address public attestor;
    uint64 public attestorEpoch;
    uint64 public lastFetchedAt;
    uint256 public updateNonce;
    address public pendingAttestor;
    uint64 public pendingAttestorReadyAt;
    uint64 public unpauseReadyAt;
    bool public paused;
    mapping(bytes32 kidHash => StoredKey) private _keys;
    bytes32[] private _activeKidHashes;

    error InvalidAttestorSignature();
    error InvalidAttestor();
    error InvalidConfiguration();
    error UnauthorizedPause();
    error InvalidNonce(uint256 expected, uint256 actual);
    error InvalidObservationTime();
    error NonMonotonicObservation();
    error InvalidKeySet();
    error ChangedKeyMaterial(bytes32 kidHash);
    error NoPendingAttestorRotation();
    error AttestorRotationNotReady();
    error NoPendingUnpause();
    error UnpauseNotReady();
    error FreshHeartbeatRequired();

    event AttestorRotationScheduled(address indexed attestor, uint64 readyAt);
    event AttestorRotationCancelled(address indexed attestor);
    event AttestorRotated(
        address indexed previousAttestor, address indexed newAttestor, uint64 epoch
    );
    event UnpauseScheduled(uint64 readyAt);
    event UnpauseCancelled();
    event PauseStatusChanged(bool paused, address indexed account);
    event KeySetApplied(bytes32 indexed keySetHash, uint64 fetchedAt, uint64 epoch, uint256 nonce);

    /// @param initialOwner Threshold governance that may schedule attestors and delayed unpause.
    /// @param initialGuardian Emergency address allowed only to pause and cancel pending rotation.
    /// @param rotationDelay_ Delay applied to both signer rotation and unpause.
    /// @param maxObservationAge_ Maximum accepted age of a newly submitted observation.
    /// @param maxRegistryStaleness_ Maximum age of the last observation during key consumption.
    constructor(
        address initialOwner,
        address initialGuardian,
        uint64 rotationDelay_,
        uint64 maxObservationAge_,
        uint64 maxRegistryStaleness_
    ) EIP712("TEEGoogleKeyUpdater", "1") Ownable(initialOwner) {
        if (
            initialOwner == address(0) || initialGuardian == address(0)
                || rotationDelay_ < MIN_ROTATION_DELAY || maxObservationAge_ < MIN_OBSERVATION_AGE
                || maxObservationAge_ > MAX_OBSERVATION_AGE
                || maxRegistryStaleness_ < MIN_REGISTRY_STALENESS
                || maxRegistryStaleness_ > MAX_REGISTRY_STALENESS
                || maxRegistryStaleness_ <= maxObservationAge_
        ) revert InvalidConfiguration();
        guardian = initialGuardian;
        attestorRotationDelay = rotationDelay_;
        maxObservationAge = maxObservationAge_;
        maxRegistryStaleness = maxRegistryStaleness_;
    }

    /// @notice Stops Google-key consumption immediately. Governance or the guardian may pause.
    function pause() external {
        if (msg.sender != owner() && msg.sender != guardian) revert UnauthorizedPause();
        paused = true;
        delete unpauseReadyAt;
        emit PauseStatusChanged(true, msg.sender);
    }

    /// @notice Schedules key consumption to resume after the same delay used for attestor rotation.
    function scheduleUnpause() external onlyOwner {
        if (!paused) revert NoPendingUnpause();
        uint64 readyAt = (block.timestamp + attestorRotationDelay).toUint64();
        unpauseReadyAt = readyAt;
        emit UnpauseScheduled(readyAt);
    }

    /// @notice Cancels a pending unpause. Governance or the guardian may cancel.
    function cancelUnpause() external {
        if (msg.sender != owner() && msg.sender != guardian) revert UnauthorizedPause();
        if (unpauseReadyAt == 0) revert NoPendingUnpause();
        delete unpauseReadyAt;
        emit UnpauseCancelled();
    }

    /// @notice Resumes key consumption after the scheduled delay. Anyone may finalize.
    function finalizeUnpause() external {
        uint64 readyAt = unpauseReadyAt;
        if (readyAt == 0) revert NoPendingUnpause();
        if (block.timestamp < readyAt) revert UnpauseNotReady();
        if (lastFetchedAt < readyAt) revert FreshHeartbeatRequired();
        delete unpauseReadyAt;
        paused = false;
        emit PauseStatusChanged(false, msg.sender);
    }

    /// @notice Schedules a replacement TEE application key after the immutable governance delay.
    function scheduleAttestor(address newAttestor) external onlyOwner {
        if (newAttestor == address(0) || newAttestor == attestor) revert InvalidAttestor();
        uint64 readyAt = (block.timestamp + attestorRotationDelay).toUint64();
        pendingAttestor = newAttestor;
        pendingAttestorReadyAt = readyAt;
        emit AttestorRotationScheduled(newAttestor, readyAt);
    }

    /// @notice Cancels a pending TEE application-key rotation. Governance or guardian may cancel.
    function cancelAttestorRotation() external {
        if (msg.sender != owner() && msg.sender != guardian) revert UnauthorizedPause();
        address cancelledAttestor = pendingAttestor;
        if (cancelledAttestor == address(0)) revert NoPendingAttestorRotation();
        delete pendingAttestor;
        delete pendingAttestorReadyAt;
        emit AttestorRotationCancelled(cancelledAttestor);
    }

    /// @notice Activates a scheduled TEE application key after its delay. Anyone may finalize.
    function finalizeAttestorRotation() external {
        address newAttestor = pendingAttestor;
        if (newAttestor == address(0)) revert NoPendingAttestorRotation();
        if (block.timestamp < pendingAttestorReadyAt) revert AttestorRotationNotReady();

        address previousAttestor = attestor;
        attestor = newAttestor;
        ++attestorEpoch;
        delete pendingAttestor;
        delete pendingAttestorReadyAt;
        emit AttestorRotated(previousAttestor, newAttestor, attestorEpoch);
    }

    /// @inheritdoc IGoogleKeyRegistry
    /// @dev Fails closed while paused, before the first snapshot, or after the freshness lease expires.
    function getKey(bytes32 kidHash)
        external
        view
        override
        returns (bytes memory modulus, uint64 validAfter, uint64 validUntil)
    {
        uint64 observedAt = lastFetchedAt;
        if (
            paused || observedAt == 0
                || block.timestamp > uint256(observedAt) + maxRegistryStaleness
        ) return (new bytes(0), 0, 0);
        StoredKey storage key = _keys[kidHash];
        return (key.modulus, key.validAfter, key.validUntil);
    }

    /// @notice Returns the complete currently active `kid` hash list in canonical order.
    function activeKidHashes() external view returns (bytes32[] memory) {
        return _activeKidHashes;
    }

    /// @notice Returns the EIP-712 digest that the currently enrolled TEE key must sign.
    function keySetDigest(GoogleKey[] calldata keys, uint64 fetchedAt, uint256 nonce)
        external
        view
        returns (bytes32)
    {
        return _keySetDigest(_hashKeys(keys), fetchedAt, attestorEpoch, nonce);
    }

    /// @notice Computes a digest for an explicit epoch during enrollment and rotation checks.
    function keySetDigestForEpoch(
        GoogleKey[] calldata keys,
        uint64 fetchedAt,
        uint64 epoch,
        uint256 nonce
    ) external view returns (bytes32) {
        return _keySetDigest(_hashKeys(keys), fetchedAt, epoch, nonce);
    }

    /// @notice Publishes one attested Google key snapshot. Anyone may relay the signed snapshot.
    function submitKeySet(
        GoogleKey[] calldata keys,
        uint64 fetchedAt,
        uint256 nonce,
        bytes calldata signature
    ) external {
        if (nonce != updateNonce) revert InvalidNonce(updateNonce, nonce);
        if (lastFetchedAt != 0 && fetchedAt <= lastFetchedAt) revert NonMonotonicObservation();
        if (
            uint256(fetchedAt) > block.timestamp + MAX_FUTURE_SKEW
                || block.timestamp > uint256(fetchedAt) + maxObservationAge
        ) revert InvalidObservationTime();
        _validateKeys(keys);
        bytes32 keysHash = _hashKeys(keys);
        bytes32 digest = _keySetDigest(keysHash, fetchedAt, attestorEpoch, nonce);
        if (ECDSA.recover(digest, signature) != attestor) revert InvalidAttestorSignature();

        for (uint256 i; i < _activeKidHashes.length; ++i) {
            bytes32 activeKidHash = _activeKidHashes[i];
            if (!_contains(keys, activeKidHash)) {
                _keys[activeKidHash].validUntil = fetchedAt;
            }
        }

        for (uint256 i; i < keys.length; ++i) {
            StoredKey storage stored = _keys[keys[i].kidHash];
            if (stored.modulus.length == 0) {
                _keys[keys[i].kidHash] = StoredKey(keys[i].modulus, fetchedAt, 0);
            } else {
                if (keccak256(stored.modulus) != keccak256(keys[i].modulus)) {
                    revert ChangedKeyMaterial(keys[i].kidHash);
                }
                if (stored.validUntil != 0) {
                    stored.validAfter = fetchedAt;
                    stored.validUntil = 0;
                }
            }
        }

        lastFetchedAt = fetchedAt;
        updateNonce = nonce + 1;
        delete _activeKidHashes;
        for (uint256 i; i < keys.length; ++i) {
            _activeKidHashes.push(keys[i].kidHash);
        }

        emit KeySetApplied(keysHash, fetchedAt, attestorEpoch, nonce);
    }

    function _keySetDigest(bytes32 keysHash, uint64 fetchedAt, uint64 epoch, uint256 nonce)
        private
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(GOOGLE_KEY_SET_TYPEHASH, keysHash, fetchedAt, epoch, nonce)
        );
        return _hashTypedDataV4(structHash);
    }

    function _validateKeys(GoogleKey[] calldata keys) private pure {
        if (keys.length == 0 || keys.length > MAX_KEYS) revert InvalidKeySet();
        bytes32 previousKidHash = bytes32(0);
        for (uint256 i; i < keys.length; ++i) {
            if (
                keys[i].kidHash == bytes32(0) || keys[i].modulus.length != 256
                    || uint8(keys[i].modulus[0]) < 0x80 || uint8(keys[i].modulus[255]) & 1 == 0
                    || keys[i].kidHash <= previousKidHash
            ) revert InvalidKeySet();
            previousKidHash = keys[i].kidHash;
        }
    }

    function _contains(GoogleKey[] calldata keys, bytes32 kidHash) private pure returns (bool) {
        for (uint256 i; i < keys.length; ++i) {
            if (keys[i].kidHash == kidHash) return true;
        }
        return false;
    }

    function _hashKeys(GoogleKey[] calldata keys) private pure returns (bytes32) {
        bytes32[] memory keyHashes = new bytes32[](keys.length);
        for (uint256 i; i < keys.length; ++i) {
            keyHashes[i] = keccak256(
                abi.encode(GOOGLE_KEY_TYPEHASH, keys[i].kidHash, keccak256(keys[i].modulus))
            );
        }
        return keccak256(abi.encodePacked(keyHashes));
    }
}
