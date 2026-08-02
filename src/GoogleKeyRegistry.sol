// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IGoogleKeyRegistry } from "./IGoogleKeyRegistry.sol";

/// @title Google RSA Modulus Registry
/// @notice Owner-managed registry for deployments that do not use the TEE updater.
/// @dev The TEE deployment stores keys directly in `TEEGoogleKeyUpdater` and does not deploy this
/// contract, avoiding a second mutation surface that could bypass pause and freshness policy.
contract GoogleKeyRegistry is Ownable, IGoogleKeyRegistry {
    /// @notice RSA modulus and its accepted token issue-time interval.
    /// @param modulus 256-byte big-endian RSA modulus encoding.
    /// @param validAfter Earliest accepted token `iat`, inclusive.
    /// @param validUntil First rejected token `iat`, or zero for no upper bound.
    struct Key {
        bytes modulus;
        uint64 validAfter;
        uint64 validUntil;
    }

    /// @dev Keys are indexed by `keccak256(bytes(kid))` from the protected JWT header.
    mapping(bytes32 kidHash => Key) private _keys;

    /// @dev Emitted when the owner creates or replaces a key entry.
    /// @param kidHash Hash used to resolve the protected-header `kid`.
    /// @param validAfter Earliest accepted token issue time.
    /// @param validUntil First rejected token issue time, or zero.
    event KeySet(bytes32 indexed kidHash, uint64 validAfter, uint64 validUntil);
    /// @dev Emitted when the owner removes a key entry.
    /// @param kidHash Hash of the removed key identifier.
    event KeyRemoved(bytes32 indexed kidHash);

    /// @dev Thrown when key material or its issue-time interval is invalid.
    error InvalidKey();

    /// @param initialOwner Address authorized to manage the standalone registry.
    constructor(address initialOwner) Ownable(initialOwner) { }

    /// @notice Creates or replaces the RSA modulus registered for `kidHash`.
    /// @dev Replacing or removing a key affects verification immediately. Operators should publish new
    /// keys before Google starts using them and retain old keys for the accepted claim-age overlap.
    /// @param kidHash Keccak-256 hash of the exact UTF-8 Google `kid`.
    /// @param modulus 256-byte big-endian RSA modulus encoding.
    /// @param validAfter Earliest accepted token issue time, inclusive.
    /// @param validUntil First rejected token issue time, or zero for no upper bound.
    function setKey(bytes32 kidHash, bytes calldata modulus, uint64 validAfter, uint64 validUntil)
        external
        onlyOwner
    {
        if (
            kidHash == bytes32(0) || modulus.length != 256
                || (validUntil != 0 && validUntil <= validAfter)
        ) revert InvalidKey();

        _keys[kidHash] = Key(modulus, validAfter, validUntil);
        emit KeySet(kidHash, validAfter, validUntil);
    }

    /// @notice Removes the RSA modulus registered for `kidHash`.
    /// @dev Tokens referencing the key stop verifying immediately, including otherwise unexpired tokens.
    /// @param kidHash Hash of the key identifier to remove.
    function removeKey(bytes32 kidHash) external onlyOwner {
        delete _keys[kidHash];
        emit KeyRemoved(kidHash);
    }

    /// @inheritdoc IGoogleKeyRegistry
    function getKey(bytes32 kidHash)
        external
        view
        returns (bytes memory modulus, uint64 validAfter, uint64 validUntil)
    {
        Key storage key = _keys[kidHash];
        return (key.modulus, key.validAfter, key.validUntil);
    }
}
