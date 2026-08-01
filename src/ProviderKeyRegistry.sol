// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @notice Governance registry for pseudonymous OIDC provider policies and canonical public keys.
/// @dev JWTs and identity claims never enter this registry. Revocation is intentionally checked at current time.
contract ProviderKeyRegistry is Ownable2Step {
    struct ProviderKey {
        bytes32 providerId;
        bytes32 kidHash;
        uint64 notBefore;
        uint64 notAfter;
        bool revoked;
        bytes canonicalJwk;
    }

    mapping(bytes32 providerId => bool) public providers;
    mapping(bytes32 providerId => mapping(bytes32 keyHash => ProviderKey)) private _keys;

    event ProviderRegistered(bytes32 indexed providerId);
    event ProviderKeyPublished(
        bytes32 indexed providerId,
        bytes32 indexed keyHash,
        bytes32 indexed kidHash,
        uint64 notBefore,
        uint64 notAfter,
        bytes canonicalJwk
    );
    event ProviderKeyRevoked(bytes32 indexed providerId, bytes32 indexed keyHash);

    error InvalidProvider();
    error InvalidKey();
    error InvalidValidityWindow();
    error ProviderAlreadyRegistered(bytes32 providerId);
    error ProviderNotRegistered(bytes32 providerId);
    error KeyAlreadyPublished(bytes32 keyHash);
    error KeyNotPublished(bytes32 keyHash);

    constructor(address initialOwner) Ownable(initialOwner) { }

    function registerProvider(bytes32 providerId) external onlyOwner {
        if (providerId == bytes32(0)) revert InvalidProvider();
        if (providers[providerId]) revert ProviderAlreadyRegistered(providerId);
        providers[providerId] = true;
        emit ProviderRegistered(providerId);
    }

    function publishKey(
        bytes32 providerId,
        bytes32 kidHash,
        bytes calldata canonicalJwk,
        uint64 notBefore,
        uint64 notAfter
    ) external onlyOwner returns (bytes32 keyHash) {
        if (!providers[providerId]) revert ProviderNotRegistered(providerId);
        if (kidHash == bytes32(0) || canonicalJwk.length == 0) revert InvalidKey();
        if (notBefore >= notAfter) revert InvalidValidityWindow();
        keyHash = sha256(canonicalJwk);
        if (_keys[providerId][keyHash].providerId != bytes32(0)) {
            revert KeyAlreadyPublished(keyHash);
        }
        _keys[providerId][keyHash] =
            ProviderKey(providerId, kidHash, notBefore, notAfter, false, canonicalJwk);
        emit ProviderKeyPublished(providerId, keyHash, kidHash, notBefore, notAfter, canonicalJwk);
    }

    function revokeKey(bytes32 providerId, bytes32 keyHash) external onlyOwner {
        ProviderKey storage key = _keys[providerId][keyHash];
        if (key.providerId == bytes32(0)) revert KeyNotPublished(keyHash);
        key.revoked = true;
        emit ProviderKeyRevoked(providerId, keyHash);
    }

    function getKey(bytes32 providerId, bytes32 keyHash)
        external
        view
        returns (ProviderKey memory)
    {
        return _keys[providerId][keyHash];
    }

    function isKeyValid(bytes32 providerId, bytes32 keyHash, uint64 issuedAt)
        external
        view
        returns (bool)
    {
        ProviderKey storage key = _keys[providerId][keyHash];
        return key.providerId == providerId && !key.revoked && issuedAt >= key.notBefore
            && issuedAt < key.notAfter;
    }
}
