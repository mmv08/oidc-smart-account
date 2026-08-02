// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IGoogleKeyRegistry } from "./IGoogleKeyRegistry.sol";

/// @notice Minimal project-operated registry of Google OIDC RSA signing keys.
/// @dev The owner is a recovery trust root: registering an attacker key permits forged claims.
contract GoogleKeyRegistry is Ownable, IGoogleKeyRegistry {
    struct Key {
        bytes exponent;
        bytes modulus;
        uint64 validAfter;
        uint64 validUntil;
    }

    mapping(bytes32 kidHash => Key) private _keys;

    event KeySet(bytes32 indexed kidHash, uint64 validAfter, uint64 validUntil);
    event KeyRemoved(bytes32 indexed kidHash);

    error InvalidKey();

    constructor(address initialOwner) Ownable(initialOwner) { }

    function setKey(
        bytes32 kidHash,
        bytes calldata exponent,
        bytes calldata modulus,
        uint64 validAfter,
        uint64 validUntil
    ) external onlyOwner {
        if (
            kidHash == bytes32(0) || exponent.length != 3 || bytes3(exponent) != bytes3(0x010001)
                || modulus.length != 256 || (validUntil != 0 && validUntil <= validAfter)
        ) revert InvalidKey();

        _keys[kidHash] = Key(exponent, modulus, validAfter, validUntil);
        emit KeySet(kidHash, validAfter, validUntil);
    }

    function removeKey(bytes32 kidHash) external onlyOwner {
        delete _keys[kidHash];
        emit KeyRemoved(kidHash);
    }

    function getKey(bytes32 kidHash)
        external
        view
        returns (bytes memory exponent, bytes memory modulus, uint64 validAfter, uint64 validUntil)
    {
        Key storage key = _keys[kidHash];
        return (key.exponent, key.modulus, key.validAfter, key.validUntil);
    }
}
