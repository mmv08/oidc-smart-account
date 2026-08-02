// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

interface IGoogleKeyRegistry {
    function getKey(bytes32 kidHash)
        external
        view
        returns (bytes memory exponent, bytes memory modulus, uint64 validAfter, uint64 validUntil);
}
