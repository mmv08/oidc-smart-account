// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

/// @title Google RSA Modulus Registry Interface
/// @notice Resolves a Google JWT key identifier to an RSA modulus and its issue-time range.
/// @dev The verifier hashes the protected-header `kid` with Keccak-256 before lookup. An empty return
/// value denotes an unknown or removed key.
interface IGoogleKeyRegistry {
    /// @notice Returns the RSA modulus and token issue-time interval registered for `kidHash`.
    /// @dev `validUntil == 0` represents an open-ended interval. The interval applies to the token's
    /// signed `iat`, not the current block time.
    /// @param kidHash Keccak-256 hash of the exact UTF-8 `kid` value.
    /// @return modulus Big-endian RSA public modulus.
    /// @return validAfter Earliest accepted token issue time, inclusive.
    /// @return validUntil First rejected token issue time, or zero for no upper bound.
    function getKey(bytes32 kidHash)
        external
        view
        returns (bytes memory modulus, uint64 validAfter, uint64 validUntil);
}
