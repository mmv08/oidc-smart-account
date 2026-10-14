// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @title JWKS Registry
/// @notice Keeps the RSA public keys of one OIDC issuer.
/// @dev A TEE updater gets the issuer JWKS from `jwksUri` and signs a snapshot of it. Anyone can
/// send the snapshot. The owner examines the TEE attestation off-chain and then sets the attestor.
contract JWKSRegistry is EIP712 {
    /// @notice One RSA key from the JWKS. The exponent is always 65537.
    /// @param kid Key ID from the JWKS. The `kid` in a JWT header selects the key.
    /// @param modulus Big-endian RSA modulus.
    struct Key {
        string kid;
        bytes modulus;
    }

    bytes32 private constant KEY_TYPEHASH = keccak256("Key(string kid,bytes modulus)");
    bytes32 private constant KEY_SET_TYPEHASH = keccak256(
        "KeySet(string jwksUri,Key[] keys,uint64 fetchedAt)Key(string kid,bytes modulus)"
    );

    /// @notice Maximum age of the key set. `getKey` reverts when the key set is older.
    uint256 public constant MAX_KEY_SET_AGE = 1 days;

    /// @notice Address that sets the attestor.
    address public immutable owner;
    /// @notice Hash of the JWKS URI that each snapshot must have.
    bytes32 public immutable jwksUriHash;
    /// @notice Address of the TEE key that signs snapshots.
    address public attestor;
    /// @notice Time at which the TEE got the current key set, or the time of the last
    /// `setAttestor`. A new snapshot must be after this time.
    uint256 public fetchedAt;

    bytes32[] private _kidHashes;
    mapping(bytes32 kidHash => bytes modulus) private _moduli;

    /// @notice Emitted when the owner sets the attestor.
    event AttestorSet(address attestor);
    /// @notice Emitted when a snapshot replaces the key set.
    event KeySetUpdated(uint64 fetchedAt, bytes32[] kidHashes);

    /// @notice The caller is not the owner.
    error NotOwner();
    /// @notice The signature is not from the attestor.
    error InvalidSignature();
    /// @notice The snapshot is not after `fetchedAt`.
    error OldKeySet();
    /// @notice The key set is older than `MAX_KEY_SET_AGE`.
    error StaleKeySet();
    /// @notice The current key set does not contain the key.
    error UnknownKey();

    /// @param owner_ Address that sets the attestor.
    /// @param jwksUri URI of the issuer JWKS, for example `https://www.googleapis.com/oauth2/v3/certs`.
    constructor(address owner_, string memory jwksUri) EIP712("JWKSRegistry", "1") {
        owner = owner_;
        jwksUriHash = keccak256(bytes(jwksUri));
    }

    /// @notice Sets the TEE key that signs snapshots.
    /// @dev This also removes the current keys, because the old attestor signed them. The next
    /// snapshot must be after the block time of this change. Thus an old snapshot cannot put back a
    /// removed key, also when the owner sets the same attestor again. Use the zero address to stop
    /// all updates.
    function setAttestor(address newAttestor) external {
        if (msg.sender != owner) revert NotOwner();
        attestor = newAttestor;
        _clearKeys();
        fetchedAt = block.timestamp;
        emit AttestorSet(newAttestor);
    }

    /// @notice Replaces the key set with a snapshot that the attestor signed.
    /// @dev Anyone can send the snapshot. The snapshot must be after the current key set. Thus an
    /// old snapshot cannot put back a key that the issuer removed.
    /// @param keys All keys in the JWKS at `fetchTime`. An empty array removes all keys.
    /// @param fetchTime Time at which the TEE started to get the JWKS, in Unix seconds.
    /// @param signature Attestor signature of `hashKeySet(keys, fetchTime)`.
    function updateKeys(Key[] calldata keys, uint64 fetchTime, bytes calldata signature) external {
        if (fetchTime <= fetchedAt) revert OldKeySet();
        if (ECDSA.recover(hashKeySet(keys, fetchTime), signature) != attestor) {
            revert InvalidSignature();
        }

        _clearKeys();
        for (uint256 i = 0; i < keys.length; ++i) {
            bytes32 kidHash = keccak256(bytes(keys[i].kid));
            _moduli[kidHash] = keys[i].modulus;
            _kidHashes.push(kidHash);
        }
        fetchedAt = fetchTime;
        emit KeySetUpdated(fetchTime, _kidHashes);
    }

    /// @notice Returns the RSA modulus of a key in the current key set.
    /// @param kidHash Keccak-256 hash of the key ID.
    function getKey(bytes32 kidHash) external view returns (bytes memory modulus) {
        if (block.timestamp > fetchedAt + MAX_KEY_SET_AGE) revert StaleKeySet();
        modulus = _moduli[kidHash];
        if (modulus.length == 0) revert UnknownKey();
    }

    /// @notice Returns the EIP-712 digest that the attestor signs for a snapshot.
    function hashKeySet(Key[] calldata keys, uint64 fetchTime) public view returns (bytes32) {
        bytes32[] memory keyHashes = new bytes32[](keys.length);
        for (uint256 i = 0; i < keys.length; ++i) {
            keyHashes[i] = keccak256(
                abi.encode(KEY_TYPEHASH, keccak256(bytes(keys[i].kid)), keccak256(keys[i].modulus))
            );
        }
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    KEY_SET_TYPEHASH, jwksUriHash, keccak256(abi.encodePacked(keyHashes)), fetchTime
                )
            )
        );
    }

    function _clearKeys() private {
        for (uint256 i = 0; i < _kidHashes.length; ++i) {
            delete _moduli[_kidHashes[i]];
        }
        delete _kidHashes;
    }
}
