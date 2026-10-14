// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @title JWKS Registry
/// @notice Keeps a copy of the RSA public keys (the JWKS) of one OIDC issuer.
/// @dev A TEE updater gets the JWKS from `jwksUri` and signs it with its attestor key. Anyone can
/// send the signed key set. The owner examines the TEE attestation off-chain and then sets the
/// attestor.
contract JWKSRegistry is EIP712 {
    /// @notice One RSA key of the issuer. The exponent is always 65537.
    /// @param kid Key ID. The `kid` in a JWT header selects the key.
    /// @param modulus Big-endian RSA modulus.
    struct Key {
        string kid;
        bytes modulus;
    }

    bytes32 private constant KEY_TYPEHASH = keccak256("Key(string kid,bytes modulus)");
    bytes32 private constant KEY_SET_TYPEHASH = keccak256(
        "KeySet(string jwksUri,Key[] keys,uint64 fetchedAt)Key(string kid,bytes modulus)"
    );

    /// @notice Maximum age of the key set. After this age, `getKey` reverts.
    uint256 public constant MAX_KEY_SET_AGE = 1 days;

    /// @notice Address that sets the attestor.
    address public immutable owner;
    /// @notice Hash of the JWKS URI. Each key set must be for this URI.
    bytes32 public immutable jwksUriHash;
    /// @notice Address of the TEE key that signs key sets.
    address public attestor;
    /// @notice Time at which the TEE got the current key set, or the time of the last attestor
    /// change. A new key set must have a later time.
    uint256 public fetchedAt;

    /// @dev Each key set (and each attestor change) gets a new ID. `getKey` reads only the keys of
    /// the current ID. Thus a change removes all old keys.
    uint256 private _keySetId;
    mapping(uint256 keySetId => mapping(bytes32 kidHash => bytes modulus)) private _moduli;

    /// @notice Emitted when the owner sets the attestor.
    event AttestorSet(address attestor);
    /// @notice Emitted when a signed key set replaces the keys.
    event KeySetUpdated(uint64 fetchedAt);

    /// @notice The caller is not the owner.
    error NotOwner();
    /// @notice The signature is not from the attestor.
    error InvalidSignature();
    /// @notice The time of the key set is not after `fetchedAt`.
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

    /// @notice Sets the TEE key that signs key sets.
    /// @dev This also removes all keys, because the old attestor signed them. The next key set must
    /// be from after this change. Thus an old key set cannot come back, also when the owner sets the
    /// same attestor again. Use the zero address to stop all updates.
    function setAttestor(address newAttestor) external {
        require(msg.sender == owner, NotOwner());
        attestor = newAttestor;
        fetchedAt = block.timestamp;
        ++_keySetId;
        emit AttestorSet(newAttestor);
    }

    /// @notice Replaces all keys with a key set that the attestor signed.
    /// @dev Anyone can send the key set. Its time must be after the current key set. Thus an old key
    /// set cannot put back a key that the issuer removed.
    /// @param keys All keys in the JWKS at `fetchTime`. An empty array removes all keys.
    /// @param fetchTime Time at which the TEE started to get the JWKS, in Unix seconds.
    /// @param signature Attestor signature of `hashKeySet(keys, fetchTime)`.
    function updateKeys(Key[] calldata keys, uint64 fetchTime, bytes calldata signature) external {
        require(fetchTime > fetchedAt, OldKeySet());
        require(
            ECDSA.recover(hashKeySet(keys, fetchTime), signature) == attestor, InvalidSignature()
        );

        uint256 keySetId = ++_keySetId;
        for (uint256 i = 0; i < keys.length; ++i) {
            _moduli[keySetId][keccak256(bytes(keys[i].kid))] = keys[i].modulus;
        }
        fetchedAt = fetchTime;
        emit KeySetUpdated(fetchTime);
    }

    /// @notice Returns the RSA modulus of a key in the current key set.
    /// @param kidHash Keccak-256 hash of the key ID.
    function getKey(bytes32 kidHash) external view returns (bytes memory modulus) {
        require(block.timestamp <= fetchedAt + MAX_KEY_SET_AGE, StaleKeySet());
        modulus = _moduli[_keySetId][kidHash];
        require(modulus.length != 0, UnknownKey());
    }

    /// @notice Returns the EIP-712 digest that the attestor signs for a key set.
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
}
