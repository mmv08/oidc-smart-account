// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { ProviderKeyRegistry } from "./ProviderKeyRegistry.sol";

/// @notice Verifies quorum attestations over exact, privacy-preserving OIDC management intents.
/// @dev Attestors sign only the EIP-712 digest. No JWT, issuer string, subject, email, or other PII is stored.
contract IdentityIntentVerifier is EIP712, Ownable2Step {
    enum Action {
        CREATE,
        ADD,
        REPLACE
    }

    struct Intent {
        uint8 version;
        Action action;
        bytes32 identityCommitment;
        address account;
        address controller;
        bytes32 currentSignerHash;
        bytes32 newSignerHash;
        uint256 recoveryNonce;
        bytes32 intentNonce;
        bytes32 providerId;
        bytes32 providerKeyHash;
        uint64 issuedAt;
        uint64 validAfter;
        uint64 validUntil;
        uint256 chainId;
        uint64 attestorEpoch;
    }

    bytes32 public constant INTENT_TYPEHASH = keccak256(
        "Intent(uint8 version,uint8 action,bytes32 identityCommitment,address account,address controller,bytes32 currentSignerHash,bytes32 newSignerHash,uint256 recoveryNonce,bytes32 intentNonce,bytes32 providerId,bytes32 providerKeyHash,uint64 issuedAt,uint64 validAfter,uint64 validUntil,uint256 chainId,uint64 attestorEpoch)"
    );
    bytes32 public constant ACTION_REQUEST_TYPEHASH = keccak256(
        "ActionRequest(uint8 version,uint8 action,bytes32 identityCommitment,address account,address controller,bytes32 currentSignerHash,bytes32 newSignerHash,uint256 recoveryNonce,bytes32 intentNonce,bytes32 providerId,uint64 issuedAt,uint64 validAfter,uint64 validUntil,uint256 chainId,uint64 attestorEpoch)"
    );
    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "Attestation(bytes32 intentDigest,bytes32 providerKeyHash,uint64 tokenIssuedAt)"
    );

    ProviderKeyRegistry public immutable providerRegistry;
    uint64 public immutable maxAttestationTTL;
    uint64 public attestorEpoch;
    uint8 public threshold;
    address[] private _attestors;
    mapping(address attestor => bool) public isAttestor;
    mapping(bytes32 digest => bool) public consumed;

    event AttestorsUpdated(uint64 indexed epoch, uint8 threshold, address[] attestors);
    event IntentConsumed(bytes32 indexed digest, Action indexed action, address indexed account);

    error InvalidAttestorConfiguration();
    error InvalidIntentVersion(uint8 version);
    error InvalidController(address expected, address actual);
    error InvalidChain(uint256 expected, uint256 actual);
    error InvalidEpoch(uint64 expected, uint64 actual);
    error InvalidIntentTime();
    error InvalidProviderKey();
    error InvalidAttestation();
    error IntentAlreadyConsumed(bytes32 digest);

    constructor(
        ProviderKeyRegistry registry,
        address[] memory attestors,
        uint8 threshold_,
        uint64 maxTTL,
        address initialOwner
    ) EIP712("OIDC Identity Intent", "1") Ownable(initialOwner) {
        if (address(registry) == address(0) || maxTTL == 0) {
            revert InvalidAttestorConfiguration();
        }
        providerRegistry = registry;
        maxAttestationTTL = maxTTL;
        _setAttestors(attestors, threshold_);
    }

    function getAttestors() external view returns (address[] memory) {
        return _attestors;
    }

    function setAttestors(address[] calldata attestors, uint8 threshold_) external onlyOwner {
        for (uint256 i; i < _attestors.length; ++i) {
            isAttestor[_attestors[i]] = false;
        }
        _setAttestors(attestors, threshold_);
    }

    function hashIntent(Intent calldata intent) public view returns (bytes32) {
        return _hashTypedDataV4(_hashIntentStruct(intent));
    }

    function hashActionRequest(Intent calldata intent) external view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    ACTION_REQUEST_TYPEHASH,
                    intent.version,
                    uint8(intent.action),
                    intent.identityCommitment,
                    intent.account,
                    intent.controller,
                    intent.currentSignerHash,
                    intent.newSignerHash,
                    intent.recoveryNonce,
                    intent.intentNonce,
                    intent.providerId,
                    intent.issuedAt,
                    intent.validAfter,
                    intent.validUntil,
                    intent.chainId,
                    intent.attestorEpoch
                )
            )
        );
    }

    /// @notice Digest signed by one attestor, including that attestor's exact OIDC token key evidence.
    function hashAttestation(bytes32 intentDigest, bytes32 providerKeyHash, uint64 tokenIssuedAt)
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(ATTESTATION_TYPEHASH, intentDigest, providerKeyHash, tokenIssuedAt)
            )
        );
    }

    /// @notice Consumes a quorum-authorized intent. Controller equality prevents generic signature relaying.
    function consume(Intent calldata intent, bytes[] calldata signatures)
        external
        returns (bytes32 digest)
    {
        if (intent.version != 1) revert InvalidIntentVersion(intent.version);
        if (intent.controller != msg.sender) {
            revert InvalidController(intent.controller, msg.sender);
        }
        if (intent.chainId != block.chainid) revert InvalidChain(block.chainid, intent.chainId);
        if (intent.attestorEpoch != attestorEpoch) {
            revert InvalidEpoch(attestorEpoch, intent.attestorEpoch);
        }
        if (
            intent.issuedAt > block.timestamp || intent.validAfter < intent.issuedAt
                || intent.validUntil <= intent.validAfter || block.timestamp < intent.validAfter
                || block.timestamp >= intent.validUntil
                || intent.validUntil - intent.issuedAt > maxAttestationTTL
        ) revert InvalidIntentTime();
        // The common intent reserves providerKeyHash as zero. Each packed attestation below carries
        // its own provider key and token issuance time so independent logins can span JWKS rotation.
        if (intent.providerKeyHash != bytes32(0)) revert InvalidProviderKey();

        digest = hashIntent(intent);
        if (consumed[digest]) revert IntentAlreadyConsumed(digest);
        if (signatures.length < threshold) revert InvalidAttestation();
        address previous;
        for (uint256 i; i < signatures.length; ++i) {
            (bytes32 providerKeyHash, uint64 tokenIssuedAt, bytes memory signature) =
                abi.decode(signatures[i], (bytes32, uint64, bytes));
            if (
                tokenIssuedAt > block.timestamp
                    || !providerRegistry.isKeyValid(
                        intent.providerId, providerKeyHash, tokenIssuedAt
                    )
            ) {
                revert InvalidProviderKey();
            }
            (address recovered, ECDSA.RecoverError recoverError,) = ECDSA.tryRecover(
                hashAttestation(digest, providerKeyHash, tokenIssuedAt), signature
            );
            if (
                recoverError != ECDSA.RecoverError.NoError || !isAttestor[recovered]
                    || recovered <= previous
            ) {
                revert InvalidAttestation();
            }
            previous = recovered;
        }
        consumed[digest] = true;
        emit IntentConsumed(digest, intent.action, intent.account);
    }

    function _setAttestors(address[] memory attestors, uint8 threshold_) private {
        if (threshold_ < 2 || threshold_ > attestors.length || attestors.length > type(uint8).max) {
            revert InvalidAttestorConfiguration();
        }
        address previous;
        for (uint256 i; i < attestors.length; ++i) {
            if (attestors[i] == address(0) || attestors[i] <= previous) {
                revert InvalidAttestorConfiguration();
            }
            previous = attestors[i];
            isAttestor[previous] = true;
        }
        _attestors = attestors;
        threshold = threshold_;
        ++attestorEpoch;
        emit AttestorsUpdated(attestorEpoch, threshold_, attestors);
    }

    function _hashIntentStruct(Intent calldata intent) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                INTENT_TYPEHASH,
                intent.version,
                uint8(intent.action),
                intent.identityCommitment,
                intent.account,
                intent.controller,
                intent.currentSignerHash,
                intent.newSignerHash,
                intent.recoveryNonce,
                intent.intentNonce,
                intent.providerId,
                intent.providerKeyHash,
                intent.issuedAt,
                intent.validAfter,
                intent.validUntil,
                intent.chainId,
                intent.attestorEpoch
            )
        );
    }
}
