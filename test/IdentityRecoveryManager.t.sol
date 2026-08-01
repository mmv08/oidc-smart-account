// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Test } from "forge-std/Test.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IERC7913SignatureVerifier } from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import { ProviderKeyRegistry } from "../src/ProviderKeyRegistry.sol";
import { IdentityIntentVerifier } from "../src/IdentityIntentVerifier.sol";
import { IndependentKeyAccount } from "../src/IndependentKeyAccount.sol";
import { IdentityRecoveryManager } from "../src/IdentityRecoveryManager.sol";

contract RecoveryEntryPoint {
    function getNonce(address, uint192) external pure returns (uint256) {
        return 0;
    }

    function callAccount(address account, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory result) = account.call(data);
        if (!ok) assembly ("memory-safe") { revert(add(result, 32), mload(result)) }
        return result;
    }
}

contract TestERC7913Verifier is IERC7913SignatureVerifier {
    function verify(bytes calldata key, bytes32 hash, bytes calldata signature)
        external
        pure
        returns (bytes4)
    {
        if (key.length != 20) return bytes4(0xffffffff);
        return ECDSA.recover(hash, signature) == address(bytes20(key))
            ? this.verify.selector
            : bytes4(0xffffffff);
    }
}

contract FakeRecoveryAccount {
    bytes32 public immutable identityCommitment;
    bytes32 public immutable signerSetHash;
    bool public constant recoveryEnabled = true;

    constructor(bytes32 identityCommitment_, bytes32 signerSetHash_) {
        identityCommitment = identityCommitment_;
        signerSetHash = signerSetHash_;
    }

    function isSigner(bytes calldata) external pure returns (bool) {
        return false;
    }
}

contract IdentityRecoveryManagerTest is Test {
    uint256 internal a1 = 0xA11CE;
    uint256 internal a2 = 0xB0B;
    uint256 internal oldPk = 0x1111;
    uint256 internal newPk = 0x2222;
    bytes32 internal provider = keccak256("provider");
    bytes32 internal keyHash;
    IdentityIntentVerifier internal verifier;
    IdentityRecoveryManager internal manager;
    IndependentKeyAccount internal account;
    RecoveryEntryPoint internal entryPoint;

    function setUp() public {
        vm.warp(10_000);
        ProviderKeyRegistry registry = new ProviderKeyRegistry(address(this));
        registry.registerProvider(provider);
        keyHash =
            registry.publishKey(provider, keccak256("kid"), bytes("jwk"), 9000, type(uint64).max);
        address[] memory attestors = new address[](2);
        attestors[0] = vm.addr(a1);
        attestors[1] = vm.addr(a2);
        if (attestors[0] > attestors[1]) {
            (attestors[0], attestors[1]) = (attestors[1], attestors[0]);
        }
        verifier = new IdentityIntentVerifier(registry, attestors, 2, 1 hours, address(this));
        manager = new IdentityRecoveryManager(verifier, 2 days, 7 days, address(this));
        entryPoint = new RecoveryEntryPoint();
        account = new IndependentKeyAccount(
            address(entryPoint),
            address(manager),
            keccak256("identity"),
            abi.encodePacked(vm.addr(oldPk))
        );
    }

    function _intent(bytes memory newSigner)
        internal
        view
        returns (IdentityIntentVerifier.Intent memory intent)
    {
        intent = IdentityIntentVerifier.Intent({
            version: 1,
            action: IdentityIntentVerifier.Action.ADD,
            identityCommitment: account.identityCommitment(),
            account: address(account),
            controller: address(manager),
            currentSignerHash: account.signerSetHash(),
            newSignerHash: keccak256(newSigner),
            recoveryNonce: manager.recoveryNonces(address(account)),
            intentNonce: keccak256("nonce"),
            providerId: provider,
            providerKeyHash: bytes32(0),
            issuedAt: uint64(block.timestamp),
            validAfter: uint64(block.timestamp),
            validUntil: uint64(block.timestamp + 600),
            chainId: block.chainid,
            attestorEpoch: verifier.attestorEpoch()
        });
    }

    function _sign(uint256 pk, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _attest(bytes32 digest) internal returns (bytes[] memory sigs) {
        uint64 tokenIssuedAt = uint64(block.timestamp);
        bytes32 attestationDigest = verifier.hashAttestation(digest, keyHash, tokenIssuedAt);
        bytes memory s1 = _sign(a1, attestationDigest);
        bytes memory s2 = _sign(a2, attestationDigest);
        sigs = new bytes[](2);
        if (vm.addr(a1) < vm.addr(a2)) {
            sigs[0] = abi.encode(keyHash, tokenIssuedAt, s1);
            sigs[1] = abi.encode(keyHash, tokenIssuedAt, s2);
        } else {
            sigs[0] = abi.encode(keyHash, tokenIssuedAt, s2);
            sigs[1] = abi.encode(keyHash, tokenIssuedAt, s1);
        }
    }

    function test_addRecoveryIsDelayedAndRequiresNewKeyProofAgain() public {
        bytes memory newSigner = abi.encodePacked(vm.addr(newPk));
        IdentityIntentVerifier.Intent memory intent = _intent(newSigner);
        bytes32 digest = verifier.hashIntent(intent);
        manager.schedule(
            address(account), bytes(""), newSigner, _sign(newPk, digest), intent, _attest(digest)
        );
        assertEq(manager.recoveryNonces(address(account)), 1);
        assertFalse(account.isSigner(newSigner));

        vm.expectRevert(IdentityRecoveryManager.RecoveryNotReady.selector);
        manager.finalize(address(account), _sign(newPk, digest));
        vm.warp(block.timestamp + 2 days);
        manager.finalize(address(account), _sign(newPk, digest));
        assertTrue(account.isSigner(newSigner));
    }

    function test_replaceRecoveryRemovesOnlyTheBoundCurrentSigner() public {
        bytes memory oldSigner = abi.encodePacked(vm.addr(oldPk));
        bytes memory newSigner = abi.encodePacked(vm.addr(newPk));
        IdentityIntentVerifier.Intent memory intent = _intent(newSigner);
        intent.action = IdentityIntentVerifier.Action.REPLACE;
        intent.currentSignerHash = keccak256(oldSigner);
        bytes32 digest = verifier.hashIntent(intent);
        manager.schedule(
            address(account), oldSigner, newSigner, _sign(newPk, digest), intent, _attest(digest)
        );
        vm.warp(block.timestamp + 2 days);
        manager.finalize(address(account), _sign(newPk, digest));
        assertFalse(account.isSigner(oldSigner));
        assertTrue(account.isSigner(newSigner));
        assertEq(account.getSignerCount(), 1);
    }

    function test_accountCanCancelButConsumedNonceCannotBeReplayed() public {
        bytes memory newSigner = abi.encodePacked(vm.addr(newPk));
        IdentityIntentVerifier.Intent memory intent = _intent(newSigner);
        bytes32 digest = verifier.hashIntent(intent);
        bytes memory pop = _sign(newPk, digest);
        bytes[] memory attestations = _attest(digest);
        manager.schedule(address(account), bytes(""), newSigner, pop, intent, attestations);
        entryPoint.callAccount(
            address(account),
            abi.encodeCall(
                IndependentKeyAccount.execute,
                (
                    address(manager),
                    0,
                    abi.encodeCall(IdentityRecoveryManager.cancel, (address(account)))
                )
            )
        );
        assertEq(manager.getPending(address(account)).executeAfter, 0);
        assertEq(manager.recoveryNonces(address(account)), 1);
        vm.expectRevert();
        manager.schedule(address(account), bytes(""), newSigner, pop, intent, attestations);
    }

    function test_expiredPendingRecoveryCannotFinalizeAndDoesNotBlockANewRecovery() public {
        bytes memory firstSigner = abi.encodePacked(vm.addr(newPk));
        IdentityIntentVerifier.Intent memory firstIntent = _intent(firstSigner);
        bytes32 firstDigest = verifier.hashIntent(firstIntent);
        manager.schedule(
            address(account),
            bytes(""),
            firstSigner,
            _sign(newPk, firstDigest),
            firstIntent,
            _attest(firstDigest)
        );

        vm.warp(block.timestamp + 2 days + 7 days + 1);
        vm.expectRevert(IdentityRecoveryManager.RecoveryExpired.selector);
        manager.finalize(address(account), _sign(newPk, firstDigest));

        uint256 laterPk = 0x3333;
        bytes memory laterSigner = abi.encodePacked(vm.addr(laterPk));
        IdentityIntentVerifier.Intent memory laterIntent = _intent(laterSigner);
        bytes32 laterDigest = verifier.hashIntent(laterIntent);
        manager.schedule(
            address(account),
            bytes(""),
            laterSigner,
            _sign(laterPk, laterDigest),
            laterIntent,
            _attest(laterDigest)
        );
        assertEq(manager.getPending(address(account)).digest, laterDigest);
    }

    function test_wrongActionAccountCurrentSignerNonceAndProofAreRejected() public {
        bytes memory newSigner = abi.encodePacked(vm.addr(newPk));
        IdentityIntentVerifier.Intent memory intent = _intent(newSigner);
        intent.action = IdentityIntentVerifier.Action.CREATE;
        bytes32 digest = verifier.hashIntent(intent);
        bytes memory pop = _sign(newPk, digest);
        bytes[] memory attestations = _attest(digest);
        vm.expectRevert(IdentityRecoveryManager.InvalidRecoveryIntent.selector);
        manager.schedule(address(account), bytes(""), newSigner, pop, intent, attestations);

        intent = _intent(newSigner);
        intent.account = address(0xBEEF);
        digest = verifier.hashIntent(intent);
        pop = _sign(newPk, digest);
        attestations = _attest(digest);
        vm.expectRevert(IdentityRecoveryManager.InvalidRecoveryIntent.selector);
        manager.schedule(address(account), bytes(""), newSigner, pop, intent, attestations);

        intent = _intent(newSigner);
        intent.currentSignerHash = keccak256("wrong");
        digest = verifier.hashIntent(intent);
        pop = _sign(newPk, digest);
        attestations = _attest(digest);
        vm.expectRevert(IdentityRecoveryManager.InvalidRecoveryIntent.selector);
        manager.schedule(address(account), bytes(""), newSigner, pop, intent, attestations);

        intent = _intent(newSigner);
        intent.recoveryNonce = 1;
        digest = verifier.hashIntent(intent);
        pop = _sign(newPk, digest);
        attestations = _attest(digest);
        vm.expectRevert(IdentityRecoveryManager.InvalidRecoveryIntent.selector);
        manager.schedule(address(account), bytes(""), newSigner, pop, intent, attestations);

        intent = _intent(newSigner);
        digest = verifier.hashIntent(intent);
        attestations = _attest(digest);
        vm.expectRevert(IdentityRecoveryManager.InvalidProofOfPossession.selector);
        manager.schedule(
            address(account), bytes(""), newSigner, _sign(oldPk, digest), intent, attestations
        );
    }

    function test_addresslessVerifierMustBeAllowlistedAndCodehashPinned() public {
        TestERC7913Verifier signerVerifier = new TestERC7913Verifier();
        bytes memory signer = abi.encodePacked(address(signerVerifier), vm.addr(newPk));
        IdentityIntentVerifier.Intent memory intent = _intent(signer);
        bytes32 digest = verifier.hashIntent(intent);
        bytes memory pop = _sign(newPk, digest);
        bytes[] memory attestations = _attest(digest);
        vm.expectRevert();
        manager.schedule(address(account), bytes(""), signer, pop, intent, attestations);

        manager.setSignerVerifierPolicy(address(signerVerifier), true);
        manager.schedule(address(account), bytes(""), signer, pop, intent, attestations);
        vm.warp(block.timestamp + 2 days);
        manager.finalize(address(account), pop);
        assertTrue(account.isSigner(signer));
    }

    function test_pinnedVerifierCodehashDriftIsRejected() public {
        TestERC7913Verifier signerVerifier = new TestERC7913Verifier();
        manager.setSignerVerifierPolicy(address(signerVerifier), true);
        vm.etch(address(signerVerifier), hex"00");
        bytes memory signer = abi.encodePacked(address(signerVerifier), vm.addr(newPk));
        IdentityIntentVerifier.Intent memory intent = _intent(signer);
        bytes32 digest = verifier.hashIntent(intent);
        bytes memory pop = _sign(newPk, digest);
        bytes[] memory attestations = _attest(digest);
        vm.expectRevert();
        manager.schedule(address(account), bytes(""), signer, pop, intent, attestations);
    }

    function test_permanentlyDisabledRecoveryCannotSchedule() public {
        entryPoint.callAccount(
            address(account), abi.encodeCall(IndependentKeyAccount.disableRecovery, ())
        );
        bytes memory newSigner = abi.encodePacked(vm.addr(newPk));
        IdentityIntentVerifier.Intent memory intent = _intent(newSigner);
        bytes32 digest = verifier.hashIntent(intent);
        bytes memory pop = _sign(newPk, digest);
        bytes[] memory attestations = _attest(digest);
        vm.expectRevert(IdentityRecoveryManager.InvalidRecoveryIntent.selector);
        manager.schedule(address(account), bytes(""), newSigner, pop, intent, attestations);
    }

    function test_recoveryRejectsLookalikeAccountNotBoundToManager() public {
        bytes memory newSigner = abi.encodePacked(vm.addr(newPk));
        FakeRecoveryAccount fake = new FakeRecoveryAccount(
            keccak256("fake-identity"), keccak256(abi.encode(new bytes32[](0)))
        );
        IdentityIntentVerifier.Intent memory intent = _intent(newSigner);
        intent.identityCommitment = fake.identityCommitment();
        intent.account = address(fake);
        intent.currentSignerHash = fake.signerSetHash();
        bytes32 digest = verifier.hashIntent(intent);
        bytes memory pop = _sign(newPk, digest);
        bytes[] memory attestations = _attest(digest);
        vm.expectRevert(IdentityRecoveryManager.InvalidRecoveryIntent.selector);
        manager.schedule(address(fake), bytes(""), newSigner, pop, intent, attestations);
    }
}
