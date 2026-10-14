// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import { LowLevelCall } from "@openzeppelin/contracts/utils/LowLevelCall.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { JWTVerifier } from "./JWTVerifier.sol";

/// @title OIDC Account
/// @notice Smart account of one OIDC user. A JWT from the issuer sets the signer. Then the signer
/// sends transactions from the account.
contract OIDCAccount {
    /// @notice Verifier that examines the JWTs.
    JWTVerifier public immutable verifier;
    /// @notice Keccak-256 hash of the `sub` claim of the user.
    bytes32 public immutable subjectHash;
    /// @notice Address that can call `execute`. It is zero until the first `setSigner`.
    address public signer;
    /// @notice Number of signer changes. Each JWT nonce contains this value.
    uint256 public nonce;

    /// @notice Emitted when a JWT sets the signer.
    event SignerSet(address indexed signer);

    /// @notice The JWT is for a different user or for a different action.
    error InvalidJWT();
    /// @notice The caller is not the signer.
    error NotSigner();

    /// @param verifier_ Verifier for the issuer and the audience of the user.
    /// @param subjectHash_ Keccak-256 hash of the `sub` claim of the user.
    constructor(JWTVerifier verifier_, bytes32 subjectHash_) {
        verifier = verifier_;
        subjectHash = subjectHash_;
    }

    /// @notice Lets the account receive Ether.
    receive() external payable { }

    /// @notice Sets the signer with a JWT from the issuer.
    /// @dev Anyone can send the JWT. The JWT must have the subject of this account and the nonce
    /// `jwtNonce(newSigner)`. Thus the JWT can set only the signer that the user selected, and only
    /// one time, on this account and this chain.
    /// @param jwt Compact RS256 JWT from the issuer.
    /// @param newSigner Address that the JWT approves as the new signer.
    function setSigner(string calldata jwt, address newSigner) external {
        (bytes32 sub, bytes32 nonceHash) = verifier.verify(jwt);
        require(
            sub == subjectHash && nonceHash == keccak256(bytes(jwtNonce(newSigner))), InvalidJWT()
        );
        signer = newSigner;
        ++nonce;
        emit SignerSet(newSigner);
    }

    /// @notice Calls `target` from the account. Only the signer can do this.
    /// @dev If the call reverts, this function reverts with the same data.
    function execute(address target, uint256 value, bytes calldata data) external {
        require(msg.sender == signer, NotSigner());
        if (!LowLevelCall.callNoReturn(target, value, data)) LowLevelCall.bubbleRevert();
    }

    /// @notice Returns the `nonce` claim that a JWT must have to set `newSigner`.
    /// @dev The value is `keccak256(abi.encode(chainId, account, newSigner, nonce))` as a
    /// lowercase hex string with the `0x` prefix.
    function jwtNonce(address newSigner) public view returns (string memory) {
        bytes32 digest = keccak256(abi.encode(block.chainid, address(this), newSigner, nonce));
        return Strings.toHexString(uint256(digest), 32);
    }
}
