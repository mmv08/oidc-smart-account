// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

/// @title Strict Base64URL Decoder
/// @notice Decodes unpadded Base64URL segments used by compact JWS and JWT values.
/// @dev Rejects padding, non-URL-safe characters, impossible lengths, and nonzero unused pad bits so
/// each accepted byte string has one canonical encoding.
library Base64Url {
    /// @dev Thrown when the input is not canonical unpadded Base64URL.
    error InvalidBase64Url();

    /// @notice Decodes one canonical unpadded Base64URL value.
    /// @param input ASCII Base64URL bytes without `=` padding.
    /// @return output Decoded bytes.
    function decode(bytes memory input) internal pure returns (bytes memory output) {
        uint256 length = input.length;
        uint256 remainder = length & 3;
        if (remainder == 1) revert InvalidBase64Url();

        output = new bytes((length * 6) >> 3);
        uint256 inputIndex = 0;
        uint256 outputIndex = 0;

        while (inputIndex + 4 <= length) {
            uint256 value = (uint256(_value(input[inputIndex])) << 18)
                | (uint256(_value(input[inputIndex + 1])) << 12)
                | (uint256(_value(input[inputIndex + 2])) << 6)
                | uint256(_value(input[inputIndex + 3]));
            output[outputIndex] = bytes1(uint8(value >> 16));
            output[outputIndex + 1] = bytes1(uint8(value >> 8));
            output[outputIndex + 2] = bytes1(uint8(value));
            inputIndex += 4;
            outputIndex += 3;
        }

        if (remainder == 2) {
            uint8 first = _value(input[inputIndex]);
            uint8 second = _value(input[inputIndex + 1]);
            if (second & 0x0f != 0) revert InvalidBase64Url();
            output[outputIndex] = bytes1((first << 2) | (second >> 4));
        } else if (remainder == 3) {
            uint8 first = _value(input[inputIndex]);
            uint8 second = _value(input[inputIndex + 1]);
            uint8 third = _value(input[inputIndex + 2]);
            if (third & 0x03 != 0) revert InvalidBase64Url();
            output[outputIndex] = bytes1((first << 2) | (second >> 4));
            output[outputIndex + 1] = bytes1((second << 4) | (third >> 2));
        }
    }

    function _value(bytes1 character) private pure returns (uint8) {
        uint8 c = uint8(character);
        if (c >= 0x41 && c <= 0x5a) return c - 0x41;
        if (c >= 0x61 && c <= 0x7a) return c - 0x61 + 26;
        if (c >= 0x30 && c <= 0x39) return c - 0x30 + 52;
        if (c == 0x2d) return 62;
        if (c == 0x5f) return 63;
        revert InvalidBase64Url();
    }
}
