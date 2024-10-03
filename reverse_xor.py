def reverse_xor(hex_string1, target_result):
    # Convert hex strings to bytes
    bytes1 = bytes.fromhex(hex_string1)
    target_bytes = bytes.fromhex(target_result)
    
    # Perform XOR to find the unknown hex string
    result = bytes([b1 ^ b2 for b1, b2 in zip(bytes1, target_bytes)])
    
    # Convert result to hex
    return result.hex().upper()

# Known hex string
hex_string1 = "1BE3D13267E6993C1194F434281DDA43"
# Target XOR result
target_result = "D4B40305EE2B6F1833D77439129ACADE"

# Get the unknown hex string
unknown_hex_string = reverse_xor(hex_string1, target_result)
print("The unknown hex string is:", unknown_hex_string)
