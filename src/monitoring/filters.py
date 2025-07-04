from typing import List, Optional
import base64
import struct
import hashlib

# Configurable threshold for the creator's initial buy amount (50 million tokens)
CREATOR_INITIAL_BUY_THRESHOLD = 50_000_000  # 50 million tokens
PUMP_TOKEN_DECIMALS = 6  # Pump.fun tokens use 6 decimals, not 9!

# Calculate the correct BUY_DISCRIMINATOR using Anchor framework method
def calculate_buy_discriminator():
    """Calculate the correct discriminator for pump.fun buy instruction"""
    # Anchor uses sha256('global:buy') for the buy instruction discriminator
    hash_input = 'global:buy'.encode('utf-8')
    hash_result = hashlib.sha256(hash_input).digest()
    # Take first 8 bytes as little-endian u64
    return struct.unpack('<Q', hash_result[:8])[0]

# Correct discriminator calculation
BUY_DISCRIMINATOR = calculate_buy_discriminator()
print(f"Calculated BUY_DISCRIMINATOR: {BUY_DISCRIMINATOR}")


def get_buy_instruction_amount(logs: List[str]) -> Optional[float]:
    """
    Extracts the amount field from the buy instruction in the logs.
    
    Args:
        logs: The logs from the transaction (from logsSubscribe).
    
    Returns:
        The scaled amount as a float if found, otherwise None.
    """
    for log in logs:
        # Look for program data logs specifically
        if "Program data:" not in log:
            continue

        try:
            # Extract the base64 encoded data after "Program data: "
            parts = log.split("Program data: ")
            if len(parts) != 2:
                continue
                
            encoded_data = parts[1].strip()
            
            # Decode the base64 data
            decoded_data = base64.b64decode(encoded_data)
            
            # Debug: Print decoded data for troubleshooting
            print(f"Log: {log}")
            print(f"Decoded data length: {len(decoded_data)}")
            print(f"Decoded data hex: {decoded_data.hex()}")
            
            # Ensure we have at least 16 bytes (8 for discriminator + 8 for amount)
            if len(decoded_data) < 16:
                print(f"Log skipped: Data too short ({len(decoded_data)} bytes)")
                continue

            # Extract and verify the discriminator (first 8 bytes)
            discriminator_bytes = decoded_data[0:8]
            discriminator = struct.unpack("<Q", discriminator_bytes)[0]
            
            print(f"Found discriminator: {discriminator}")
            print(f"Expected discriminator: {BUY_DISCRIMINATOR}")
            
            if discriminator != BUY_DISCRIMINATOR:
                print(f"Log skipped: Discriminator {discriminator} does not match BUY_DISCRIMINATOR {BUY_DISCRIMINATOR}")
                continue

            # Extract the amount field (bytes 8-15, according to IDL structure)
            amount_bytes = decoded_data[8:16]
            amount_raw = struct.unpack("<Q", amount_bytes)[0]
            
            # Scale the amount using pump.fun's 6 decimals
            scaled_amount = amount_raw / (10 ** PUMP_TOKEN_DECIMALS)

            # Debug: Log the extracted amount
            print(f"Raw amount: {amount_raw}")
            print(f"Scaled amount: {scaled_amount}")

            return scaled_amount
            
        except Exception as e:
            print(f"Error decoding log: {e}")
            print(f"Problematic log: {log}")
            continue

    # If no valid buy instruction is found, return None
    print("No valid buy instruction found in logs")
    return None


def should_process_token(logs: List[str]) -> bool:
    """
    Determines whether a token should be processed based on the creator's initial buy amount.
    
    Args:
        logs: The logs from the transaction.
    
    Returns:
        True if the token should be processed, False otherwise.
    """
    buy_amount = get_buy_instruction_amount(logs)
    
    if buy_amount is None:
        print("No valid buy instruction found.")
        return False

    if buy_amount <= CREATOR_INITIAL_BUY_THRESHOLD:
        print(f"✅ Token PASSED filter: Buy amount {buy_amount:,.2f} is <= threshold {CREATOR_INITIAL_BUY_THRESHOLD:,}")
        return True
    else:
        print(f"❌ Token FAILED filter: Buy amount {buy_amount:,.2f} exceeds threshold {CREATOR_INITIAL_BUY_THRESHOLD:,}")
        return False
    