from typing import List, Optional
import base64
import struct

# Configurable threshold for the creator's initial buy amount
CREATOR_INITIAL_BUY_THRESHOLD = 50000000  # 50 million tokens
BUY_DISCRIMINATOR = 16927863322537952870  # Global constant for "buy" instruction
TOKEN_DECIMALS = 6  # Pump.fun uses 6 decimals

def get_buy_instruction_amount(logs: List[str]) -> Optional[float]:
    """
    Extracts the amount field from the buy instruction in the logs.

    Args:
        logs: The logs from the transaction.

    Returns:
        The scaled amount as a float if found, otherwise None.
    """
    for log in logs:
        if "Program data:" not in log:
            continue

        try:
            # Extract and decode the program data from the log
            encoded_data = log.split("Program data: ")[1].strip()
            decoded_data = base64.b64decode(encoded_data)
            
            # Check if we have enough data for a buy instruction
            if len(decoded_data) < 24:
                continue
            
            # Check the discriminator to ensure this is a buy instruction
            discriminator = struct.unpack("<Q", decoded_data[:8])[0]
            
            if discriminator != BUY_DISCRIMINATOR:
                continue  # Not a buy instruction, skip
            
            # Extract the amount field (bytes 8-16)
            amount_raw = struct.unpack("<Q", decoded_data[8:16])[0]
            scaled_amount = amount_raw / (10 ** TOKEN_DECIMALS)

            return scaled_amount
        except Exception:
            continue

    # If no valid buy instruction is found, return None
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
        return False

    return buy_amount <= CREATOR_INITIAL_BUY_THRESHOLD