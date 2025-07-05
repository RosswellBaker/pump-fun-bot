from typing import List, Optional, Tuple
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
    # Look for the Buy instruction log first to confirm it exists
    for i, log in enumerate(logs):
        if "Program log: Instruction: Buy" in log:
            # Now find the Program data that comes AFTER the Buy instruction
            for j in range(i + 1, len(logs)):
                if "Program data:" in logs[j]:
                    try:
                        # Extract the base64 data
                        encoded_data = logs[j].split("Program data: ")[1].strip()
                        
                        # Decode the base64 data
                        decoded_data = base64.b64decode(encoded_data)
                        
                        # Check if it's long enough for a buy instruction (24 bytes minimum)
                        if len(decoded_data) < 24:
                            continue
                        
                        # Check the discriminator (first 8 bytes)
                        discriminator = struct.unpack("<Q", decoded_data[:8])[0]
                        
                        if discriminator == BUY_DISCRIMINATOR:
                            # Found the buy instruction data!
                            # Extract amount (bytes 8-16)
                            amount_raw = struct.unpack("<Q", decoded_data[8:16])[0]
                            
                            # Convert to decimal representation
                            scaled_amount = amount_raw / (10 ** TOKEN_DECIMALS)
                            
                            # Return the scaled amount (even if it's 0)
                            return scaled_amount
                    except Exception:
                        # Continue to the next log if parsing fails
                        continue
    # If we get here, we found a Buy instruction but couldn't parse its data
    return None


def should_process_token(logs: List[str], signature: str) -> Tuple[bool, Optional[float]]:
    """
    Determines whether a token should be processed based on the creator's initial buy amount.
    
    Args:
        logs: The logs from the transaction.
        signature: Transaction signature for logging purposes.

    Returns:
        Tuple of (should_process, buy_amount)
    """
    # Check if this is a token creation transaction
    is_create_tx = any("Program log: Instruction: Create" in log for log in logs)
    
    if not is_create_tx:
        # Not a token creation - let it pass through
        return True, None
    
    # This is a token creation. Now check the creator's buy amount.
    buy_amount = get_buy_instruction_amount(logs)
    
    if buy_amount is None:
        # Couldn't find/parse buy instruction in a Create transaction
        return False, None
    
    # Check against threshold
    should_process = buy_amount <= CREATOR_INITIAL_BUY_THRESHOLD
    return should_process, buy_amount