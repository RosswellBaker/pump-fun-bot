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
    
    Based on actual Solscan data, we know:
    - There are multiple Program data entries in a pump.fun mint transaction
    - The Buy instruction data contains discriminator + amount + max_sol_cost
    - We need to check ALL Program data entries to find the right one

    Args:
        logs: The logs from the transaction.

    Returns:
        The scaled amount as a float if found, otherwise None.
    """
    # Look for the Buy instruction log first to confirm it exists
    has_buy_instruction = False
    buy_instruction_index = -1
    
    for i, log in enumerate(logs):
        if "Program log: Instruction: Buy" in log:
            has_buy_instruction = True
            buy_instruction_index = i
            break
    
    if not has_buy_instruction:
        return None
    
    # Now find the Program data that comes AFTER the Buy instruction
    # In pump.fun transactions, the Program data follows shortly after the instruction
    for i in range(buy_instruction_index, min(buy_instruction_index + 50, len(logs))):
        if i >= len(logs):
            break
            
        log = logs[i]
        if "Program data:" not in log:
            continue
        
        try:
            # Extract the base64 data
            # The log format is: "Program data: <base64data>"
            if "Program data: " not in log:
                continue
                
            data_start = log.find("Program data: ") + 14  # Length of "Program data: "
            encoded_data = log[data_start:].strip()
            
            # Decode the base64 data
            decoded_data = base64.b64decode(encoded_data)
            
            # Check if it's long enough for a buy instruction (24 bytes minimum)
            if len(decoded_data) < 24:
                continue
            
            # Check the discriminator (first 8 bytes)
            discriminator = struct.unpack("<Q", decoded_data[:8])[0]
            
            if discriminator == BUY_DISCRIMINATOR:
                # Found the buy instruction data!
                # Extract amount (bytes 8-16) and max_sol_cost (bytes 16-24)
                amount_raw = struct.unpack("<Q", decoded_data[8:16])[0]
                
                # Convert to decimal representation
                scaled_amount = amount_raw / (10 ** TOKEN_DECIMALS)
                
                # Return the scaled amount (even if it's 0)
                return scaled_amount
                
        except Exception as e:
            # Log the error for debugging and continue to the next log
            print(f"Error parsing Program data: {e}")
            continue
    
    # If we get here, we found a Buy instruction but couldn't parse its data
    return None


def should_process_token(logs: List[str], signature: str) -> Tuple[bool, Optional[float]]:
    """
    Determines whether a token should be processed based on the creator's initial buy amount.
    
    This is the gatekeeper for pump.fun token creations. We only filter CREATE transactions
    where the creator buys too much of the supply.

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
        # Could be a regular buy/sell or other pump.fun operation
        return True, None
    
    # This is a token creation. Now check the creator's buy amount.
    buy_amount = get_buy_instruction_amount(logs)
    
    if buy_amount is None:
        # Couldn't find/parse buy instruction in a Create transaction
        # This is unusual - skip to be safe
        return False, None
    
    # Check against threshold
    should_process = buy_amount <= CREATOR_INITIAL_BUY_THRESHOLD
    return should_process, buy_amount