"""
Filter for pump.fun tokens based on creator's initial buy amount.
Follows the same pattern as logs_event_processor.py
"""

import base64
import struct
from typing import Optional, List

# Filter configuration
CREATOR_INITIAL_BUY_THRESHOLD = 50_000_000  # 50 million tokens
BUY_DISCRIMINATOR = bytes([102, 6, 61, 18, 1, 218, 235, 234])  # Buy instruction discriminator
PUMP_TOKEN_DECIMALS = 6  # Pump.fun tokens use 6 decimals

def should_process_token(logs: List[str], signature: str) -> tuple[bool, Optional[float]]:
    """
    Filter pump.fun tokens based on creator's initial buy amount.
    
    Follows the same pattern as logs_event_processor.py - processes logs directly
    to find buy instructions and extract the amount field.
    
    Args:
        logs: List of log strings from logsSubscribe notification  
        signature: Transaction signature (for logging purposes)
        
    Returns:
        tuple[bool, Optional[float]]: (should_process, buy_amount_in_tokens)
            - should_process: True if token should be processed, False to skip
            - buy_amount_in_tokens: Creator's buy amount in tokens, None if not found
    """
    try:
        # Process logs directly (same pattern as event processor)
        for log in logs:
            # Look for program data entries (same as event processor)
            if "Program data:" not in log:
                continue
                
            try:
                # Extract and decode program data (same as event processor)
                encoded_data = log.split(": ")[1]
                decoded_data = base64.b64decode(encoded_data)
                
                # Need at least 16 bytes for buy instruction (8 discriminator + 8 amount)
                if len(decoded_data) < 16:
                    continue
                
                # Check if this is a buy instruction (compare discriminator bytes directly)
                if decoded_data[:8] != BUY_DISCRIMINATOR:
                    continue
                
                # Extract amount field from buy instruction (bytes 8-15)
                amount_raw = struct.unpack("<Q", decoded_data[8:16])[0]
                
                # Scale by pump.fun decimals to get actual token amount
                amount_tokens = amount_raw / (10 ** PUMP_TOKEN_DECIMALS)
                
                # Apply filter logic: allow if creator bought ≤ threshold
                should_process = amount_tokens <= CREATOR_INITIAL_BUY_THRESHOLD
                
                return should_process, amount_tokens
                
            except Exception:
                # Skip malformed log entries
                continue
        
        # No buy instruction found in any log entry
        return False, None
        
    except Exception:
        # Any error - skip token to maintain stability
        return False, None