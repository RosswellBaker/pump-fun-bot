from typing import Optional, Tuple, Dict
from solders.signature import Signature
from solana.rpc.async_api import AsyncClient
import base64
import base58
import struct
import os
import asyncio
from collections import deque
from time import time

# Configure RPC endpoint
FILTER_RPC_ENDPOINT = os.getenv("FILTER_RPC_ENDPOINT")
if not FILTER_RPC_ENDPOINT:
    raise ValueError("FILTER_RPC_ENDPOINT environment variable not set")

rpc_client = AsyncClient(FILTER_RPC_ENDPOINT)

# Pump.fun constants
CREATOR_BUY_AMOUNT_THRESHOLD = 50000000  # 50 million tokens
TOKEN_DECIMALS = 6  # Pump.fun uses 6 decimals
PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"

# FIXED: Use correct discriminator from repository (calculate_discriminator.py)
BUY_DISCRIMINATOR = 16927863322537952870  # global:buy discriminator

# Rate Limiter
class RateLimiter:
    def __init__(self, max_requests: int, time_window: float):
        self.max_requests = max_requests
        self.time_window = time_window
        self.request_times = deque()

    async def acquire(self):
        while len(self.request_times) >= self.max_requests:
            now = time()
            if now - self.request_times[0] > self.time_window:
                self.request_times.popleft()
            else:
                await asyncio.sleep(self.time_window - (now - self.request_times[0]))
        self.request_times.append(time())

rate_limiter = RateLimiter(max_requests=8, time_window=1.0)

async def fetch_transaction_data(signature: str, max_retries: int = 5, retry_delay: float = 0.5) -> Optional[Dict]:
    """
    Fetch transaction data using the configured RPC endpoint.
    
    Args:
        signature: Transaction signature as a string.
        max_retries: Maximum number of retry attempts.
        retry_delay: Delay between retries in seconds.
        
    Returns:
        Decoded transaction data if found, otherwise None.
    """
    await rate_limiter.acquire()
    
    for attempt in range(max_retries):
        try:
            # Critical fix: Add maxSupportedTransactionVersion parameter
            transaction_response = await rpc_client.get_transaction(
                Signature.from_string(signature),
                encoding="jsonParsed",
                commitment="confirmed",
                maxSupportedTransactionVersion=0  # Required for newer Solana transactions
            )
            
            if transaction_response and transaction_response.value:
                return transaction_response.value
                
            await asyncio.sleep(retry_delay)
            
        except Exception:
            await asyncio.sleep(retry_delay)
            
    return None

def extract_buy_instruction_amount(transaction_data: Dict) -> Optional[float]:
    """
    Extract the buy instruction amount from transaction data.
    
    Args:
        transaction_data: The transaction data dictionary fetched from the RPC.
        
    Returns:
        The buy amount as a float (in tokens), or None if not a relevant buy instruction or amount extraction fails.
    """
    try:
        instructions_to_check = []
        
        # Add main instructions
        if "instructions" in transaction_data["transaction"]["message"]:
            instructions_to_check.extend(transaction_data["transaction"]["message"]["instructions"])
        
        # Add inner instructions if available
        if "innerInstructions" in transaction_data["meta"]:
            for inner_instruction_list in transaction_data["meta"]["innerInstructions"]:
                instructions_to_check.extend(inner_instruction_list["instructions"])
                
        # Check each instruction
        for instruction in instructions_to_check:
            program_id = instruction.get("programId")
            
            # Only check instructions from the pump.fun program
            if program_id == PUMP_PROGRAM_ID:
                if "data" in instruction:
                    data = instruction["data"]
                    decoded_data = None
                    
                    # Try both base64 and base58 decoding
                    try:
                        # Try base64 first (most common in jsonParsed encoding)
                        decoded_data = base64.b64decode(data)
                    except:
                        try:
                            # Fallback to base58 if base64 fails
                            decoded_data = base58.b58decode(data)
                        except:
                            continue
                    
                    # Ensure minimum length for discriminator + amount
                    if decoded_data and len(decoded_data) >= 16:  # 8 bytes discriminator + 8 bytes amount
                        # FIXED: Compare discriminator as integer (same as repository)
                        discriminator = struct.unpack("<Q", decoded_data[:8])[0]
                        if discriminator == BUY_DISCRIMINATOR:
                            # Extract amount (next 8 bytes after discriminator) as u64
                            amount_raw = struct.unpack("<Q", decoded_data[8:16])[0]
                            # Convert from raw units to token units (6 decimals)
                            return amount_raw / (10 ** TOKEN_DECIMALS)
        
        return None
        
    except Exception:
        return None

async def should_process_token(signature: str) -> Tuple[bool, Optional[float]]:
    """
    Determines whether a token should be processed based on the creator's initial buy amount.
    """
    transaction_data = await fetch_transaction_data(signature)
    if not transaction_data:
        return False, None

    # Quick pre-check: Only process creation transactions
    logs = transaction_data.get("meta", {}).get("logMessages", [])
    if not any("Program log: Instruction: Create" in log for log in logs):
        return False, None

    creator_buy_amount = extract_buy_instruction_amount(transaction_data)
    
    # FIXED: If no buy instruction found, treat as 0 (creator didn't buy = PERFECT TARGET)
    if creator_buy_amount is None:
        creator_buy_amount = 0.0

    # Return True if amount is below or equal to threshold, False otherwise
    return creator_buy_amount <= CREATOR_BUY_AMOUNT_THRESHOLD, creator_buy_amount