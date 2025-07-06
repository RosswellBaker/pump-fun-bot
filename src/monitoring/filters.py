from typing import Optional, Tuple, Dict
from solders.signature import Signature
from solana.rpc.async_api import AsyncClient
import base64
import base58
import hashlib
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
CREATOR_INITIAL_BUY_THRESHOLD = 50000000  # 50 million tokens
TOKEN_DECIMALS = 6  # Pump.fun uses 6 decimals
PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"

# Calculate the correct discriminator for "global:buy" instruction
def get_discriminator(name: str) -> bytes:
    return hashlib.sha256(f"global:{name}".encode()).digest()[:8]

BUY_DISCRIMINATOR = get_discriminator("buy")

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
    """
    await rate_limiter.acquire()

    for attempt in range(max_retries):
        try:
            transaction_response = await rpc_client.get_transaction(
                Signature.from_string(signature),
                encoding="jsonParsed",
                commitment="confirmed"
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
                    # Base58 decode the instruction data
                    data = instruction["data"]
                    decoded_data = base58.b58decode(data)
                    
                    # Ensure minimum length for discriminator + amount
                    if len(decoded_data) >= 16:
                        # Compare discriminator (first 8 bytes)
                        if decoded_data[:8] == BUY_DISCRIMINATOR:
                            # Extract amount (next 8 bytes after discriminator)
                            amount_raw = int.from_bytes(decoded_data[8:16], byteorder="little")
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

    creator_buy_amount = extract_buy_instruction_amount(transaction_data)
    if creator_buy_amount is None:
        return False, None

    # Return True if amount is below threshold, False otherwise
    return creator_buy_amount <= CREATOR_INITIAL_BUY_THRESHOLD, creator_buy_amount