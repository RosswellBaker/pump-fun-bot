from typing import Optional, Tuple, Dict
from solders.signature import Signature
from solana.rpc.async_api import AsyncClient
import base64
import struct
import os
import asyncio
from collections import deque
from time import time

# Replace with your actual Helius RPC endpoint
FILTER_RPC_ENDPOINT = os.getenv("FILTER_RPC_ENDPOINT")
if not FILTER_RPC_ENDPOINT:
    raise ValueError("FILTER_RPC_ENDPOINT environment variable not set")

rpc_client = AsyncClient(FILTER_RPC_ENDPOINT)

# Configurable threshold for the creator's initial buy amount
CREATOR_INITIAL_BUY_THRESHOLD = 50000000  # 50 million tokens
BUY_DISCRIMINATOR = 16927863322537952870  # Replace with actual value from PumpFun IDL
AMOUNT_OFFSET = 8  # Replace with actual offset
AMOUNT_SIZE = 8  # For u64
TOKEN_DECIMALS = 6  # PumpFun uses 6 decimals

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

async def fetch_transaction_data(signature: str, max_retries: int = 5, retry_delay: float = 2.0) -> Optional[Dict]:
    """
    Fetch transaction data using the Helius RPC endpoint.

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
            transaction_response = await rpc_client.get_transaction(
                Signature.from_string(signature),
                encoding="jsonParsed",
                commitment="finalized"
            )

            if transaction_response and transaction_response.value:
                return transaction_response.value

            await asyncio.sleep(retry_delay)

        except Exception:
            await asyncio.sleep(retry_delay)

    return None

def extract_buy_instruction_amount(transaction_data: Dict) -> Optional[float]:
    """
    Extract the buy instruction amount from the transaction data.

    Args:
        transaction_data: The transaction data dictionary fetched from the RPC.

    Returns:
        The buy amount as a float (in tokens), or None if not a relevant buy instruction or amount extraction fails.
    """
    try:
        instructions_to_check = []
        if "instructions" in transaction_data["transaction"]["message"]:
            instructions_to_check.extend(transaction_data["transaction"]["message"]["instructions"])
        if "innerInstructions" in transaction_data["meta"]:
            for inner_instruction_list in transaction_data["meta"]["innerInstructions"]:
                instructions_to_check.extend(inner_instruction_list["instructions"])

        for instruction in instructions_to_check:
            program_id = instruction.get("programId")
            if program_id == "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P":  # PumpFun program ID
                if "data" in instruction:
                    data = instruction["data"]
                    decoded_data = base64.b64decode(data)

                    if len(decoded_data) >= AMOUNT_OFFSET + AMOUNT_SIZE:
                        discriminator = struct.unpack("<Q", decoded_data[:8])[0]
                        if discriminator == BUY_DISCRIMINATOR:
                            amount_raw = struct.unpack("<Q", decoded_data[AMOUNT_OFFSET:AMOUNT_OFFSET + AMOUNT_SIZE])[0]
                            return amount_raw / (10 ** TOKEN_DECIMALS)

        return None

    except Exception:
        return None

async def should_process_token(signature: str) -> Tuple[bool, Optional[float]]:
    """
    Determines whether a token should be processed based on the creator's initial buy amount.

    Args:
        signature: Transaction signature.

    Returns:
        Tuple of (should_process, creator_buy_amount).
    """
    transaction_data = await fetch_transaction_data(signature)
    if not transaction_data:
        return False, None

    creator_buy_amount = extract_buy_instruction_amount(transaction_data)
    if creator_buy_amount is None:
        return False, None

    return creator_buy_amount <= CREATOR_INITIAL_BUY_THRESHOLD, creator_buy_amount