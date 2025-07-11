from typing import Optional, Tuple, Dict, List
from solders.signature import Signature
from solana.rpc.async_api import AsyncClient
import base64
import struct
import os
import asyncio
from collections import deque
from time import time
from enum import Enum

# Configure RPC endpoint
FILTER_RPC_ENDPOINT = os.getenv("FILTER_RPC_ENDPOINT")
if not FILTER_RPC_ENDPOINT:
    raise ValueError("FILTER_RPC_ENDPOINT environment variable not set")

rpc_client = AsyncClient(FILTER_RPC_ENDPOINT)

# Pump.fun constants
CREATOR_BUY_AMOUNT_THRESHOLD = 50000000  # 50 million tokens
TOKEN_DECIMALS = 6  # Pump.fun uses 6 decimals
PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"

# Discriminator bytes - verified from multiple sources
BUY_DISCRIMINATOR_BYTES = bytes([102, 6, 61, 18, 1, 218, 235, 234])  # global:buy
CREATE_DISCRIMINATOR_BYTES = bytes([24, 30, 200, 40, 5, 28, 7, 119])  # global:create

class TransactionType(Enum):
    CREATE = "create"
    BUY = "buy"
    SELL = "sell"
    UNKNOWN = "unknown"

# Rate Limiter
class RateLimiter:
    def __init__(self, max_requests: int, time_window: float):
        self.max_requests = max_requests
        self.time_window = time_window
        self.request_times = deque()

    async def acquire(self):
        now = time()
        # Remove old requests outside the time window
        while self.request_times and now - self.request_times[0] > self.time_window:
            self.request_times.popleft()
        
        # Wait if we've hit the rate limit
        while len(self.request_times) >= self.max_requests:
            sleep_time = self.time_window - (now - self.request_times[0]) + 0.01
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
            now = time()
            while self.request_times and now - self.request_times[0] > self.time_window:
                self.request_times.popleft()
        
        self.request_times.append(now)

# Initialize rate limiter - Helius free tier: 10 RPS
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
    for attempt in range(max_retries):
        await rate_limiter.acquire()
        
        try:
            # Use jsonParsed encoding for better data structure
            transaction_response = await rpc_client.get_transaction(
                Signature.from_string(signature),
                encoding="jsonParsed",
                commitment="confirmed",
                max_supported_transaction_version=0
            )
            
            if transaction_response and transaction_response.value:
                return transaction_response.value
            
            # If transaction not found, wait and retry
            await asyncio.sleep(retry_delay * (attempt + 1))
            
        except Exception as e:
            # Log error for debugging but continue retrying
            if attempt == max_retries - 1:
                print(f"Error fetching transaction {signature}: {str(e)}")
            await asyncio.sleep(retry_delay * (attempt + 1))
    
    return None

def get_instruction_type(instruction_data: bytes) -> TransactionType:
    """Identify the instruction type based on discriminator."""
    if len(instruction_data) < 8:
        return TransactionType.UNKNOWN
    
    discriminator = instruction_data[:8]
    
    if discriminator == CREATE_DISCRIMINATOR_BYTES:
        return TransactionType.CREATE
    elif discriminator == BUY_DISCRIMINATOR_BYTES:
        return TransactionType.BUY
    else:
        return TransactionType.UNKNOWN

def extract_buy_amount_from_instruction(instruction_data: bytes) -> Optional[int]:
    """
    Extract the buy amount from a buy instruction.
    Buy instruction layout:
    - [0:8] discriminator
    - [8:16] amount (u64, little-endian)
    - [16:24] max_sol_cost (u64, little-endian)
    """
    if len(instruction_data) < 16:
        return None
    
    try:
        # Extract amount (first u64 after discriminator)
        amount_raw = struct.unpack("<Q", instruction_data[8:16])[0]
        return amount_raw
    except Exception:
        return None

def find_creator_buy_instruction(transaction: Dict) -> Optional[Tuple[int, str]]:
    """
    Find the buy instruction in a creation transaction and extract the amount.
    Returns tuple of (buy_amount, creator_address) or None if not found.
    """
    if not transaction:
        return None
    
    try:
        # Get the message and instructions
        message = transaction.get("transaction", {}).get("message", {})
        instructions = message.get("instructions", [])
        
        # Get account keys for resolving addresses
        account_keys = message.get("accountKeys", [])
        
        # Track if we found a create instruction
        found_create = False
        creator_address = None
        
        # First pass: check for create instruction and get creator
        for ix in instructions:
            program_id = ix.get("programId", "")
            
            if program_id != PUMP_PROGRAM_ID:
                continue
            
            # For parsed instructions
            if "parsed" in ix:
                continue
            
            # For raw instructions, decode the data
            data_str = ix.get("data", "")
            if not data_str:
                continue
            
            try:
                instruction_data = base64.b64decode(data_str)
            except:
                continue
            
            instruction_type = get_instruction_type(instruction_data)
            
            if instruction_type == TransactionType.CREATE:
                found_create = True
                # Get creator from instruction accounts (index 7 is typically the user/creator)
                accounts = ix.get("accounts", [])
                if len(accounts) > 7:
                    creator_idx = accounts[7]
                    if creator_idx < len(account_keys):
                        creator_key = account_keys[creator_idx]
                        if isinstance(creator_key, dict):
                            creator_address = creator_key.get("pubkey", "")
                        else:
                            creator_address = str(creator_key)
        
        # If no create instruction found, this isn't a creation transaction
        if not found_create:
            return None
        
        # Second pass: find buy instruction and verify it's from the creator
        for ix in instructions:
            program_id = ix.get("programId", "")
            
            if program_id != PUMP_PROGRAM_ID:
                continue
            
            # Skip parsed instructions
            if "parsed" in ix:
                continue
            
            data_str = ix.get("data", "")
            if not data_str:
                continue
            
            try:
                instruction_data = base64.b64decode(data_str)
            except:
                continue
            
            instruction_type = get_instruction_type(instruction_data)
            
            if instruction_type == TransactionType.BUY:
                # Verify this buy is from the creator
                accounts = ix.get("accounts", [])
                if len(accounts) > 6:  # Index 6 is the user in buy instruction
                    buyer_idx = accounts[6]
                    if buyer_idx < len(account_keys):
                        buyer_key = account_keys[buyer_idx]
                        buyer_address = ""
                        if isinstance(buyer_key, dict):
                            buyer_address = buyer_key.get("pubkey", "")
                        else:
                            buyer_address = str(buyer_key)
                        
                        # Verify buyer is the creator
                        if buyer_address == creator_address:
                            buy_amount = extract_buy_amount_from_instruction(instruction_data)
                            if buy_amount is not None:
                                return (buy_amount, creator_address)
        
        # If we found a create but no buy from creator, treat as 0 buy
        return (0, creator_address)
        
    except Exception as e:
        print(f"Error parsing transaction: {str(e)}")
        return None

async def should_process_token(signature: str) -> Tuple[bool, Optional[float]]:
    """
    Determines whether a token should be processed based on the creator's initial buy amount.
    
    Args:
        signature: Transaction signature to check
        
    Returns:
        Tuple of (should_process, creator_buy_amount_in_tokens)
    """
    # Fetch transaction data
    transaction_data = await fetch_transaction_data(signature)
    if not transaction_data:
        # If we can't fetch the transaction, we can't verify it, so skip
        return False, None
    
    # Check if this is a creation transaction and extract buy amount
    result = find_creator_buy_instruction(transaction_data)
    
    if result is None:
        # Not a creation transaction or couldn't parse
        return False, None
    
    buy_amount_raw, creator_address = result
    
    # Convert to token amount (considering 6 decimals)
    creator_buy_amount = buy_amount_raw / (10 ** TOKEN_DECIMALS)
    
    # Check against threshold
    should_process = creator_buy_amount <= CREATOR_BUY_AMOUNT_THRESHOLD
    
    return should_process, creator_buy_amount

# Optional: Close RPC client when done
async def cleanup():
    """Clean up resources."""
    await rpc_client.close()