import asyncio
import aiohttp
import json
import base64
import struct
from typing import Optional
import os

# Filter configuration  
CREATOR_INITIAL_BUY_THRESHOLD = 50_000_000  # 50 million tokens
PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
BUY_DISCRIMINATOR = bytes([102, 6, 61, 18, 1, 218, 235, 234])  # Correct from research
PUMP_TOKEN_DECIMALS = 6  # Pump.fun tokens use 6 decimals

async def should_process_token(signature: str) -> tuple[bool, Optional[float]]:
    """
    Fast gatekeeper filter for pump.fun tokens.
    
    Checks if creator's initial buy amount is reasonable (≤50M tokens).
    Returns (should_process, buy_amount) tuple.
    
    Args:
        signature: Transaction signature from logs_listener
        
    Returns:
        tuple[bool, Optional[float]]: (should_process, buy_amount_in_tokens)
    """
    try:
        # Use dedicated filter RPC endpoint (Helius free) with fallback to main RPC
        rpc_endpoint = os.getenv("FILTER_RPC_ENDPOINT") or os.getenv("SOLANA_NODE_RPC_ENDPOINT")
        
        # Fast RPC call to get transaction data
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction", 
            "params": [
                signature,
                {
                    "encoding": "json",
                    "commitment": "confirmed",
                    "maxSupportedTransactionVersion": 0
                }
            ]
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                rpc_endpoint, 
                json=payload, 
                timeout=aiohttp.ClientTimeout(total=1.0)
            ) as response:
                if response.status != 200:
                    return False, None
                    
                data = await response.json()
                
                # Check if transaction exists
                if not data.get("result"):
                    return False, None
                
                # Extract transaction instructions
                transaction = data["result"]["transaction"]
                message = transaction["message"]
                instructions = message["instructions"]
                account_keys = message["accountKeys"]
                
                # Find pump.fun buy instruction
                for instruction in instructions:
                    # Check if instruction is for pump.fun program
                    program_idx = instruction.get("programIdIndex")
                    if program_idx is None or program_idx >= len(account_keys):
                        continue
                        
                    if account_keys[program_idx] != PUMP_PROGRAM_ID:
                        continue
                    
                    # Get instruction data
                    instruction_data = instruction.get("data", "")
                    if not instruction_data:
                        continue
                    
                    # Decode base64 instruction data
                    try:
                        decoded = base64.b64decode(instruction_data)
                    except:
                        continue
                        
                    # Need at least 16 bytes (8 discriminator + 8 amount)
                    if len(decoded) < 16:
                        continue
                    
                    # Check buy instruction discriminator (compare bytes directly)
                    if decoded[:8] != BUY_DISCRIMINATOR:
                        continue
                    
                    # Extract amount field (bytes 8-15) - creator's token buy amount
                    amount_raw = struct.unpack("<Q", decoded[8:16])[0]
                    
                    # Scale by 6 decimals to get actual token amount
                    amount_tokens = amount_raw / (10 ** PUMP_TOKEN_DECIMALS)
                    
                    # Apply filter: allow if creator bought ≤ 50M tokens
                    should_process = amount_tokens <= CREATOR_INITIAL_BUY_THRESHOLD
                    
                    return should_process, amount_tokens
                
                # No buy instruction found
                return False, None
                
    except asyncio.TimeoutError:
        # RPC timeout - skip token to maintain speed
        return False, None
    except Exception:
        # Any other error - skip token to maintain stability
        return False, None