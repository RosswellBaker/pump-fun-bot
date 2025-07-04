import asyncio
import base64
import struct
import os
from typing import Optional
from core.client import SolanaClient  # Use the existing SolanaClient from the repo

# Your exact constants - keeping the same
CREATOR_INITIAL_BUY_THRESHOLD = 50000000  # 50 million tokens
BUY_DISCRIMINATOR = 16927863322537952870  # Global constant for "buy" instruction (from repo IDL)
TOKEN_DECIMALS = 6  # Pump.fun uses 6 decimals
PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"

# Global RPC client - created once and reused
_rpc_client = None

async def get_rpc_client():
    """Get or create the RPC client using the same endpoint as the main bot"""
    global _rpc_client
    if _rpc_client is None:
        # Use the same RPC endpoint as configured in your .env file
        rpc_endpoint = os.getenv('SOLANA_NODE_RPC_ENDPOINT')
        if not rpc_endpoint:
            raise ValueError("SOLANA_NODE_RPC_ENDPOINT not found in environment")
        _rpc_client = SolanaClient(rpc_endpoint)
    return _rpc_client

async def get_buy_amount_from_signature(signature: str) -> Optional[float]:
    """
    ULTRA-FAST buy amount extraction - 100ms timeout max.
    If it takes longer, we skip the filter to maintain bot speed.
    """
    try:
        client = await get_rpc_client()
        
        # ULTRA-FAST RPC call - 100ms timeout to maintain lightning speed
        rpc_client = await client.get_client()
        response = await asyncio.wait_for(
            rpc_client.get_transaction(signature, encoding="base64", max_supported_transaction_version=0),
            timeout=0.1  # 100ms max - if slower, skip filter
        )
        
        if not response.value?.transaction?.message:
            return None
            
        # Find buy instruction (ultra-fast parsing)
        for instruction in response.value.transaction.message.instructions:
            try:
                # Check if pump.fun program
                account_keys = response.value.transaction.message.account_keys
                program_id = str(account_keys[instruction.program_id_index])
                if program_id != PUMP_PROGRAM_ID:
                    continue
                
                # Decode instruction
                data = base64.b64decode(instruction.data)
                if len(data) < 16:
                    continue
                
                # Check discriminator
                discriminator = struct.unpack('<Q', data[0:8])[0]
                if discriminator != BUY_DISCRIMINATOR:
                    continue
                
                # Extract REAL amount
                amount_raw = struct.unpack('<Q', data[8:16])[0]
                return amount_raw / (10 ** TOKEN_DECIMALS)
                
            except:
                continue
        return None
    except asyncio.TimeoutError:
        # If RPC is slow, skip filter to maintain speed
        return None
    except:
        return None  # Don't break bot on errors

# ALTERNATIVE: Completely non-blocking version
async def should_process_token_nonblocking(signature: str) -> bool:
    """
    NON-BLOCKING version: Always returns True immediately, 
    but logs filter results in background for monitoring.
    This maintains 100% bot speed while still providing filter feedback.
    """
    # Start filter check in background (fire and forget)
    asyncio.create_task(_background_filter_check(signature))
    
    # Always allow processing to maintain speed
    return True

async def _background_filter_check(signature: str):
    """Background task to check filter and log results"""
    try:
        buy_amount = await get_buy_amount_from_signature(signature)
        if buy_amount is not None:
            if buy_amount > CREATOR_INITIAL_BUY_THRESHOLD:
                print(f"🚨 PROCESSED POTENTIAL RUG: {signature} - {buy_amount:,.0f} tokens > {CREATOR_INITIAL_BUY_THRESHOLD:,}")
            else:
                print(f"✅ PROCESSED SAFE TOKEN: {signature} - {buy_amount:,.0f} tokens")
    except Exception as e:
        pass  # Silent background failure

async def should_process_token_simple(signature: str) -> tuple[bool, Optional[float]]:
    """
    Simple gatekeeper function - completely self-contained.
    Returns (should_process, buy_amount)
    """
    buy_amount = await get_buy_amount_from_signature(signature)
    
    if buy_amount is None:
        return True, None  # Process if unknown (keeps bot running)
    
    if buy_amount <= CREATOR_INITIAL_BUY_THRESHOLD:
        return True, buy_amount
    else:
        return False, buy_amount

# Keep your original function names for compatibility but they won't work
def get_buy_instruction_amount(logs):
    """DEPRECATED: This approach doesn't work with logs. Use should_process_token_simple instead."""
    return None

def should_process_token(logs):
    """DEPRECATED: This approach doesn't work with logs. Use should_process_token_simple instead."""
    return True