# filters.py

import os
import asyncio
import base64
import struct
from collections import deque
from time import time
from typing import Optional, Tuple, Dict, Any

from solana.rpc.async_api import AsyncClient
from solders.signature import Signature

# ─── CONFIGURATION ─────────────────────────────────────────────────────────────

# JSON-RPC endpoint (e.g. your Helius free-tier URL)
FILTER_RPC_ENDPOINT = os.getenv("FILTER_RPC_ENDPOINT")
if not FILTER_RPC_ENDPOINT:
    raise ValueError("FILTER_RPC_ENDPOINT environment variable not set")

# Pump.fun program and buy() discriminator
PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
BUY_DISCRIMINATOR = bytes([102, 6, 61, 18, 1, 218, 235, 234])

# Token decimals and creator buy threshold (in whole tokens)
TOKEN_DECIMALS = 6
CREATOR_BUY_THRESHOLD = 50_000_000

# ─── RPC CLIENT & RATE LIMITER ─────────────────────────────────────────────────

rpc_client = AsyncClient(FILTER_RPC_ENDPOINT)

class RateLimiter:
    """Keep under ~8 requests/sec to avoid Helius 429s."""
    def __init__(self, max_requests: int = 8, per_seconds: float = 1.0):
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self.requests = deque()

    async def acquire(self):
        now = time()
        # remove stale
        while self.requests and now - self.requests[0] > self.per_seconds:
            self.requests.popleft()
        if len(self.requests) >= self.max_requests:
            await asyncio.sleep(self.per_seconds - (now - self.requests[0]))
        self.requests.append(now)

rate_limiter = RateLimiter()

# ─── CORE FUNCTIONS ────────────────────────────────────────────────────────────

async def fetch_transaction(sig_str: str) -> Optional[Dict[str, Any]]:
    """
    Fetch a confirmed transaction with jsonParsed encoding so that
    innerInstructions and logMessages are included.
    """
    sig = Signature.from_string(sig_str)
    for _ in range(5):
        await rate_limiter.acquire()
        resp = await rpc_client.get_transaction(
            sig,
            encoding="jsonParsed",
            commitment="confirmed",
            max_supported_transaction_version=0
        )
        if resp and resp.value:
            return resp.value  # type: ignore
        await asyncio.sleep(0.5)
    return None

def extract_buy_amount(txn: Dict[str, Any]) -> Optional[float]:
    """
    Scan meta.innerInstructions for the Pump.fun buy() call,
    decode its 8-byte u64 amount, and return normalized tokens.
    """
    for group in txn.get("meta", {}).get("innerInstructions", []):
        for instr in group.get("instructions", []):
            if instr.get("programId") != PUMP_PROGRAM_ID:
                continue
            data_b64 = instr.get("data", "")
            try:
                raw = base64.b64decode(data_b64)
            except Exception:
                continue
            if len(raw) < 16 or raw[:8] != BUY_DISCRIMINATOR:
                continue
            amount_raw = struct.unpack("<Q", raw[8:16])[0]
            return amount_raw / (10 ** TOKEN_DECIMALS)
    return None

async def should_process_token(signature: str) -> Tuple[bool, Optional[float]]:
    """
    Gatekeeper filter:
      1. Fetch the full transaction for this mint signature.
      2. Ensure it’s a true mint: logs contain "Instruction: Create"
         and do NOT contain "Instruction: CreateTokenAccount".
      3. Extract the buy() amount (always present) and compare to threshold.
      4. Return (True, amount) if ≤ threshold (allow processing),
         else (False, amount) to skip.
    """
    txn = await fetch_transaction(signature)
    if not txn:
        return False, None

    # 1) Confirm this is a Pump.fun mint
    logs = txn.get("meta", {}).get("logMessages", [])
    if not any("Program log: Instruction: Create" in msg for msg in logs):
        return False, None
    if any("Program log: Instruction: CreateTokenAccount" in msg for msg in logs):
        return False, None

    # 2) Extract buy amount and apply threshold
    amount = extract_buy_amount(txn)
    if amount is None:
        return False, None

    return (amount <= CREATOR_BUY_THRESHOLD), amount
