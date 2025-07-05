from typing import Optional, Tuple
import base64
import struct
import os
import json
from websockets import connect
import asyncio
from collections import deque
from time import time

# Configurable threshold for the creator's initial buy amount
CREATOR_INITIAL_BUY_THRESHOLD = 50000000  # 50 million tokens
BUY_DISCRIMINATOR = 16927863322537952870  # Global constant for "buy" instruction
TOKEN_DECIMALS = 6  # Pump.fun uses 6 decimals
FILTER_WSS_ENDPOINT = os.getenv("FILTER_WSS_ENDPOINT")  # Use the WebSocket endpoint from .env

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

async def fetch_transaction_data(signature: str) -> Optional[dict]:
    await rate_limiter.acquire()
    try:
        async with connect(FILTER_WSS_ENDPOINT) as websocket:
            subscription_message = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getTransaction",
                    "params": [
                        signature,
                        {"encoding": "jsonParsed"}
                    ]
                }
            )
            await websocket.send(subscription_message)
            response = await websocket.recv()
            return json.loads(response).get("result", None)
    except Exception:
        return None

def extract_buy_instruction_amount(transaction_data: dict) -> Optional[float]:
    try:
        message = transaction_data["transaction"]["message"]
        instructions = message["instructions"]

        for instruction in instructions:
            program_id = instruction["programId"]
            if program_id == "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P":
                data = instruction["data"]
                decoded_data = base64.b64decode(data)
                discriminator = struct.unpack("<Q", decoded_data[:8])[0]

                if discriminator == BUY_DISCRIMINATOR:
                    amount_raw = struct.unpack("<Q", decoded_data[8:16])[0]
                    return amount_raw / (10 ** TOKEN_DECIMALS)
    except Exception:
        return None

async def should_process_token(signature: str) -> Tuple[bool, Optional[float]]:
    transaction_data = await fetch_transaction_data(signature)
    if not transaction_data:
        return False, None

    creator_buy_amount = extract_buy_instruction_amount(transaction_data)
    if creator_buy_amount is None:
        return False, None

    return creator_buy_amount <= CREATOR_INITIAL_BUY_THRESHOLD, creator_buy_amount