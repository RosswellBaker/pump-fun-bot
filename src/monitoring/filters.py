from typing import Optional, Tuple
import base64
import struct

# Pump.fun constants
CREATOR_BUY_AMOUNT_THRESHOLD = 50_000_000  # 50 million tokens
TOKEN_DECIMALS = 6  # Pump.fun uses 6 decimals
BUY_DISCRIMINATOR_BYTES = bytes([102, 6, 61, 18, 1, 218, 235, 234])  # global:buy


def should_process_token(logs: list[str], signature: str) -> Tuple[bool, Optional[float]]:
    """
    Filters token mints by decoding logs to find the creator's buy() amount.

    Args:
        logs: List of log strings from logsSubscribe
        signature: Transaction signature (for logging only)

    Returns:
        (should_process, buy_amount)
    """
    for log in logs:
        if not log.startswith("Program data: "):
            continue

        b64_str = log.replace("Program data: ", "")
        try:
            raw = base64.b64decode(b64_str)
        except Exception:
            continue

        if len(raw) < 16:
            continue

        if raw[:8] != BUY_DISCRIMINATOR_BYTES:
            continue

        amount_raw = struct.unpack("<Q", raw[8:16])[0]
        buy_amount = amount_raw / (10 ** TOKEN_DECIMALS)
        return buy_amount <= CREATOR_BUY_AMOUNT_THRESHOLD, buy_amount

    # If no valid buy() instruction found, treat as 0 = perfect target
    return True, 0.0
