"""
WebSocket monitoring for pump.fun tokens using logsSubscribe.
"""

import asyncio
import json
from collections.abc import Awaitable, Callable
import os
import base64
import struct

import websockets
from solders.pubkey import Pubkey

from monitoring.base_listener import BaseTokenListener
from monitoring.logs_event_processor import LogsEventProcessor
from trading.base import TokenInfo
from utils.logger import get_logger

logger = get_logger(__name__)


class LogsListener(BaseTokenListener):
    """WebSocket listener for pump.fun token creation events using logsSubscribe."""

    def __init__(self, wss_endpoint: str, pump_program: Pubkey):
        """Initialize token listener.

        Args:
            wss_endpoint: WebSocket endpoint URL
            pump_program: Pump.fun program address
        """
        self.wss_endpoint = wss_endpoint
        self.pump_program = pump_program
        self.event_processor = LogsEventProcessor(pump_program)
        self.ping_interval = 20  # seconds

    async def listen_for_tokens(
        self,
        token_callback: Callable[[TokenInfo], Awaitable[None]],
        match_string: str | None = None,
        creator_address: str | None = None,
    ) -> None:
        """Listen for new token creations using logsSubscribe.

        Args:
            token_callback: Callback function for new tokens
            match_string: Optional string to match in token name/symbol
            creator_address: Optional creator address to filter by
        """
        while True:
            try:
                async with websockets.connect(self.wss_endpoint) as websocket:
                    await self._subscribe_to_logs(websocket)
                    ping_task = asyncio.create_task(self._ping_loop(websocket))

                    try:
                        while True:
                            token_info = await self._wait_for_token_creation(websocket)
                            if not token_info:
                                continue

                            logger.info(
                                f"New token detected: {token_info.name} ({token_info.symbol})"
                            )

                            if match_string and not (
                                match_string.lower() in token_info.name.lower()
                                or match_string.lower() in token_info.symbol.lower()
                            ):
                                logger.info(
                                    f"Token does not match filter '{match_string}'. Skipping..."
                                )
                                continue

                            if (
                                creator_address
                                and str(token_info.user) != creator_address
                            ):
                                logger.info(
                                    f"Token not created by {creator_address}. Skipping..."
                                )
                                continue

                            await token_callback(token_info)

                    except websockets.exceptions.ConnectionClosed:
                        logger.warning("WebSocket connection closed. Reconnecting...")
                        ping_task.cancel()

            except Exception as e:
                logger.error(f"WebSocket connection error: {str(e)}")
                logger.info("Reconnecting in 5 seconds...")
                await asyncio.sleep(5)

    def _get_initial_buy_amount(self, logs: list[str]) -> float:
        """Extract the initial buy amount from pump.fun creation transaction."""
        # Pump.fun buy instruction discriminator
        BUY_DISCRIMINATOR = 16927863322537952870
        
        # Track when we see Create and Buy instructions
        seen_create = False
        seen_buy = False
        
        for i, log in enumerate(logs):
            if "Program log: Instruction: Create" in log:
                seen_create = True
            elif "Program log: Instruction: Buy" in log and seen_create:
                seen_buy = True
            elif seen_buy and "Program data:" in log:
                # This should be the buy instruction data
                try:
                    encoded_data = log.split(": ")[1]
                    decoded_data = base64.b64decode(encoded_data)
                    
                    if len(decoded_data) >= 16:
                        # Verify discriminator
                        discriminator = struct.unpack("<Q", decoded_data[:8])[0]
                        if discriminator == BUY_DISCRIMINATOR:
                            # Extract amount (8 bytes after discriminator)
                            amount_raw = struct.unpack("<Q", decoded_data[8:16])[0]
                            # Convert to tokens (pump.fun uses 6 decimals)
                            return float(amount_raw) / (10 ** 6)
                except Exception as e:
                    logger.debug(f"Error parsing buy instruction: {e}")
                    
        return 0.0           

    async def _subscribe_to_logs(self, websocket) -> None:
        """Subscribe to logs mentioning the pump.fun program.

        Args:
            websocket: Active WebSocket connection
        """
        subscription_message = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "logsSubscribe",
                "params": [
                    {"mentions": [str(self.pump_program)]},
                    {"commitment": "processed"},
                ],
            }
        )

        await websocket.send(subscription_message)
        logger.info(f"Subscribed to logs mentioning program: {self.pump_program}")

        # Wait for subscription confirmation
        response = await websocket.recv()
        response_data = json.loads(response)
        if "result" in response_data:
            logger.info(f"Subscription confirmed with ID: {response_data['result']}")
        else:
            logger.warning(f"Unexpected subscription response: {response}")

    async def _ping_loop(self, websocket) -> None:
        """Keep connection alive with pings.

        Args:
            websocket: Active WebSocket connection
        """
        try:
            while True:
                await asyncio.sleep(self.ping_interval)
                try:
                    pong_waiter = await websocket.ping()
                    await asyncio.wait_for(pong_waiter, timeout=10)
                except asyncio.TimeoutError:
                    logger.warning("Ping timeout - server not responding")
                    # Force reconnection
                    await websocket.close()
                    return
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Ping error: {str(e)}")

    async def _wait_for_token_creation(self, websocket) -> TokenInfo | None:
        try:
            response = await asyncio.wait_for(websocket.recv(), timeout=30)
            data = json.loads(response)

            if "method" not in data or data["method"] != "logsNotification":
                return None

            log_data = data["params"]["result"]["value"]
            logs = log_data.get("logs", [])
            signature = log_data.get("signature", "unknown")

            # Check if this is a token creation
            if not any("Program log: Instruction: Create" in log for log in logs):
                return None
                
            # Skip swaps
            if any("Program log: Instruction: CreateTokenAccount" in log for log in logs):
                return None

            # NEW FILTER CODE - Check creator buy amount
            if os.getenv("FILTER_CREATOR_BUYS", "false").lower() == "true":
                buy_amount = self._get_creator_buy_amount(logs)
                if buy_amount > 0:
                    max_allowed = float(os.getenv("MAX_CREATOR_TOKENS", "50000000"))
                    if buy_amount > max_allowed:
                        logger.info(f"Creator bought {buy_amount:,.0f} tokens (> {max_allowed:,.0f}). Skipping...")
                        return None

            # Continue with normal processing
            return self.event_processor.process_program_logs(logs, signature)

        except Exception as e:
            logger.error(f"Error processing WebSocket message: {str(e)}")
            return None