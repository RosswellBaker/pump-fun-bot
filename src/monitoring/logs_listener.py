"""
WebSocket monitoring for pump.fun tokens using logsSubscribe.
"""

import asyncio
import json
from collections.abc import Awaitable, Callable

import websockets
from solders.pubkey import Pubkey

from monitoring.filters import get_buy_instruction_amount, should_process_token
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

    async def wait_for_token_creation(self, websocket) -> TokenInfo | None:
        """
        Waits for token creation events and filters based on creator's initial buy amount.
        Only processes tokens where the creator's initial buy is <= 50 million tokens.
        """
        try:
            # Wait for WebSocket response with timeout
            response = await asyncio.wait_for(websocket.recv(), timeout=30)
            data = json.loads(response)
            
            # Validate the response structure
            if "method" not in data or data["method"] != "logsNotification":
                return None
                
            log_data = data["params"]["result"]["value"]
            logs = log_data.get("logs", [])
            signature = log_data.get("signature", "unknown")
            
            if signature == "unknown":
                logger.warning("Transaction skipped: Signature is unknown.")
                return None
            
            logger.info(f"Processing transaction: {signature}")
            
            # Check if this transaction contains a valid buy instruction
            buy_amount = get_buy_instruction_amount(logs)
            if buy_amount is None:
                logger.info(f"Transaction {signature} skipped: No valid buy instruction found.")
                return None
            
            # Filter based on creator's initial buy amount threshold
            if not should_process_token(logs):
                logger.info(
                    f"Transaction {signature} skipped: Creator's initial buy amount ({buy_amount:,.2f}) exceeds threshold."
                )
                return None
            
            # Token passed the filter - proceed with processing
            logger.info(
                f"✅ Transaction {signature} PASSED filter: Creator's initial buy amount is {buy_amount:,.2f} tokens."
            )
            
            # Process the token creation event
            return self.event_processor.process_program_logs(logs, signature)
            
        except asyncio.TimeoutError:
            logger.debug("No data received for 30 seconds")
            return None
            
        except websockets.exceptions.ConnectionClosed:
            logger.warning("WebSocket connection closed")
            raise
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {str(e)}")
            return None
            
        except Exception as e:
            logger.error(f"Error processing WebSocket message: {str(e)}")
            return None