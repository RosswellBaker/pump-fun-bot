"""
WebSocket monitoring for pump.fun tokens using logsSubscribe.
Enhanced with creator token amount filtering to prevent buying tokens
where the creator purchased too many tokens during creation.
"""

import asyncio
import json
from collections.abc import Awaitable, Callable

import websockets
from solders.pubkey import Pubkey

from monitoring.base_listener import BaseTokenListener
from monitoring.logs_event_processor import LogsEventProcessor
from trading.base import TokenInfo
from utils.logger import get_logger

logger = get_logger(__name__)


class LogsListener(BaseTokenListener):
    """
    WebSocket listener for pump.fun token creation events using logsSubscribe.
    
    This class is your connection to the Solana blockchain. It subscribes to transaction logs
    and filters them in real-time to find only the tokens that meet your criteria.
    
    The filtering happens at the earliest possible point in your pipeline, which means:
    1. You save RPC calls by not even attempting to buy filtered tokens
    2. You stay well within rate limits since filtering uses data you already have
    3. Your bot can focus on the most promising opportunities
    """

    def __init__(self, wss_endpoint: str, pump_program: Pubkey):
        """Initialize token listener.

        Args:
            wss_endpoint: WebSocket endpoint URL (your Helius WSS endpoint)
            pump_program: Pump.fun program address (6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P)
        """
        self.wss_endpoint = wss_endpoint
        self.pump_program = pump_program
        self.event_processor = LogsEventProcessor(pump_program)
        self.ping_interval = 20  # Keep connection alive with periodic pings

    async def listen_for_tokens(
        self,
        token_callback: Callable[[TokenInfo], Awaitable[None]],
        match_string: str | None = None,
        creator_address: str | None = None,
        creator_token_amount_max: float | None = None,
    ) -> None:
        """
        Listen for new token creations using logsSubscribe with filtering.

        This method is the main loop of your bot. It maintains a WebSocket connection
        to your RPC provider and processes each transaction as it happens on-chain.

        Args:
            token_callback: Function to call when a valid token is found
            match_string: Optional string to match in token name/symbol
            creator_address: Optional creator address to filter by
            creator_token_amount_max: Maximum tokens creator can buy (in human-readable format)
        """
        while True:
            try:
                async with websockets.connect(self.wss_endpoint) as websocket:
                    await self._subscribe_to_logs(websocket)
                    ping_task = asyncio.create_task(self._ping_loop(websocket))

                    try:
                        while True:
                            # Wait for the next token creation event
                            token_info = await self._wait_for_token_creation(websocket)
                            if not token_info:
                                continue

                            logger.info(f"New token detected: {token_info.name} ({token_info.symbol})")
                            
                            # Apply all filters in sequence
                            # This is where we decide whether to proceed with this token or skip it
                            
                            # Filter 1: String matching (optional)
                            if match_string and not self._matches_string_filter(token_info, match_string):
                                logger.info(f"Token does not match filter '{match_string}'. Skipping...")
                                continue

                            # Filter 2: Creator address matching (optional)
                            if creator_address and not self._matches_creator_filter(token_info, creator_address):
                                logger.info(f"Token not created by {creator_address}. Skipping...")
                                continue

                            # Filter 3: Creator token amount filter (the heart of our system)
                            if creator_token_amount_max is not None:
                                should_skip, reason = self._should_skip_by_creator_amount(
                                    token_info, creator_token_amount_max
                                )
                                if should_skip:
                                    logger.info(reason)
                                    continue

                            # If we get here, the token passed all filters
                            logger.info(f"Token {token_info.symbol} passed all filters - forwarding to trader")
                            await token_callback(token_info)

                    except asyncio.CancelledError:
                        logger.info("Token listening was cancelled")
                        raise
                    finally:
                        ping_task.cancel()
                        try:
                            await ping_task
                        except asyncio.CancelledError:
                            pass

            except asyncio.CancelledError:
                logger.info("Token listener shutdown requested")
                break
            except Exception as e:
                logger.error(f"WebSocket connection error: {e}")
                logger.info("Reconnecting in 5 seconds...")
                await asyncio.sleep(5)

    def _matches_string_filter(self, token_info: TokenInfo, match_string: str) -> bool:
        """
        Check if token name or symbol contains the match string.
        
        Args:
            token_info: Token information
            match_string: String to search for
            
        Returns:
            True if token matches, False otherwise
        """
        match_lower = match_string.lower()
        return (match_lower in token_info.name.lower() or 
                match_lower in token_info.symbol.lower())

    def _matches_creator_filter(self, token_info: TokenInfo, creator_address: str) -> bool:
        """
        Check if token was created by the specified address.
        
        Args:
            token_info: Token information
            creator_address: Creator address to match
            
        Returns:
            True if creator matches, False otherwise
        """
        return str(token_info.creator) == creator_address

    def _should_skip_by_creator_amount(
        self, 
        token_info: TokenInfo, 
        creator_token_amount_max: float
    ) -> tuple[bool, str]:
        """
        Determine if token should be skipped based on creator's initial purchase amount.
        
        This is the core of our filtering system. We compare how many tokens the creator
        bought during token creation against our maximum threshold.
        
        Args:
            token_info: Token information with creator purchase data
            creator_token_amount_max: Maximum allowed creator purchase (human-readable)
            
        Returns:
            Tuple of (should_skip, reason_string)
        """
        # Convert our human-readable limit to raw format for comparison
        # Pump.fun uses 6 decimals, so 50 million tokens = 50,000,000 * 10^6
        max_allowed_raw = int(creator_token_amount_max * (10 ** 6))
        
        # Get the human-readable amount for logging
        creator_amount_human = token_info.get_creator_tokens_human_readable()
        
        # Debug logging to help you understand what's happening
        logger.debug(f"Creator amount check: {creator_amount_human:,.2f} vs {creator_token_amount_max:,.0f} limit")
        
        if token_info.creator_token_amount > max_allowed_raw:
            reason = (f"Creator bought {creator_amount_human:,.2f} tokens "
                     f"(exceeds {creator_token_amount_max:,.0f} limit). Skipping...")
            return True, reason
        
        # Token passed the filter
        logger.debug(f"Creator amount OK: {creator_amount_human:,.2f} tokens (within limit)")
        return False, ""

    async def _subscribe_to_logs(self, websocket) -> None:
        """
        Subscribe to pump.fun program logs.
        
        This sets up the WebSocket subscription that will deliver transaction logs
        for all pump.fun activities in real-time.
        
        Args:
            websocket: Active WebSocket connection
        """
        subscription_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "logsSubscribe",
            "params": [
                {"mentions": [str(self.pump_program)]},
                {"commitment": "confirmed"}
            ],
        }

        await websocket.send(json.dumps(subscription_request))
        
        # Wait for subscription confirmation
        response = await websocket.recv()
        response_data = json.loads(response)
        
        if "result" in response_data:
            subscription_id = response_data["result"]
            logger.info(f"Subscribed to logs mentioning program: {self.pump_program}")
            logger.info(f"Subscription confirmed with ID: {subscription_id}")
        else:
            raise Exception(f"Failed to subscribe to logs: {response_data}")

    async def _wait_for_token_creation(self, websocket) -> TokenInfo | None:
        """
        Wait for and process the next token creation event.
        
        This method listens to the WebSocket stream and processes each incoming
        transaction to see if it contains a token creation.
        
        Args:
            websocket: Active WebSocket connection
            
        Returns:
            TokenInfo if a token creation is found, None otherwise
        """
        try:
            # Receive the next message from the WebSocket
            message = await websocket.recv()
            data = json.loads(message)

            # Skip non-notification messages (like pings, subscription confirmations, etc.)
            if data.get("method") != "logsNotification":
                return None

            # Extract the transaction logs from the notification
            notification_params = data.get("params", {})
            result = notification_params.get("result", {})
            logs = result.get("value", {}).get("logs", [])
            signature = result.get("value", {}).get("signature", "")

            # Process the logs to extract token information
            return self.event_processor.process_program_logs(logs, signature)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode WebSocket message: {e}")
            return None
        except Exception as e:
            logger.error(f"Error processing WebSocket message: {e}")
            return None

    async def _ping_loop(self, websocket) -> None:
        """
        Keep the WebSocket connection alive with periodic pings.
        
        This prevents the connection from being closed due to inactivity.
        
        Args:
            websocket: Active WebSocket connection
        """
        try:
            while True:
                await asyncio.sleep(self.ping_interval)
                await websocket.ping()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning(f"Ping failed: {e}")