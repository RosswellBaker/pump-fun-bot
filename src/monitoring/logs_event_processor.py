"""
Event processing for pump.fun tokens using logsSubscribe data.
"""

import base64
import struct
import json
from typing import Final

import base58
from solders.pubkey import Pubkey

from core.pubkeys import PumpAddresses, SystemAddresses
from trading.base import TokenInfo
from utils.logger import get_logger

logger = get_logger(__name__)


class LogsEventProcessor:
    """Processes events from pump.fun program logs."""

    # Discriminator for create instruction to avoid non-create transactions
    CREATE_DISCRIMINATOR: Final[int] = 8530921459188068891
    # Discriminator for buy instruction
    BUY_DISCRIMINATOR: Final[int] = 17177263679997991869

    def __init__(self, pump_program: Pubkey):
        self.pump_program = pump_program
        # Add this line for state management
        self.pending_creations = {}

    def process_program_logs(self, logs: list[str], signature: str) -> TokenInfo | None:
        """Process program logs and extract token info.

        Args:
            logs: List of log strings from the notification
            signature: Transaction signature

        Returns:
            TokenInfo if a token creation is found, None otherwise
        """
        
        # Check for Create instruction
        if any("Program log: Instruction: Create" in log for log in logs):
            # Skip swaps as the first condition may pass them
            if any("Program log: Instruction: CreateTokenAccount" in log for log in logs):
                return None

            # Find and process program data
            for log in logs:
                if "Program data:" in log:
                    try:
                        encoded_data = log.split(": ")[1]
                        decoded_data = base64.b64decode(encoded_data)
                        parsed_data = self._parse_create_instruction(decoded_data)
                        
                        if parsed_data and "name" in parsed_data:
                            # Store the creation data and wait for the buy instruction
                            self.pending_creations[signature] = parsed_data
                            logger.debug(f"Stored pending creation for {parsed_data['symbol']} with sig {signature}")
                            return None  # Wait for buy log before returning TokenInfo
                            
                    except Exception as e:
                        logger.error(f"Failed to process log data: {e}")
        
        # Check for Buy instruction log (arrives separately)
        elif any("Pump.fun: anchor Self CPI Log" in log for log in logs):
            # If we have a pending creation for this signature
            if signature in self.pending_creations:
                creator_token_amount = 0
                
                # Parse the buy amount from the JSON log
                for log_line in logs:
                    if "Pump.fun: anchor Self CPI Log" in log_line and '"isBuy":true' in log_line:
                        try:
                            buy_parsed = self._parse_buy_instruction(log_line)
                            if buy_parsed and "amount" in buy_parsed:
                                creator_token_amount = buy_parsed["amount"]
                                logger.info(f"Found creator buy amount: {creator_token_amount:,.2f} tokens")
                                break
                        except Exception as e:
                            logger.debug(f"Failed to parse potential buy log: {e}")
                            continue
                
                # Retrieve the stored creation data and remove from pending
                parsed_data = self.pending_creations.pop(signature)
                
                # Create the complete TokenInfo object
                mint = Pubkey.from_string(parsed_data["mint"])
                bonding_curve = Pubkey.from_string(parsed_data["bondingCurve"])
                associated_curve = self._find_associated_bonding_curve(mint, bonding_curve)
                creator = Pubkey.from_string(parsed_data["creator"])
                creator_vault = self._find_creator_vault(creator)
                
                return TokenInfo(
                    name=parsed_data["name"],
                    symbol=parsed_data["symbol"],
                    uri=parsed_data["uri"],
                    mint=mint,
                    bonding_curve=bonding_curve,
                    associated_bonding_curve=associated_curve,
                    user=Pubkey.from_string(parsed_data["user"]),
                    creator=creator,
                    creator_vault=creator_vault,
                    creator_token_amount=creator_token_amount,
                )
        
        # Clean up old pending creations (prevent memory leaks)
        if len(self.pending_creations) > 100:
            oldest_sig = next(iter(self.pending_creations))
            del self.pending_creations[oldest_sig]
            logger.warning(f"Cleaned up old pending creation for sig: {oldest_sig}")
        
        return None

    def _parse_create_instruction(self, data: bytes) -> dict | None:
        """Parse the create instruction data.

        Args:
            data: Raw instruction data

        Returns:
            Dictionary of parsed data or None if parsing fails
        """
        if len(data) < 8:
            return None
            
        # Check for the correct instruction discriminator
        discriminator = struct.unpack("<Q", data[:8])[0]
        if discriminator != self.CREATE_DISCRIMINATOR:
            logger.info(f"Skipping non-Create instruction with discriminator: {discriminator}")
            return None

        offset = 8
        parsed_data = {}

        # Parse fields based on CreateEvent structure
        fields = [
            ("name", "string"),
            ("symbol", "string"),
            ("uri", "string"),
            ("mint", "publicKey"),
            ("bondingCurve", "publicKey"),
            ("user", "publicKey"),
            ("creator", "publicKey"),
        ]

        try:
            for field_name, field_type in fields:
                if field_type == "string":
                    length = struct.unpack("<I", data[offset : offset + 4])[0]
                    offset += 4
                    value = data[offset : offset + length].decode("utf-8")
                    offset += length
                elif field_type == "publicKey":
                    value = base58.b58encode(data[offset : offset + 32]).decode("utf-8")
                    offset += 32

                parsed_data[field_name] = value

            return parsed_data
        except Exception as e:
            logger.error(f"Failed to parse create instruction: {e}")
            return None

    def _parse_buy_instruction(self, log_line: str) -> dict | None:
        """
        REPLACEMENT METHOD:
        Parses the JSON data from the 'Trade' event log to get the exact token amount.
        This is the correct and fast method, using only the data already received.
        """
        try:
            # Extract the JSON part of the log
            json_str = log_line.split("Pump.fun: anchor Self CPI Log")[1].strip()
            event_data = json.loads(json_str)

            # Check if it's a buy event and has the token amount
            if event_data.get("isBuy") and "tokenAmount" in event_data:
                # The token amount is a raw integer, divide by 10^6 for pump.fun's 6 decimals
                raw_amount = int(event_data["tokenAmount"])
                token_amount = raw_amount / 1_000_000  # 10**6
                return {"amount": token_amount}
            
            return None
        except (json.JSONDecodeError, IndexError, KeyError, ValueError) as e:
            logger.debug(f"Failed to parse buy event log: {e}")
            return None

    def _find_associated_bonding_curve(
        self, mint: Pubkey, bonding_curve: Pubkey
    ) -> Pubkey:
        """
        Find the associated bonding curve for a given mint and bonding curve.
        This uses the standard ATA derivation.

        Args:
            mint: Token mint address
            bonding_curve: Bonding curve address

        Returns:
            Associated bonding curve address
        """
        derived_address, _ = Pubkey.find_program_address(
            [
                bytes(bonding_curve),
                bytes(SystemAddresses.TOKEN_PROGRAM),
                bytes(mint),
            ],
            SystemAddresses.ASSOCIATED_TOKEN_PROGRAM,
        )
        return derived_address
    
    def _find_creator_vault(self, creator: Pubkey) -> Pubkey:
        """
        Find the creator vault for a creator.

        Args:
            creator: Creator address

        Returns:
            Creator vault address
        """
        derived_address, _ = Pubkey.find_program_address(
            [
                b"creator-vault",
                bytes(creator)
            ],
            PumpAddresses.PROGRAM,
        )
        return derived_address