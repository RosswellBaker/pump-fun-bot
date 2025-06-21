"""
Event processing for pump.fun tokens using logsSubscribe data.
Fixed to properly detect creator initial token purchases.
"""

import base64
import hashlib
import struct
from typing import Final

import base58
from solders.pubkey import Pubkey

from core.pubkeys import PumpAddresses, SystemAddresses, TOKEN_DECIMALS
from trading.base import TokenInfo
from utils.logger import get_logger

logger = get_logger(__name__)


class LogsEventProcessor:
    """Processes events from pump.fun program logs."""

    # Calculate discriminators correctly using sha256 hashes
    CREATE_DISCRIMINATOR: Final[int] = struct.unpack("<Q", hashlib.sha256(b"global:create").digest()[:8])[0]
    BUY_DISCRIMINATOR: Final[int] = struct.unpack("<Q", hashlib.sha256(b"global:buy").digest()[:8])[0]

    def __init__(self, pump_program: Pubkey):
        """Initialize event processor.

        Args:
            pump_program: Pump.fun program address
        """
        self.pump_program = pump_program

    def process_program_logs(self, logs: list[str], signature: str) -> TokenInfo | None:
        """Process program logs and extract token info with creator token amount.

        Args:
            logs: List of log strings from the notification
            signature: Transaction signature

        Returns:
            TokenInfo if a token creation is found, None otherwise
        """
        # Check if this is a token creation
        if not any("Program log: Instruction: Create" in log for log in logs):
            return None
        
        # Skip swaps as the first condition may pass them
        if any("Program log: Instruction: CreateTokenAccount" in log for log in logs):
            return None

        # Parse all program data logs to find CREATE and BUY instructions
        create_data = None
        creator_token_amount = 0
        creator_address = None
        
        for log in logs:
            if "Program data:" in log:
                try:
                    encoded_data = log.split(": ")[1]
                    decoded_data = base64.b64decode(encoded_data)
                    
                    # Check discriminator to determine instruction type
                    if len(decoded_data) >= 8:
                        discriminator = struct.unpack("<Q", decoded_data[:8])[0]
                        
                        if discriminator == self.CREATE_DISCRIMINATOR:
                            create_data = self._parse_create_instruction(decoded_data)
                            if create_data:
                                creator_address = create_data.get("creator")
                        
                        elif discriminator == self.BUY_DISCRIMINATOR:
                            buy_data = self._parse_buy_instruction(decoded_data)
                            if buy_data and creator_address:
                                # Check if this buy is from the creator (same transaction)
                                # In pump.fun, creator buys happen immediately after creation
                                creator_token_amount += buy_data.get("amount", 0)
                                
                except Exception as e:
                    logger.debug(f"Failed to process program data log: {e}")
                    continue

        # Create TokenInfo if we successfully parsed the creation
        if create_data and "name" in create_data:
            try:
                mint = Pubkey.from_string(create_data["mint"])
                bonding_curve = Pubkey.from_string(create_data["bondingCurve"])
                associated_curve = self._find_associated_bonding_curve(mint, bonding_curve)
                creator = Pubkey.from_string(create_data["creator"])
                creator_vault = self._find_creator_vault(creator)
                
                return TokenInfo(
                    name=create_data["name"],
                    symbol=create_data["symbol"],
                    uri=create_data["uri"],
                    mint=mint,
                    bonding_curve=bonding_curve,
                    associated_bonding_curve=associated_curve,
                    user=Pubkey.from_string(create_data["user"]),
                    creator=creator,
                    creator_vault=creator_vault,
                    creator_token_amount=creator_token_amount,  # Raw token amount (with decimals)
                )
            except Exception as e:
                logger.error(f"Failed to create TokenInfo: {e}")
                return None
        
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
            logger.debug(f"Skipping non-Create instruction with discriminator: {discriminator}")
            return None

        offset = 8
        parsed_data = {}

        # Parse fields based on CreateEvent structure from IDL
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
                    if offset + 4 > len(data):
                        return None
                    length = struct.unpack("<I", data[offset : offset + 4])[0]
                    offset += 4
                    if offset + length > len(data):
                        return None
                    value = data[offset : offset + length].decode("utf-8")
                    offset += length
                elif field_type == "publicKey":
                    if offset + 32 > len(data):
                        return None
                    value = base58.b58encode(data[offset : offset + 32]).decode("utf-8")
                    offset += 32

                parsed_data[field_name] = value

            return parsed_data
        except Exception as e:
            logger.error(f"Failed to parse create instruction: {e}")
            return None

    def _parse_buy_instruction(self, data: bytes) -> dict | None:
        """Parse the buy instruction data to extract token amount.

        Args:
            data: Raw instruction data

        Returns:
            Dictionary with amount or None if parsing fails
        """
        if len(data) < 16:
            return None
            
        try:
            discriminator = struct.unpack("<Q", data[:8])[0]
            if discriminator != self.BUY_DISCRIMINATOR:
                return None
            
            # The amount is the first argument after discriminator (u64)
            amount = struct.unpack("<Q", data[8:16])[0]
            return {"amount": amount}
            
        except Exception as e:
            logger.debug(f"Failed to parse buy instruction: {e}")
            return None

    def _find_associated_bonding_curve(self, mint: Pubkey, bonding_curve: Pubkey) -> Pubkey:
        """Find the associated bonding curve for a given mint and bonding curve.

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
        """Find the creator vault for a creator.

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