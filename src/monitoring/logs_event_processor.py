"""
Event processing for pump.fun tokens using logsSubscribe data.
This processor analyzes transaction logs to extract both token creation details
and creator purchase amounts in a single pass, eliminating the need for additional RPC calls.
"""

import base64
import hashlib
import struct
from typing import Final

import base58
from solders.pubkey import Pubkey

from core.pubkeys import PumpAddresses, SystemAddresses
from trading.base import TokenInfo
from utils.logger import get_logger

logger = get_logger(__name__)


class LogsEventProcessor:
    """
    Processes events from pump.fun program logs with creator purchase detection.
    
    This class is the heart of our filtering system. It analyzes the raw transaction logs
    to understand what happened during token creation, specifically looking for:
    1. The CREATE instruction that establishes the new token
    2. Any BUY instructions that show the creator purchasing tokens immediately
    
    By parsing both instruction types from the same transaction, we can determine
    how many tokens the creator bought during the creation process.
    """

    # Calculate discriminators using SHA256 hashes - this is how Anchor framework
    # creates unique identifiers for each instruction type
    CREATE_DISCRIMINATOR: Final[int] = struct.unpack("<Q", hashlib.sha256(b"global:create").digest()[:8])[0]
    BUY_DISCRIMINATOR: Final[int] = struct.unpack("<Q", hashlib.sha256(b"global:buy").digest()[:8])[0]

    def __init__(self, pump_program: Pubkey):
        """Initialize event processor.

        Args:
            pump_program: Pump.fun program address (6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P)
        """
        self.pump_program = pump_program

    def process_program_logs(self, logs: list[str], signature: str) -> TokenInfo | None:
        """
        Process program logs and extract complete token info with creator purchase data.

        This is where the magic happens. We analyze all the log entries from a single
        transaction to understand both the token creation and any immediate purchases.

        Args:
            logs: List of log strings from the WebSocket notification
            signature: Transaction signature for debugging

        Returns:
            TokenInfo if a token creation is found with creator purchase data, None otherwise
        """
        # First, verify this is actually a token creation transaction
        if not any("Program log: Instruction: Create" in log for log in logs):
            return None
        
        # Skip token account creations (these are different from token minting)
        if any("Program log: Instruction: CreateTokenAccount" in log for log in logs):
            return None

        # These variables will store our findings as we parse the logs
        create_data = None
        creator_token_amount = 0
        creator_address = None
        
        # Parse all program data logs to find CREATE and BUY instructions
        # In pump.fun, these often appear in the same transaction
        for log in logs:
            if "Program data:" in log:
                try:
                    # Extract and decode the base64 instruction data
                    encoded_data = log.split(": ")[1]
                    decoded_data = base64.b64decode(encoded_data)
                    
                    # Every instruction starts with an 8-byte discriminator
                    if len(decoded_data) >= 8:
                        discriminator = struct.unpack("<Q", decoded_data[:8])[0]
                        
                        if discriminator == self.CREATE_DISCRIMINATOR:
                            # This is the token creation instruction
                            create_data = self._parse_create_instruction(decoded_data)
                            if create_data:
                                creator_address = create_data.get("creator")
                                logger.debug(f"Found CREATE instruction for token: {create_data.get('name')}")
                        
                        elif discriminator == self.BUY_DISCRIMINATOR:
                            # This is a token purchase instruction
                            buy_data = self._parse_buy_instruction(decoded_data)
                            if buy_data:
                                # Add to total creator purchases (there could be multiple buys)
                                creator_token_amount += buy_data.get("amount", 0)
                                logger.debug(f"Found BUY instruction: {buy_data.get('amount', 0)} tokens")
                                
                except Exception as e:
                    # Log parsing errors for debugging but continue processing
                    logger.debug(f"Failed to process program data log: {e}")
                    continue

        # Create TokenInfo if we successfully parsed the creation
        if create_data and "name" in create_data:
            try:
                # Convert string addresses back to Pubkey objects
                mint = Pubkey.from_string(create_data["mint"])
                bonding_curve = Pubkey.from_string(create_data["bondingCurve"])
                associated_curve = self._find_associated_bonding_curve(mint, bonding_curve)
                creator = Pubkey.from_string(create_data["creator"])
                creator_vault = self._find_creator_vault(creator)
                
                # Log what we found for debugging
                human_readable_amount = creator_token_amount / (10 ** 6)
                logger.debug(f"Token {create_data['name']}: creator bought {human_readable_amount:,.2f} tokens")
                
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
                    creator_token_amount=creator_token_amount,  # This is the key field for our filter
                )
            except Exception as e:
                logger.error(f"Failed to create TokenInfo: {e}")
                return None
        
        return None

    def _parse_create_instruction(self, data: bytes) -> dict | None:
        """
        Parse the CREATE instruction data to extract token details.

        The CREATE instruction contains all the basic token information:
        name, symbol, metadata URI, and the addresses of key accounts.

        Args:
            data: Raw instruction data from the transaction logs

        Returns:
            Dictionary of parsed data or None if parsing fails
        """
        if len(data) < 8:
            return None
            
        # Verify this is actually a CREATE instruction
        discriminator = struct.unpack("<Q", data[:8])[0]
        if discriminator != self.CREATE_DISCRIMINATOR:
            logger.debug(f"Expected CREATE discriminator, got: {discriminator}")
            return None

        offset = 8  # Skip the discriminator
        parsed_data = {}

        # Parse fields based on pump.fun's CreateEvent structure
        # The order and types here match exactly what pump.fun sends
        fields = [
            ("name", "string"),      # Token name (e.g., "My Awesome Token")
            ("symbol", "string"),    # Token symbol (e.g., "MAT")
            ("uri", "string"),       # Metadata URI
            ("mint", "publicKey"),   # Token mint address
            ("bondingCurve", "publicKey"),  # Bonding curve address
            ("user", "publicKey"),   # User who initiated creation
            ("creator", "publicKey"), # Creator address (important for our filter)
        ]

        try:
            for field_name, field_type in fields:
                if field_type == "string":
                    # Strings are prefixed with a 4-byte length
                    if offset + 4 > len(data):
                        return None
                    length = struct.unpack("<I", data[offset : offset + 4])[0]
                    offset += 4
                    if offset + length > len(data):
                        return None
                    value = data[offset : offset + length].decode("utf-8")
                    offset += length
                elif field_type == "publicKey":
                    # Public keys are always 32 bytes
                    if offset + 32 > len(data):
                        return None
                    value = base58.b58encode(data[offset : offset + 32]).decode("utf-8")
                    offset += 32

                parsed_data[field_name] = value

            return parsed_data
        except Exception as e:
            logger.error(f"Failed to parse CREATE instruction: {e}")
            return None

    def _parse_buy_instruction(self, data: bytes) -> dict | None:
        """
        Parse the BUY instruction data to extract purchase amount.

        The BUY instruction tells us how many tokens were purchased.
        When the creator buys tokens during creation, this appears in the same transaction.

        Args:
            data: Raw instruction data from the transaction logs

        Returns:
            Dictionary with amount or None if parsing fails
        """
        if len(data) < 16:
            return None
            
        try:
            # Verify this is actually a BUY instruction
            discriminator = struct.unpack("<Q", data[:8])[0]
            if discriminator != self.BUY_DISCRIMINATOR:
                return None
            
            # The amount is the first argument after the discriminator (8-byte unsigned integer)
            amount = struct.unpack("<Q", data[8:16])[0]
            return {"amount": amount}
            
        except Exception as e:
            logger.debug(f"Failed to parse BUY instruction: {e}")
            return None

    def _find_associated_bonding_curve(self, mint: Pubkey, bonding_curve: Pubkey) -> Pubkey:
        """
        Calculate the associated bonding curve address.

        This uses Solana's Program Derived Address (PDA) system to find
        the token account that holds the bonding curve's tokens.

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
        Calculate the creator vault address.

        The creator vault is where creator fees are collected.

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