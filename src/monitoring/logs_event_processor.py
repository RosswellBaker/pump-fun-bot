# Replace your logs_event_processor.py with this updated version
# This adds a quick balance check to detect creator token amounts

"""
Event processing for pump.fun tokens using logsSubscribe data.
"""

import asyncio
import base64
import struct
import time
from typing import Final

import base58
from solders.pubkey import Pubkey
from spl.token.instructions import get_associated_token_address

from core.pubkeys import PumpAddresses, SystemAddresses, TOKEN_DECIMALS
from trading.base import TokenInfo
from utils.logger import get_logger

logger = get_logger(__name__)


class LogsEventProcessor:
    """Processes events from pump.fun program logs."""

    # Discriminator for create instruction to avoid non-create transactions
    CREATE_DISCRIMINATOR: Final[int] = 8530921459188068891
    # Add this new discriminator for BUY instructions
    BUY_DISCRIMINATOR: Final[int] = 16927863322537952870

    def __init__(self, pump_program: Pubkey):
        """Initialize event processor.

        Args:
            pump_program: Pump.fun program address
        """
        self.pump_program = pump_program
        self.solana_client = None  # Will be set by the caller if needed

    def set_solana_client(self, client):
        """Set Solana client for balance checks."""
        self.solana_client = client

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

        # Parse both create and buy instructions from program data logs
        create_data = None
        creator_token_amount = 0.0
        
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
                        elif discriminator == self.BUY_DISCRIMINATOR:
                            buy_data = self._parse_buy_instruction(decoded_data)
                            if buy_data and "amount" in buy_data:
                                # Convert from raw token units to decimal
                                creator_token_amount = buy_data["amount"] / (10 ** TOKEN_DECIMALS)
                                logger.info(f"Found creator buy in same transaction: {creator_token_amount:,.0f} tokens")
                        
                except Exception as e:
                    logger.error(f"Failed to process log data: {e}")

        # Must have create data to proceed
        if not create_data or "name" not in create_data:
            return None

        # Create addresses
        mint = Pubkey.from_string(create_data["mint"])
        bonding_curve = Pubkey.from_string(create_data["bondingCurve"])
        associated_curve = self._find_associated_bonding_curve(
            mint, bonding_curve
        )
        creator = Pubkey.from_string(create_data["creator"])
        creator_vault = self._find_creator_vault(creator)
        
        # 🔧 NEW: If no buy found in same transaction, check creator's balance
        # This catches the common case where CREATE and BUY are separate transactions
        if creator_token_amount == 0.0:
            creator_token_amount = self._quick_creator_balance_check(mint, creator)
            if creator_token_amount > 0:
                logger.info(f"Creator balance check found: {creator_token_amount:,.0f} tokens")
        
        return TokenInfo(
            name=create_data["name"],
            symbol=create_data["symbol"],
            uri=create_data["uri"],
            signature=signature,
            mint=mint,
            bonding_curve=bonding_curve,
            associated_bonding_curve=associated_curve,
            user=Pubkey.from_string(create_data["user"]),
            creator=creator,
            creator_vault=creator_vault,
            creator_token_amount=creator_token_amount,
        )

    def _quick_creator_balance_check(self, mint: Pubkey, creator: Pubkey) -> float:
        """Quick check of creator's token balance using sync approach for speed."""
        try:
            import os
            from core.client import SolanaClient
            
            # Give creator a moment to make their buy transaction
            time.sleep(1.0)  # 1 second - balance between speed and accuracy
            
            # Get creator's associated token account
            creator_ata = get_associated_token_address(creator, mint)
        
            # Quick balance check
            async def check_balance():
                try:
                    client = SolanaClient(os.environ.get("SOLANA_NODE_RPC_ENDPOINT"))
                    solana_client = await client.get_client()
                    account_info = await solana_client.get_token_account_balance(creator_ata)
                    if account_info and account_info.value:
                        return float(account_info.value.amount) / (10 ** TOKEN_DECIMALS)
                    return 0.0
                except Exception as e:
                    logger.debug(f"Balance check failed: {e}")
                    return 0.0
            
            # Run with timeout to keep bot fast
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                balance = loop.run_until_complete(asyncio.wait_for(check_balance(), timeout=2.0))
                return balance
            except asyncio.TimeoutError:
                logger.debug("Creator balance check timed out")
                return 0.0
            finally:
                loop.close()
                
        except Exception as e:
            logger.debug(f"Creator balance check failed: {e}")
            return balance

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

    def _parse_buy_instruction(self, data: bytes) -> dict | None:
        """Parse the buy instruction data for creator token amount."""
        if len(data) < 16:
            return None
        try:
            discriminator = struct.unpack("<Q", data[:8])[0]
            if discriminator != self.BUY_DISCRIMINATOR:
                return None
            amount = struct.unpack("<Q", data[8:16])[0]
            return {"amount": amount}
        except Exception as e:
            logger.error(f"Failed to parse buy instruction: {e}")
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