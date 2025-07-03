import base64
import struct
from typing import Final
import os

import base58
from solders.pubkey import Pubkey
from solders.signature import Signature
from solana.rpc.api import Client

from core.pubkeys import PumpAddresses, SystemAddresses
from trading.base import TokenInfo
from utils.logger import get_logger

logger = get_logger(__name__)


class LogsEventProcessor:
    """Processes events from pump.fun program logs."""

    # Discriminator for create instruction
    CREATE_DISCRIMINATOR: Final[int] = 8530921459188068891
    # Discriminator for the 'buy' instruction
    BUY_DISCRIMINATOR: Final[int] = 16927863322537952870
    
    def __init__(self, pump_program: Pubkey):
        """Initialize event processor.

        Args:
            pump_program: Pump.fun program address
        """
        self.pump_program = pump_program

    def process_program_logs(self, logs: list[str], signature: str) -> TokenInfo | None:
        """Process program logs and extract token info.

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
        
        # Get the creator's buy amount ONCE at the start, using the correct function you already have.
        initial_buy_amount = self._get_amount_from_buy_instruction(signature)

        # Find and process program data
        for log in logs:
            if "Program data:" in log:
                try:
                    encoded_data = log.split(": ")[1]
                    decoded_data = base64.b64decode(encoded_data)
                    parsed_data = self._parse_create_instruction(decoded_data)
                    
                    if parsed_data and "name" in parsed_data:
                        mint = Pubkey.from_string(parsed_data["mint"])
                        bonding_curve = Pubkey.from_string(parsed_data["bondingCurve"])
                        # This is the bonding curve's token vault address
                        associated_curve = self._find_associated_bonding_curve(
                            mint, bonding_curve
                        )
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
                            creator_token_amount=initial_buy_amount, # Store the result
                            signature=signature
                        )
                except Exception as e:
                    logger.error(f"Failed to process log data: {e}")
        
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
        
    def _get_initial_buy_for_filter(self, tx_signature: str, mint_address: str, associated_curve_address: str) -> float:
        """
        Calculates the creator's total initial buy amount by analyzing inner instructions
        to correctly handle bundling within the same transaction. This is the definitive method.
        """
        try:
            rpc_endpoint = os.getenv("SOLANA_NODE_RPC_ENDPOINT")
            if not rpc_endpoint:
                logger.error("SOLANA_NODE_RPC_ENDPOINT not set in environment")
                return 0.0
                
            from solana.rpc.api import Client
            client = Client(rpc_endpoint)
            
            from solders.signature import Signature
            signature = Signature.from_string(tx_signature)
            
            tx_response = None
            try:
                tx_response = client.get_transaction(signature, encoding="jsonParsed", max_supported_transaction_version=0)
            except Exception as e:
                logger.error(f"Failed to get transaction {tx_signature}. Error: {e}")
                return 0.0

            if not tx_response or not tx_response.value or not tx_response.value.transaction or not tx_response.value.transaction.meta:
                logger.warning(f"Could not get transaction meta for {tx_signature}")
                return 0.0

            meta = tx_response.value.transaction.meta
            
            decimals = None
            if meta.post_token_balances:
                for balance in meta.post_token_balances:
                    if str(balance.mint) == mint_address:
                        decimals = balance.ui_token_amount.decimals
                        break
            
            if decimals is None:
                logger.warning(f"Could not determine token decimals for mint {mint_address} in tx {tx_signature}. Cannot calculate initial buy.")
                return 0.0

            total_buy_amount_raw = 0
            if not meta.inner_instructions:
                logger.warning(f"No inner instructions found for {tx_signature}, cannot determine initial buy.")
                return 0.0

            for instruction_group in meta.inner_instructions:
                for inner_ix in instruction_group.instructions:
                    if not hasattr(inner_ix, "parsed"):
                        continue

                    parsed_ix = inner_ix.parsed
                    if (isinstance(parsed_ix, dict) and
                        parsed_ix.get("type") == "transfer" and
                        inner_ix.program == "spl-token"):

                        info = parsed_ix.get("info", {})
                        source = info.get("source")
                        
                        if source == associated_curve_address:
                            try:
                                amount_raw = int(info.get("amount", "0"))
                                total_buy_amount_raw += amount_raw
                            except (ValueError, TypeError):
                                logger.warning(f"Could not parse amount from inner instruction: {info}")

            if total_buy_amount_raw == 0:
                logger.debug(f"No initial buy detected from bonding curve for tx {tx_signature[:6]}")
                return 0.0

            scaled_amount = total_buy_amount_raw / (10 ** decimals)
            logger.info(f"Detected total initial buy of {scaled_amount:,.2f} tokens from bonding curve in tx {tx_signature[:6]}...")
            
            return scaled_amount
                    
        except Exception as e:
            logger.error(f"Critical error in _get_creator_initial_buy_amount_sync: {e}")
            return 0.0