"""
Event processing for pump.fun tokens using logsSubscribe data.
"""

import asyncio
import base64
import struct
import json
import os
from typing import Final

import base58
from solders.pubkey import Pubkey
from solana.rpc.async_api import AsyncClient
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
        """Initialize event processor.

        Args:
            pump_program: Pump.fun program address
        """
        self.pump_program = pump_program

    async def process_program_logs(self, logs: list[str], signature: str) -> TokenInfo | None:
        """Process program logs and extract token info."""
        
        # Check if this is a token creation
        if not any("Program log: Instruction: Create" in log for log in logs):
            return None
        
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
                        # Extract creator buy amount using getTransaction
                        creator_token_amount = await self._get_creator_initial_buy_amount(signature)
                        
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
                except Exception as e:
                    logger.error(f"Failed to process log data: {e}")
        
        return None

    def _extract_creator_buy_amount(self, logs: list[str]) -> float:
        """Extract creator buy amount from logs in the same transaction."""
        for log_line in logs:
            if "Pump.fun: anchor Self CPI Log" in log_line and '"isBuy":true' in log_line:
                try:
                    json_start = log_line.find('{')
                    if json_start != -1:
                        json_data = json.loads(log_line[json_start:])
                        if "tokenAmount" in json_data:
                            token_amount_raw = int(json_data["tokenAmount"])
                            return token_amount_raw / 1_000_000  # Convert to tokens
                except Exception as e:
                    logger.debug(f"Failed to parse buy log: {e}")
        return 0.0

    # Add this method after line 95 (after _extract_creator_buy_amount):
    async def _get_creator_initial_buy_amount(self, signature: str) -> float:
        """Get the creator's initial buy amount by fetching and decoding the actual transaction."""
        try:
            rpc_endpoint = os.getenv("SOLANA_NODE_RPC_ENDPOINT")
            if not rpc_endpoint:
                logger.error("SOLANA_NODE_RPC_ENDPOINT not set")
                return 0.0
                
            async with AsyncClient(rpc_endpoint) as client:
                # Add retry logic for transaction indexing
                for attempt in range(3):
                    try:
                        tx_response = await client.get_transaction(
                            signature, 
                            encoding="base64",
                            max_supported_transaction_version=0
                        )
                        
                        if tx_response.value and tx_response.value.transaction:
                            break
                            
                        if attempt < 2:
                            await asyncio.sleep(0.5)  # Wait for transaction to be indexed
                            
                    except Exception as e:
                        if attempt < 2:
                            await asyncio.sleep(0.5)
                            continue
                        logger.debug(f"Failed to get transaction {signature}: {e}")
                        return 0.0
                
                if not tx_response.value or not tx_response.value.transaction:
                    return 0.0
                    
                transaction = tx_response.value.transaction
                
                from solders.transaction import VersionedTransaction
                
                if isinstance(transaction.message, str):
                    tx_data = base64.b64decode(transaction.message)
                    versioned_tx = VersionedTransaction.from_bytes(tx_data)
                else:
                    versioned_tx = transaction
                    
                # Look for Buy instructions in the transaction
                for ix in versioned_tx.message.instructions:
                    program_id = str(versioned_tx.message.account_keys[ix.program_id_index])
                    
                    if program_id == str(self.pump_program):
                        ix_data = bytes(ix.data)
                        
                        if len(ix_data) >= 16:  # Need at least 16 bytes for discriminator + amount
                            discriminator = struct.unpack("<Q", ix_data[:8])[0]
                            
                            if discriminator == self.BUY_DISCRIMINATOR:
                                token_amount_raw = struct.unpack("<Q", ix_data[8:16])[0]
                                token_amount = token_amount_raw / 1_000_000
                                
                                logger.info(f"Found creator buy amount: {token_amount:,.2f} tokens")
                                return token_amount
                                
        except Exception as e:
            logger.debug(f"Failed to get creator buy amount: {e}")
            
        return 0.0

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