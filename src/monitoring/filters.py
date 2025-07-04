from typing import List
import base64
import struct
import logging

logger = logging.getLogger(__name__)

def validate_creator_initial_buy(
    logs: List[str], 
    buy_discriminator: int, 
    token_decimals: int, 
    max_buy: float
) -> bool:
    """
    Validates the creator's initial buy amount against the max threshold.

    Args:
        logs: The logs from the transaction.
        buy_discriminator: The discriminator for the "buy" instruction.
        token_decimals: The number of decimals for the token.
        max_buy: The maximum allowed buy amount.

    Returns:
        True if the creator's initial buy amount is within the threshold, False otherwise.
    """
    for log in logs:
        if "Program data:" not in log:
            continue

        try:
            # Extract and decode the program data from the log
            encoded_data = log.split(": ")[1]
            decoded_data = base64.b64decode(encoded_data)

            # Ensure the decoded data is long enough to contain the discriminator and amount
            if len(decoded_data) < 16:
                logger.warning("Decoded data is too short to contain a valid buy instruction.")
                continue

            # Extract the discriminator and validate it
            discriminator = struct.unpack("<Q", decoded_data[:8])[0]
            if discriminator != buy_discriminator:
                logger.debug(f"Skipping log with invalid discriminator: {discriminator}")
                continue

            # Extract the amount field and scale it based on token decimals
            amount_raw = struct.unpack("<Q", decoded_data[8:16])[0]
            scaled_amount = amount_raw / (10 ** token_decimals)

            logger.debug(f"Creator buy amount: {scaled_amount:,.2f}")

            # Validate the scaled amount against the max threshold
            return scaled_amount <= max_buy
        except Exception as e:
            logger.error(f"Failed to validate creator buy amount: {e}")
            continue

    # If no valid buy instruction is found, return False
    return False