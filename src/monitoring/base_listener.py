"""
Base class for WebSocket token listeners.
Enhanced to support creator token amount filtering across all listener types.
"""

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable

from trading.base import TokenInfo


class BaseTokenListener(ABC):
    """
    Base abstract class for token listeners.
    
    This interface ensures that all listener types (logs, blocks, geyser, etc.)
    support the same filtering capabilities. This design allows you to switch
    between different listener types while maintaining the same filtering logic.
    """

    @abstractmethod
    async def listen_for_tokens(
        self,
        token_callback: Callable[[TokenInfo], Awaitable[None]],
        match_string: str | None = None,
        creator_address: str | None = None,
    ) -> None:
        """
        Listen for new token creations with comprehensive filtering.

        This method defines the interface that all listener implementations must follow.
        By standardizing the parameters across all listener types, we ensure that
        the trader can work with any listener while applying the same filters.

        Args:
            token_callback: Callback function to invoke when a valid token is found
            match_string: Optional string to match in token name/symbol (case-insensitive)
            creator_address: Optional creator address to filter by (exact match)
"""
        pass