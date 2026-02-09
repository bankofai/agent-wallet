"""Abstract base provider: compatible get_account_info and sign_tx."""
from abc import ABC, abstractmethod
from typing import Any

from wallet.types import AccountInfo, SignedTxResult


class BaseProvider(ABC):
    """
    Abstract base provider. Subclasses (TronProvider, FlashProvider) implement
    chain-specific logic.
    """

    @abstractmethod
    async def get_account_info(self) -> AccountInfo:
        """Get account info; must include wallet address."""
        ...

    @abstractmethod
    async def sign_tx(self, unsigned_tx: Any) -> SignedTxResult:
        """
        Sign an unsigned transaction and return the signed result.
        :param unsigned_tx: Chain-specific unsigned transaction object
        :return: Dict with signed_tx and optional signature
        """
        ...
