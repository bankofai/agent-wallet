"""Abstract base provider: compatible get_account_info and sign_tx.

Each provider holds a Keystore instance. Call `init()` to load credentials
from keystore, or use the classmethod `create()` for one-step setup.
"""
from abc import ABC, abstractmethod
from typing import Any, Optional

from wallet.types import AccountInfo, SignedTxResult
from keystore.base import KeystoreBase
from keystore.keystore import Keystore


class BaseProvider(ABC):
    """
    Abstract base provider. Subclasses (TronProvider, FlashProvider) implement
    chain-specific logic.
    """

    def __init__(
        self,
        keystore_path: Optional[str] = None,
        keystore_password: Optional[str] = None,
        keystore: Optional[KeystoreBase] = None,
    ):
        # Allow injecting a custom keystore implementation.
        self.keystore: KeystoreBase = keystore or Keystore(
            file_path=keystore_path, password=keystore_password
        )

    async def init(self) -> "BaseProvider":
        """Load credentials from keystore. Subclasses override to populate
        chain-specific fields (private_key, api_key, etc.) from keystore data.
        """
        self.keystore.read()
        return self

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
