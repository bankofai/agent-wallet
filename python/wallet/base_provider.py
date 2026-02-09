"""Abstract base provider: compatible get_account_info and sign_tx.

Providers hold a keystore instance. Call `init()` to load credentials from
keystore, or use a helper factory on concrete providers if provided.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from keystore.base import KeystoreBase
from keystore.keystore import Keystore
from wallet.types import AccountInfo, SignedTxResult


class BaseProvider(ABC):
    """Abstract provider base class."""

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
        """Load keystore (constructors cannot be async)."""
        self.keystore.read()
        return self

    @abstractmethod
    async def get_account_info(self) -> AccountInfo:
        """Get account info; must include wallet address."""
        ...

    @abstractmethod
    async def sign_tx(self, unsigned_tx: Any) -> SignedTxResult:
        """Sign an unsigned transaction and return signed result."""
        ...

