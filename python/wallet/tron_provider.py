from os import getenv
from typing import Optional, Any
from tronpy import AsyncTron
from tronpy.keys import PrivateKey
from tronpy.providers import AsyncHTTPProvider
from dotenv import load_dotenv

from wallet.base_provider import BaseProvider
from wallet.types import AccountInfo, SignedTxResult

load_dotenv()


class TronProvider(BaseProvider):
    def __init__(
        self,
        rpc_url: Optional[str] = None,
        private_key: Optional[str] = None,
        api_key: Optional[str] = None,
        keystore_path: Optional[str] = None,
        keystore_password: Optional[str] = None,
    ):
        """
        Initialize the TronProvider.
        After construction, call `await init()` to load credentials from keystore.
        Or use `await TronProvider.create(...)` for one-step setup.
        """
        super().__init__(keystore_path=keystore_path, keystore_password=keystore_password)

        self._rpc_url = rpc_url or getenv("TRON_RPC_URL", "https://api.trongrid.io")
        self._private_key_hex: Optional[str] = private_key or getenv("TRON_PRIVATE_KEY")
        self._api_key: Optional[str] = api_key or getenv("TRON_GRID_API_KEY")
        self._key: Optional[PrivateKey] = None
        self.address: Optional[str] = None
        self.client: Optional[AsyncTron] = None

        self._build_client()

    def _build_client(self) -> None:
        """Build / rebuild the Tron client from current credentials."""
        if self._api_key:
            provider = AsyncHTTPProvider(self._rpc_url, api_key=self._api_key)
        else:
            provider = AsyncHTTPProvider(self._rpc_url)

        self.client = AsyncTron(provider=provider)

        if self._private_key_hex:
            try:
                self._key = PrivateKey(bytes.fromhex(self._private_key_hex))
                self.address = self._key.public_key.to_base58check_address()
            except Exception:
                print("Warning: Invalid private key provided")
                self._key = None
                self.address = None
        else:
            self._key = None
            self.address = None

    async def init(self) -> "TronProvider":
        """Load credentials from keystore, then rebuild client if new values found.
        Keystore keys used: privateKey, apiKey, rpcUrl
        """
        await super().init()

        ks_private_key = self.keystore.get("privateKey")
        ks_api_key = self.keystore.get("apiKey")
        ks_rpc_url = self.keystore.get("rpcUrl")

        changed = False
        if not self._private_key_hex and ks_private_key:
            self._private_key_hex = ks_private_key
            changed = True
        if not self._api_key and ks_api_key:
            self._api_key = ks_api_key
            changed = True
        if ks_rpc_url and ks_rpc_url != self._rpc_url:
            self._rpc_url = ks_rpc_url
            changed = True

        if changed:
            self._build_client()

        return self

    @classmethod
    async def create(
        cls,
        rpc_url: Optional[str] = None,
        private_key: Optional[str] = None,
        api_key: Optional[str] = None,
        keystore_path: Optional[str] = None,
        keystore_password: Optional[str] = None,
    ) -> "TronProvider":
        """Factory: create and init a TronProvider in one step."""
        provider = cls(
            rpc_url=rpc_url,
            private_key=private_key,
            api_key=api_key,
            keystore_path=keystore_path,
            keystore_password=keystore_password,
        )
        await provider.init()
        return provider

    async def get_account_info(self) -> AccountInfo:
        """Get account info (wallet address). BaseProvider compatibility."""
        if not self.address:
            raise ValueError("Address not available (no private key or wallet id)")
        return {"address": self.address}

    async def sign_tx(self, unsigned_tx: Any) -> SignedTxResult:
        """Sign unsigned transaction and return signed result. BaseProvider compatibility."""
        signed = await self.sign_transaction(unsigned_tx)
        sig = getattr(signed, "_signature", None) or getattr(signed, "signature", None)
        if isinstance(sig, list) and len(sig) > 0:
            raw_sig = sig[0]
            signature = raw_sig if isinstance(raw_sig, str) else None
        else:
            signature = None
        return {"signed_tx": signed, "signature": signature}

    async def get_balance(self, address: Optional[str] = None) -> float:
        """Get TRX balance of an address."""
        addr = address or self.address
        if not addr:
            raise ValueError("Address not provided")
        balance = await self.client.get_account_balance(addr)
        return float(balance)

    async def get_trc20_balance(self, wallet_address: str, contract_address: str) -> int:
        """Get TRC20 token balance."""
        contract = await self.client.get_contract(contract_address)
        balance = await contract.functions.balanceOf(wallet_address)
        return int(balance)

    async def send_transaction(self, to_address: str, amount: float) -> dict:
        """Send TRX to an address."""
        txn = (
            self.client.trx.transfer(self.address, to_address, amount)
            .memo("Powered by Agent Wallet")
            .fee_limit(100_000_000)
        )
        txn = await txn.build()
        signed_txn = await self.sign_transaction(txn)
        result = await signed_txn.broadcast()
        return result

    async def sign_transaction(self, transaction: Any) -> Any:
        """Sign a transaction object."""
        if not self._key:
            raise ValueError("Private key not provided for signing")
        return transaction.sign(self._key)

    async def broadcast_transaction(self, signed_transaction: Any) -> dict:
        """Broadcast a signed transaction."""
        return await signed_transaction.broadcast()
