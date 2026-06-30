"""
EIP-6110: Supply validator deposits on chain.

Provides validator deposits as a list of deposit operations added to the
Execution Layer block.

https://eips.ethereum.org/EIPS/eip-6110
"""

from hashlib import sha256
from typing import List, Mapping

from execution_testing.base_types import Address

from ....base_fork import BaseFork
from ....bytecode import load_contract_bytecode

DEPOSIT_CONTRACT_ADDRESS = 0xBABE2BED00000000000000000000000000000003
DEPOSIT_CONTRACT_BYTECODE = load_contract_bytecode(
    __name__, "deposit_contract.bin"
)


class EIP6110(BaseFork):
    """EIP-6110 class."""

    @classmethod
    def pre_allocation_blockchain(cls) -> Mapping:
        """Upgrade the beacon chain deposit contract."""
        deposit_contract_tree_depth = 32
        storage = {}
        next_hash = sha256(b"\x00" * 64).digest()
        for i in range(
            deposit_contract_tree_depth + 2,
            deposit_contract_tree_depth * 2 + 1,
        ):
            storage[i] = next_hash
            next_hash = sha256(next_hash + next_hash).digest()

        return {
            DEPOSIT_CONTRACT_ADDRESS: {
                "nonce": 1,
                "code": DEPOSIT_CONTRACT_BYTECODE,
                "storage": storage,
            },
            **super(EIP6110, cls).pre_allocation_blockchain(),
        }
