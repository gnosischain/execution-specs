"""
EIP-4895: Beacon chain push withdrawals as operations.

Support validator withdrawals from the beacon chain to the EVM via a new
"system-level" operation type.

https://eips.ethereum.org/EIPS/eip-4895
"""

from pathlib import Path
from typing import List, Mapping

from execution_testing.base_types import Address

from ....base_fork import BaseFork

CONTRACTS_DIR = Path(__file__).parent.parent.parent / "contracts"
DEPOSIT_CONTRACT_ADDRESS = 0xBABE2BED00000000000000000000000000000003
DEPOSIT_CONTRACT_BYTECODE = (
    CONTRACTS_DIR / "deposit_contract.bin"
).read_bytes()


class EIP4895(
    BaseFork,
    engine_new_payload_version_bump=True,
    engine_forkchoice_updated_version_bump=True,
    engine_get_payload_version_bump=True,
):
    """EIP-4895 class."""

    @classmethod
    def header_withdrawals_required(cls) -> bool:
        """Withdrawals are required."""
        return True

    @classmethod
    def system_contracts(cls) -> List[Address]:
        """Deposit contract is present from Shanghai onwards."""
        return [
            Address(
                DEPOSIT_CONTRACT_ADDRESS,
                label="DEPOSIT_CONTRACT_ADDRESS",
            ),
        ] + super(EIP4895, cls).system_contracts()

    @classmethod
    def pre_allocation_blockchain(cls) -> Mapping:
        """Pre-allocate the Gnosis deposit contract."""
        return {
            DEPOSIT_CONTRACT_ADDRESS: {
                "nonce": 1,
                "code": DEPOSIT_CONTRACT_BYTECODE,
            },
        } | super(EIP4895, cls).pre_allocation_blockchain()  # type: ignore
