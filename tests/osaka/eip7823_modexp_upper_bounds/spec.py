"""Defines EIP-7823 specification constants and functions."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ReferenceSpec:
    """Defines the reference spec version and git path."""

    git_path: str
    version: str


ref_spec_7823 = ReferenceSpec(
    "EIPS/eip-7823.md", "c8321494fdfbfda52ad46c3515a7ca5dc86b857c"
)


@dataclass(frozen=True)
class Spec:
    """Constants for the EIP-7825 Transaction Gas Limit Cap tests."""

    # Gas limit constants
    tx_gas_limit_cap = 10000000
