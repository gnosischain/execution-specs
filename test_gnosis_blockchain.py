"""
Simple test for Gnosis blockchain without pre-allocated accounts.

This test demonstrates a minimal blockchain test that should work
without complex pre-allocated account configurations.

"""

import pytest
from execution_testing import (
    Account,
    Alloc,
    Block,
    BlockchainTestFiller,
    Environment,
    TestAddress,
    TestPrivateKey,
    Transaction,
)

pytestmark = pytest.mark.valid_from("Shanghai")


def test_gnosis_simple(blockchain_test: BlockchainTestFiller):  # noqa: D103
    env = Environment()

    pre = Alloc({
        TestAddress: Account(balance=1_000_000_000_000_000_000),  # 1 ETH
    })

    # Empty post state - no changes expected for an empty block
    post = Alloc()

    # Create the blockchain test with an empty block
    blockchain_test(
        genesis_environment=env,
        pre=pre,
        post=post,
        blocks=[Block(txs=[])],
    )


def test_gnosis_with_transaction(blockchain_test: BlockchainTestFiller):  # noqa: D103
    # Minimal environment (will use Gnosis defaults from plugin)
    env = Environment()

    # Minimal pre-state - just the test account
    pre = Alloc(
        {
            TestAddress: Account(
                balance=1_000_000_000_000_000_000,
                nonce=0,
            ),  # 1 ETH
            0x00000000219AB540356CBB839CBE05303D7705FA: Account(balance=0),
        }
    )

    # Simple transaction that transfers some ETH to null address
    tx = Transaction(
        to=0x00000000219AB540356CBB839CBE05303D7705FA,
        value=1000,
        gas_limit=21000,
        nonce=0,  # TestAddress starts with nonce 0 in both mainnet and gnosis
        sender=TestAddress,
        secret_key=TestPrivateKey,
    )

    # Expected post-state after transaction
    # Recipient receives 1000 wei, sender's nonce increments
    # Balance verification handles gas costs automatically
    post = Alloc({
        TestAddress: Account(
            nonce=1,  # Transaction increments nonce
        ),
        0x00000000219AB540356CBB839CBE05303D7705FA: Account(
            balance=1000,  # Received the transfer
        ),
    })

    # Create the blockchain test with one transaction
    blockchain_test(
        genesis_environment=env,
        pre=pre,
        post=post,
        blocks=[Block(txs=[tx])],
    )


if __name__ == "__main__":
    pass
