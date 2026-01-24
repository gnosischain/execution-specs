"""
Test fee collector receives fees when coinbase is self-destructed.

This test verifies that the fee collector address receives base fees even
when the coinbase (fee recipient) is a contract that gets created and
self-destructed in the same transaction. This prevents a chain split between
clients that handle this case differently.
"""

import pytest
from execution_testing import (
    EOA,
    Account,
    Address,
    Alloc,
    Block,
    BlockchainTestFiller,
    Bytecode,
    Environment,
    Op,
    Transaction,
    compute_create_address,
)

# Fee collector address as defined in Prague fork
FEE_COLLECTOR_ADDRESS = Address("0x1559000000000000000000000000000000000000")

pytestmark = [pytest.mark.valid_from("Prague")]


@pytest.fixture
def sender(pre: Alloc) -> EOA:
    """Sender account with enough balance for the transaction."""
    return pre.fund_eoa(amount=10_000_000_000_000_000_000)  # 10 ETH


@pytest.fixture
def base_fee_per_gas() -> int:
    """Base fee per gas for the test."""
    return 1_000_000_000  # 1 gwei


@pytest.fixture
def env(base_fee_per_gas: int) -> Environment:
    """Environment for the test."""
    return Environment(
        base_fee_per_gas=base_fee_per_gas,
        gas_limit=30_000_000,
    )


def test_fee_collector_with_selfdestructed_coinbase(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    sender: EOA,
    env: Environment,
    base_fee_per_gas: int,
) -> None:
    """
    Test that fee collector receives fees when coinbase is self-destructed.
    """
    # Contract that self-destructs immediately when called
    self_destruct_code = Bytecode(
        Op.SELFDESTRUCT(Op.CALLER)
    )

    # Pre-deploy the self-destruct contract
    self_destruct_contract = pre.deploy_contract(code=self_destruct_code)

    factory_code = Bytecode(
        # Get the code size of the self-destruct contract
        Op.EXTCODESIZE(self_destruct_contract)
        # Stack: [size]
        + Op.DUP1  # Duplicate size for CREATE later
        # EXTCODECOPY(address, destOffset, offset, size)
        + Op.PUSH1(0)  # offset in source code
        + Op.PUSH1(0)  # destOffset in memory
        + Op.PUSH20(self_destruct_contract)
        + Op.EXTCODECOPY
        # Stack: [size]
        # CREATE(value, offset, size)
        + Op.PUSH1(0)  # offset in memory
        + Op.PUSH1(0)  # value to send
        + Op.CREATE
        + Op.DUP1
        # Check if CREATE succeeded
        + Op.ISZERO
        + Op.PUSH1(50)  # Jump destination if failed
        + Op.JUMPI
        # CALL(gas, address, value, argsOffset, argsSize, retOffset, retSize)
        + Op.PUSH1(0)  # retSize
        + Op.PUSH1(0)  # retOffset
        + Op.PUSH1(0)  # argsSize
        + Op.PUSH1(0)  # argsOffset
        + Op.PUSH1(0)  # value
        + Op.DUP6  # address (6th item on stack)
        + Op.GAS  # gas
        + Op.CALL
        # Clean up stack
        + Op.POP
        + Op.POP
        + Op.JUMPDEST
        + Op.STOP
    )

    # Deploy the factory
    factory = pre.deploy_contract(code=factory_code)

    # Calculate the address where the contract will be created
    created_contract_address = compute_create_address(
        address=factory,
        nonce=1,
    )

    # This transaction will create and self-destruct the contract
    tx = Transaction(
        sender=sender,
        to=factory,
        gas_limit=500_000,
        max_fee_per_gas=base_fee_per_gas * 2,
        max_priority_fee_per_gas=0,
    )

    # Set the coinbase to the contract that will be created and destroyed
    block = Block(
        txs=[tx],
        fee_recipient=created_contract_address,
    )

    blockchain_test(
        pre=pre,
        post={
            # Fee collector MUST receive the base fees
            FEE_COLLECTOR_ADDRESS: Account(storage={}),
            created_contract_address: Account.NONEXISTENT,
        },
        blocks=[block],
        genesis_environment=env,
    )
