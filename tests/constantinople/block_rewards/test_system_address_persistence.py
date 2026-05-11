"""
Tests for SYSTEM_ADDRESS persistence across blocks with AuRa system calls.

Invariant tested here: SYSTEM_ADDRESS is pre-allocated in genesis and MUST
survive every block, regardless of whether a system call fires.
"""

import pytest
from execution_testing import (
    Account,
    Address,
    Alloc,
    Block,
    BlockchainTestFiller,
    Op,
    Transaction,
)

pytestmark = [
    pytest.mark.valid_from("ConstantinopleFix"),
    pytest.mark.pre_alloc_mutable,
]

SYSTEM_ADDRESS = Address(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE)
BLOCK_REWARDS_CONTRACT = Address(0x2000000000000000000000000000000000000001)

# ABI-encoded (address[], uint256[]) with both arrays empty — minimal valid
# return value for the reward() function.
EMPTY_REWARD_RETURN = (
    Op.MSTORE(0x00, 0x40)
    + Op.MSTORE(0x20, 0x60)
    + Op.MSTORE(0x40, 0x00)
    + Op.MSTORE(0x60, 0x00)
    + Op.RETURN(0, 128)
)


def test_system_address_persists_after_block_rewards(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    SYSTEM_ADDRESS must remain in state after a block that fires the block
    rewards system call.
    """
    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=EMPTY_REWARD_RETURN,
        nonce=1,
        balance=0,
    )

    blockchain_test(
        pre=pre,
        blocks=[Block()],
        post={
            SYSTEM_ADDRESS: Account(nonce=0, balance=0),
        },
    )


def test_system_address_persists_without_rewards_contract(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    SYSTEM_ADDRESS must remain in state even when the block rewards contract
    has no code (system call is skipped).

    This covers the case where no AuRa system call fires at all. SYSTEM_ADDRESS
    was never "touched" in any form, yet it must survive because the deletion
    path (destroy_touched_empty_accounts) only runs against touched accounts.
    """
    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=b"",
        nonce=0,
        balance=0,
    )

    blockchain_test(
        pre=pre,
        blocks=[Block()],
        post={
            SYSTEM_ADDRESS: Account(nonce=0, balance=0),
        },
    )


def test_system_address_persists_across_multiple_blocks(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    SYSTEM_ADDRESS must remain in state across multiple consecutive blocks,
    each of which fires the block rewards system call.
    """
    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=EMPTY_REWARD_RETURN,
        nonce=1,
        balance=0,
    )

    blockchain_test(
        pre=pre,
        blocks=[Block(), Block(), Block()],
        post={
            SYSTEM_ADDRESS: Account(nonce=0, balance=0),
        },
    )


def test_system_address_not_affected_by_eip161_deletion(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    SYSTEM_ADDRESS must not be deleted by EIP-161 empty-account cleanup.

    EIP-161 (SpuriousDragon) deletes empty accounts that are "touched" during
    a transaction. SYSTEM_ADDRESS is an empty account, but it is the *caller*
    of system transactions — not the target — so it is never added to the set
    of touched accounts and must never be cleaned up by EIP-161 rules.

    The block here contains a user transaction that touches a fresh contract
    (which in turn would normally be subject to EIP-161 cleanup if it ends up
    empty). SYSTEM_ADDRESS must remain untouched throughout.
    """
    # Deploy a contract that simply stores the block number, to create a
    # genuine user transaction that goes through EIP-161 cleanup logic.
    contract = pre.deploy_contract(code=Op.SSTORE(0, Op.NUMBER))
    sender = pre.fund_eoa(10**18)

    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=EMPTY_REWARD_RETURN,
        nonce=1,
        balance=0,
    )

    blockchain_test(
        pre=pre,
        blocks=[
            Block(
                txs=[
                    Transaction(
                        sender=sender,
                        to=contract,
                        gas_limit=100_000,
                    )
                ]
            )
        ],
        post={
            SYSTEM_ADDRESS: Account(nonce=0, balance=0),
            contract: Account(storage={0: 1}),
        },
    )


def test_system_address_is_caller_not_target(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Verify that msg.sender inside the block rewards system call is
    SYSTEM_ADDRESS, confirming that SYSTEM_ADDRESS acts as the caller (and
    therefore is NOT touched as a target and NOT subject to EIP-161 deletion).
    """
    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=Op.SSTORE(0, Op.CALLER) + EMPTY_REWARD_RETURN,
        nonce=1,
        balance=0,
    )

    blockchain_test(
        pre=pre,
        blocks=[Block()],
        post={
            BLOCK_REWARDS_CONTRACT: Account(
                storage={0: int.from_bytes(SYSTEM_ADDRESS, "big")},
            ),
            SYSTEM_ADDRESS: Account(nonce=0, balance=0),
        },
    )


def test_system_address_persists_validator_set_transition(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Simulate the Gnosis block 1300→1301 validator-set transition scenario.

    At block 1300 on Gnosis mainnet, the safeContract validator set was
    activated. Block 1301 was the first block where FinalizeChange() was
    called as a system transaction from SYSTEM_ADDRESS.  Clients that did not
    correctly retain SYSTEM_ADDRESS in state computed a different state root
    and rejected block 1301.

    This test simulates the pattern:
      Block N   — system call fires; a "pending change" is written to storage.
      Block N+1 — another system call fires (simulating FinalizeChange); the
                  pending change is consumed. SYSTEM_ADDRESS must be present
                  in the post-state of both blocks.

    The block rewards contract here doubles as the mock validator-set contract:
    on the first call it records a "pending" flag; on the second call it clears
    it, simulating the InitiateChange/FinalizeChange lifecycle.
    """
    # Toggle slot 0 on each call: 0→1 (InitiateChange), 1→0 (FinalizeChange).
    # ISZERO flips 0↔1 without any conditional jumps.
    finalize_change_contract = (
        Op.PUSH1(0)
        + Op.SLOAD
        + Op.ISZERO
        + Op.PUSH1(0)
        + Op.SSTORE
        + EMPTY_REWARD_RETURN
    )

    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=finalize_change_contract,
        nonce=1,
        balance=0,
    )

    blockchain_test(
        pre=pre,
        blocks=[Block(), Block()],
        post={
            BLOCK_REWARDS_CONTRACT: Account(storage={0: 0}),
            SYSTEM_ADDRESS: Account(nonce=0, balance=0),
        },
    )
