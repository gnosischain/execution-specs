"""
Regression test: SYSTEM_ADDRESS must remain in the state trie after
every block that executes a system call (block-rewards or fee-collection).

Background
----------
geth PR #33741 "core/vm: disable the value transfer in syscall" removed the
zero-value Context.Transfer that historically journaled SYSTEM_ADDRESS as
dirty, causing it to survive ``Finalise`` (which skips the SystemAddress
exclusion).  Without that transfer, a full sync from genesis never writes
SYSTEM_ADDRESS into the state trie.

On Gnosis mainnet this first manifests at block 1301, the block after the
AuRa safeContract multi-transition at block 1300.  The execution-spec
reference implementation always journals SYSTEM_ADDRESS through the
system-call path; any client that diverges will produce a different trie
root and fail to import block 1301.

What this test checks
---------------------
1. After the *first* block (which triggers a system call via
   ``process_block_rewards``), SYSTEM_ADDRESS must exist in the post-state
   with the same nonce/balance it had in genesis — zero-value but present.

2. A second block (simulating the transition) must still find SYSTEM_ADDRESS
   in the trie and produce an identical root.  A client that silently
   dropped SYSTEM_ADDRESS after block 1 will diverge here.

The test is intentionally minimal: no user transactions, no reward
distribution, just the system-call side-effect on SYSTEM_ADDRESS.

References
----------
- https://github.com/ethereum/go-ethereum/pull/33741
- https://github.com/gnosischain/specs/blob/master/execution/posdao-post-merge.md

"""

import pytest
from execution_testing import (
    Account,
    Address,
    Alloc,
    Block,
    BlockchainTestFiller,
    Bytecode,
    Op,
)

pytestmark = [
    pytest.mark.valid_from("ConstantinopleFix"),
    pytest.mark.valid_before("Paris"),
    pytest.mark.pre_alloc_mutable,
]

SYSTEM_ADDRESS = Address(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE)
BLOCK_REWARDS_CONTRACT = Address(0x2000000000000000000000000000000000000001)


def _no_op_rewards_bytecode() -> Bytecode:
    """
    Minimal block-rewards contract: returns empty (address[], uint256[]).

    The system call succeeds, no balances are changed, but SYSTEM_ADDRESS
    is still journaled as the call origin.
    """
    return (
        Op.MSTORE(0x00, 0x40)
        + Op.MSTORE(0x20, 0x60)
        + Op.MSTORE(0x40, 0x00)
        + Op.MSTORE(0x60, 0x00)
        + Op.RETURN(0, 128)
    )


def test_system_address_persists_after_system_call(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    SYSTEM_ADDRESS must be present in the state trie after a block that
    executes a system call, even when no value is transferred.

    A client implementing geth PR #33741 without the Gnosis-specific
    MakeAuraSyscall fix will omit the zero-value transfer, never journal
    SYSTEM_ADDRESS, and drop it from the trie during Finalise.  The
    resulting stateRoot diverges from the canonical value starting with the
    first block that runs a system call, which on Gnosis mainnet is block 1.
    """
    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=_no_op_rewards_bytecode(),
        nonce=1,
        balance=0,
    )

    # SYSTEM_ADDRESS is pre-allocated in genesis by the framework
    # (ConstantinopleFix.pre_allocation_blockchain); we verify it is still
    # there — unchanged — after a block executes the system call.
    blocks = [Block()]

    post = {
        SYSTEM_ADDRESS: Account(nonce=0, balance=0),
    }

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_system_address_persists_across_validator_set_transition(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    SYSTEM_ADDRESS must survive two consecutive system-call blocks.

    This models the Gnosis mainnet scenario around block 1300→1301:
    - Block N   triggers the AuRa safeContract transition (system call).
    - Block N+1 must find SYSTEM_ADDRESS in the trie and produce the
      canonical stateRoot.

    A buggy client drops SYSTEM_ADDRESS after block N, so its trie root
    for block N+1 diverges from the canonical value — exactly the
    "invalid merkle root" error observed at block 1301 during full sync
    with unpatched geth v1.17.1-gc.
    """
    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=_no_op_rewards_bytecode(),
        nonce=1,
        balance=0,
    )

    # Two consecutive blocks, each triggering a system call.
    # Block 1 corresponds to the transition block (e.g. block 1300).
    # Block 2 corresponds to the first block after the transition (block 1301).
    blocks = [Block(), Block()]

    post = {
        SYSTEM_ADDRESS: Account(nonce=0, balance=0),
    }

    blockchain_test(pre=pre, post=post, blocks=blocks)
