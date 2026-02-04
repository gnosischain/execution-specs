# Gnosis Chain Execution Spec Diff

This is a fork of [ethereum/execution-specs](https://github.com/ethereum/execution-specs) implementing Gnosis chain's execution layer. The approach is delta-based: only differences from Ethereum are implemented. All changes live in `fork.py` files under `src/ethereum/forks/`.

## Specs

The authoritative specifications for Gnosis execution layer differences live in the [gnosischain/specs](https://github.com/gnosischain/specs) repo:

- [posdao-post-merge.md](https://github.com/gnosischain/specs/blob/master/execution/posdao-post-merge.md) — block rewards system call, system transaction rules
- [withdrawals.md](https://github.com/gnosischain/specs/blob/master/execution/withdrawals.md) — withdrawal system calls

## System transactions

System transactions are special EVM calls made by `SYSTEM_ADDRESS` that bypass normal transaction validation. The spec defines these rules:

- Gas limit checks are disabled (not compared to `block.gas_limit - block.gas_used`)
- Caller balance and nonce checks are disabled; nonce is not incremented
- No fees are collected (no priority fee, no base fee deduction)
- `block.gas_used` is not incremented
- If the call reverts or runs out of gas, the block MUST be invalid
- For withdrawals only: if no contract is deployed at `DEPOSIT_CONTRACT_ADDRESS`, the system call is skipped and the block is still valid

## Features by fork

| Feature | Paris | Shanghai | Cancun | Prague | Osaka |
|---|---|---|---|---|---|
| Base fee collection to `FEE_COLLECTOR_ADDRESS` | Yes | Yes | Yes | Yes | Yes |
| Block rewards system call | Yes | Yes | Yes | Yes | Yes |
| Withdrawals via system call | — | Yes | Yes | Yes | Yes |
| Blob fee collection to `BLOB_FEE_COLLECTOR` | — | — | — | Yes | Yes |

## Constants

```
SYSTEM_ADDRESS                    = 0xfffffffffffffffffffffffffffffffffffffffe
SYSTEM_TRANSACTION_GAS            = 30_000_000
BLOCK_REWARDS_CONTRACT_ADDRESS    = 0x2000000000000000000000000000000000000001
DEPOSIT_CONTRACT_ADDRESS          = 0xbabe2bed00000000000000000000000000000003
FEE_COLLECTOR_ADDRESS             = 0x1559000000000000000000000000000000000000
BLOB_FEE_COLLECTOR                = 0x1559000000000000000000000000000000000000
MAX_FAILED_WITHDRAWALS_TO_PROCESS = 4
```

## Block rewards (`process_block_rewards`)

Called at the start of every block before user transactions. Calls `BLOCK_REWARDS_CONTRACT_ADDRESS` with selector `f91c2898` (`reward(address[],uint16[])`). Decodes the return as `(address[], uint256[])` and increases each address's balance by the corresponding amount.

Implementation: `fork.py:process_block_rewards` in Paris through Osaka.

## Withdrawals (`process_withdrawals`)

Called after all user transactions. Calls `DEPOSIT_CONTRACT_ADDRESS` with selector `79d0c0bc` (`executeSystemWithdrawals(uint256,uint64[],address[])`) passing `MAX_FAILED_WITHDRAWALS_TO_PROCESS`, withdrawal amounts (GWei), and withdrawal addresses.

Implementation: `fork.py:process_withdrawals` in Shanghai through Osaka.

## Base fee collection

After each user transaction, the base fee portion (`gas_used * base_fee_per_gas`) is sent to `FEE_COLLECTOR_ADDRESS` instead of being burned. This replaces Ethereum's EIP-1559 burn.

## Blob fee collection (Prague+)

After each user transaction with blobs, the blob gas fee is sent to `BLOB_FEE_COLLECTOR`.

## Gnosis-specific limits (Osaka+)

- `BLOB_COUNT_LIMIT = 2`
- `MAX_BLOB_GAS_PER_BLOCK = 262144`
