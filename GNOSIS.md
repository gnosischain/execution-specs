# Gnosis Chain Execution Spec Diff

This is a fork of [ethereum/execution-specs](https://github.com/ethereum/execution-specs) implementing Gnosis chain's execution layer. The approach is delta-based: only differences from Ethereum are implemented. All changes live in `fork.py` files under `src/ethereum/forks/`.

## Specs

The authoritative specifications for Gnosis execution layer differences live in the [gnosischain/specs](https://github.com/gnosischain/specs) repo:

- [posdao-post-merge.md](https://github.com/gnosischain/specs/blob/master/execution/posdao-post-merge.md) — block rewards system call, system transaction rules
- [withdrawals.md](https://github.com/gnosischain/specs/blob/master/execution/withdrawals.md) — withdrawal system calls
- [network-upgrades/london.md](https://github.com/gnosischain/specs/blob/master/network-upgrades/london.md) — EIP-1559 fee collector (pre-merge)
- [network-upgrades/istanbul.md](https://github.com/gnosischain/specs/blob/master/network-upgrades/istanbul.md) — EIP-1283 re-enabled, EIP-2200 not included
- [network-upgrades/berlin.md](https://github.com/gnosischain/specs/blob/master/network-upgrades/berlin.md) — identical to Ethereum mainnet

### Known divergences (pre-merge)

- **Istanbul**: Gnosis re-enabled EIP-1283 (not EIP-2200). The current `istanbul/fork.py` follows Ethereum mainnet semantics (EIP-2200). This does not affect the t8n block-level machinery but may cause SSTORE gas mismatches in tests targeting the exact Istanbul EIP-1283 behaviour.
- **Constantinople**: EIP-1283 was activated, then de-activated in the Gnosis-specific ConstantinopleFix fork (block 2,508,800). This fork is not separately represented; Constantinople here follows standard Ethereum semantics.

## System transactions

System transactions are special EVM calls made by `SYSTEM_ADDRESS` that bypass normal transaction validation. The spec defines these rules:

- Gas limit checks are disabled (not compared to `block.gas_limit - block.gas_used`)
- Caller balance and nonce checks are disabled; nonce is not incremented
- No fees are collected (no priority fee, no base fee deduction)
- `block.gas_used` is not incremented
- If the call reverts or runs out of gas, the block MUST be invalid
- For withdrawals only: if no contract is deployed at `DEPOSIT_CONTRACT_ADDRESS`, the system call is skipped and the block is still valid

## Features by fork

### Pre-merge forks (Frontier → London)

| Feature | Frontier | Homestead | DAO | TW | SD | Byz | Con | Istn | Berlin | London |
|---|---|---|---|---|---|---|---|---|---|---|
| Block rewards system call | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Base fee collection to `FEE_COLLECTOR_ADDRESS` | — | — | — | — | — | — | — | — | — | Yes |

> **TW** = TangerineWhistle, **SD** = SpuriousDragon, **Byz** = Byzantium, **Con** = Constantinople, **Istn** = Istanbul
>
> Pre-merge block rewards replace Ethereum's PoW coinbase reward with a system call to `BLOCK_REWARDS_CONTRACT_ADDRESS`.
> London's `FEE_COLLECTOR_ADDRESS` is `0x1559000000000000000000000000000000000000` (same as all post-merge forks).

### Post-merge forks (Paris → Osaka)

| Feature | Paris | Shanghai | Cancun | Prague | Osaka |
|---|---|---|---|---|---|
| Base fee collection to `FEE_COLLECTOR_ADDRESS` | Yes | Yes | Yes | Yes | Yes |
| Block rewards system call | Yes | Yes | Yes | Yes | Yes |
| Withdrawals via system call | — | Yes | Yes | Yes | Yes |
| Blob fee collection to `BLOB_FEE_COLLECTOR` | — | — | — | Yes | Yes |

## Constants

```text
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
