# Gnosis Chain Execution Spec Diff

This is a fork of [ethereum/execution-specs](https://github.com/ethereum/execution-specs) implementing Gnosis chain's execution layer. The approach is delta-based: only differences from Ethereum are implemented. All changes live in `fork.py` files under `src/ethereum/forks/`.

## Specs

The authoritative specifications for Gnosis execution layer differences live in the [gnosischain/specs](https://github.com/gnosischain/specs) repo:

- [posdao-post-merge.md](https://github.com/gnosischain/specs/blob/master/execution/posdao-post-merge.md) — block rewards system call, system transaction rules
- [withdrawals.md](https://github.com/gnosischain/specs/blob/master/execution/withdrawals.md) — withdrawal system calls
- [network-upgrades/london.md](https://github.com/gnosischain/specs/blob/master/network-upgrades/london.md) — EIP-1559 fee collector (pre-merge)
- [network-upgrades/istanbul.md](https://github.com/gnosischain/specs/blob/master/network-upgrades/istanbul.md) — EIP-1283 re-enabled, EIP-2200 not included
- [network-upgrades/berlin.md](https://github.com/gnosischain/specs/blob/master/network-upgrades/berlin.md) — identical to Ethereum mainnet

## Fork history

Gnosis chain launched in 2018 with Constantinople already active. Frontier, Homestead, and Byzantium predate Gnosis and were never activated on Gnosis mainnet. The following forks are marked `ignore=True` in the test framework (skipped during fill):

- DAOFork, TangerineWhistle, SpuriousDragon — pre-Gnosis Ethereum-only forks
- MuirGlacier, ArrowGlacier, GrayGlacier — difficulty-bomb-only forks, not activated on Gnosis

The active Gnosis fork sequence starts at ConstantinopleFix:

```text
ConstantinopleFix → Istanbul → Berlin → London →
Paris (Merge) → Shanghai → Cancun → Prague → Osaka
```

Pre-merge forks (ConstantinopleFix → London) use AuRa consensus. Paris and later use standard Ethereum PoS.

### Known divergences (pre-merge)

- **Istanbul**: Gnosis re-enabled EIP-1283 (not EIP-2200). The current `istanbul/fork.py` follows Ethereum mainnet semantics (EIP-2200). This does not affect the t8n block-level machinery but may cause SSTORE gas mismatches in tests targeting the exact Istanbul EIP-1283 behaviour.
- **Constantinople**: EIP-1283 was activated, then de-activated in the Gnosis-specific ConstantinopleFix fork (block 2,508,800). This fork is not separately represented; Constantinople here follows standard Ethereum semantics.

## AuRa consensus encoding (pre-merge)

Pre-merge Gnosis blocks (Constantinople → London) use Authority Round (AuRa) consensus instead of Ethereum's PoW. AuRa-encoded fixture headers differ from standard Ethereum headers in three fields:

| Header field | Standard Ethereum | AuRa (Gnosis pre-merge) |
|---|---|---|
| `nonce` | 8-byte PoW nonce (`Bytes8`) | 65-byte ECDSA seal (`r‖s‖v`) over the unsealed header |
| `mixHash` / `prev_randao` | PoW mix hash | AuRa step (block number as `uint256`) |
| `difficulty` | Calculated PoW difficulty | Fixed: `(1 << 128) - 2` |

Genesis blocks use an all-zero 65-byte seal. Non-genesis seals are signed with the test validator key (`TestPrivateKey`). The unsealed header excludes `prev_randao` and `nonce` fields before hashing.

AuRa encoding is applied automatically by the fixture framework for any fork where `header_zero_difficulty_required()` returns `False` (all pre-merge forks). `header_zero_difficulty_required()` is overridden to `True` starting with Paris (EIP-3675), so post-merge forks use standard encoding automatically.

Implementation: `packages/testing/src/execution_testing/fixtures/blockchain.py` — `rlp_encode_list` property and `_aura_signature` cached property on `FixtureHeader`.

The block environment also sets AuRa-specific values for pre-merge non-genesis blocks:

- `fee_recipient` → `TestAddress`
- `difficulty` → `(1 << 128) - 2`

Implementation: `packages/testing/src/execution_testing/test_types/block_types.py` — `Environment.set_fork_requirements()`.

## Fixture generation strategy

| Recipe | `--from` | `--until` | Encoding | Purpose |
|---|---|---|---|---|
| `just fill` | `ConstantinopleFix` | `Osaka` (latest) | AuRa (pre-merge), standard (post-merge) | Gnosis Hive client tests |
| `just fill-pypy` | `ConstantinopleFix` | `Osaka` (latest) | AuRa (pre-merge), standard (post-merge) | PyPy fill verification |
| `just json-loader` | `Paris` | `Osaka` (latest) | Standard only | EELS Python spec validation |

Pre-merge forks are excluded from `json-loader` because EELS validates headers using standard Ethereum rules (8-byte `Bytes8` nonce, PoW difficulty check) which are incompatible with AuRa headers.

The `just fill` recipe (and `fill-pypy`) starts from `ConstantinopleFix` because:

1. Gnosis chain launched at ConstantinopleFix — pre-ConstantinopleFix forks never existed on Gnosis mainnet.
2. The `BLOCK_REWARDS_CONTRACT` pre-allocation is defined on `ConstantinopleFix` in the test framework — the first fork that actually ran on Gnosis mainnet.

Note: `SYSTEM_ADDRESS` is **not** pre-allocated in genesis. It is materialized on demand via `touch_account` immediately before each system EVM call. See [SYSTEM_ADDRESS lifecycle](#system_address-lifecycle) below for the rationale and the known Nethermind divergence.

## System transactions

System transactions are special EVM calls made by `SYSTEM_ADDRESS` that bypass normal transaction validation. The spec defines these rules:

- Gas limit checks are disabled (not compared to `block.gas_limit - block.gas_used`)
- Caller balance and nonce checks are disabled; nonce is not incremented
- No fees are collected (no priority fee, no base fee deduction)
- `block.gas_used` is not incremented
- If the call reverts or runs out of gas, the block MUST be invalid
- For withdrawals only: if no contract is deployed at `DEPOSIT_CONTRACT_ADDRESS`, the system call is skipped and the block is still valid

## SYSTEM_ADDRESS lifecycle

`SYSTEM_ADDRESS` (`0xfffffffffffffffffffffffffffffffffffffffe`) is the caller of all AuRa system transactions. It is not pre-allocated in genesis; instead, `touch_account(state, SYSTEM_ADDRESS)` is called immediately before every system EVM call that uses it as the sender, across all forks:

- **Pre-merge** (`ConstantinopleFix` → `London`): called in `process_block_rewards` (once per block).
- **Post-merge** (`Paris` → `Osaka`): called in both `process_block_rewards` and `process_withdrawals` (once per site, once per block each).

`touch_account` writes the empty account via `set_account` directly.

### Known divergence: Nethermind

Nethermind's AuRa path has two behaviors that cause it to produce a different trie from Geth, Erigon, and Reth:

1. `SystemSpec.IsEip158Enabled = false` in the system-call path — forces `StateProvider` to write an empty `SYSTEM_ADDRESS` account on every system call ([StateProvider.cs#L560-L570](https://github.com/NethermindEth/nethermind/blob/master/src/Nethermind/Nethermind.State/StateProvider.cs#L560-L570)).
2. `Eip158IgnoredAccount = Address.SystemUser` — exempts `SystemUser` from the EIP-158 sweep, so the empty leaf is never deleted ([StateProvider.cs#L768-L772](https://github.com/NethermindEth/nethermind/blob/master/src/Nethermind/Nethermind.State/StateProvider.cs#L768-L772)).

The combined effect is that Nethermind always has an empty `0xff…fe` leaf in the trie after the first system call, whereas Geth/Erigon/Reth do not fabricate a state footprint for the caller. Fixtures generated from this spec therefore pass on Geth/Erigon/Reth and fail on Nethermind. This divergence was also flagged in the [Gnosis core devs call (Sep 2023)](https://www.gnosis.io/blog/gnosis-core-devs-call-notes-september-6-2023). Resolution is pending alignment with the Nethermind team on whether the AuRa exemption should be removed or codified in the Gnosis spec.

## Features by fork

### Pre-merge forks (Constantinople → London)

| Feature | Con | ConstFix | Istn | Berlin | London |
|---|---|---|---|---|---|
| Block rewards system call | Yes | Yes | Yes | Yes | Yes |
| Base fee collection to `FEE_COLLECTOR_ADDRESS` | — | — | — | — | Yes |

> **Con** = Constantinople, **ConstFix** = ConstantinopleFix (Petersburg), **Istn** = Istanbul
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

Gnosis-specific blob limits (Osaka+, override Ethereum mainnet values):

```text
BLOB_COUNT_LIMIT       = 2
MAX_BLOB_GAS_PER_BLOCK = GasCosts.BLOB_SCHEDULE_MAX * GasCosts.PER_BLOB
```

Prague and Cancun also override `MAX_BLOB_GAS_PER_BLOCK = U64(262144)`.

## Block rewards (`process_block_rewards`)

Called at the start of every block before user transactions. Calls `BLOCK_REWARDS_CONTRACT_ADDRESS` with selector `f91c2898` (`reward(address[],uint16[])`). Decodes the return as `(address[], uint256[])` and increases each address's balance by the corresponding amount.

If no contract is deployed at `BLOCK_REWARDS_CONTRACT_ADDRESS`, the call is silently skipped (allows tests with minimal pre-state). In this case `SYSTEM_ADDRESS` is also not materialized for that block — see [SYSTEM_ADDRESS lifecycle](#system_address-lifecycle).

Implementation: `fork.py:process_block_rewards` in ConstantinopleFix through Osaka.

## Withdrawals (`process_withdrawals`)

Called after all user transactions. Calls `DEPOSIT_CONTRACT_ADDRESS` with selector `79d0c0bc` (`executeSystemWithdrawals(uint256,uint64[],address[])`) passing `MAX_FAILED_WITHDRAWALS_TO_PROCESS`, withdrawal amounts (GWei), and withdrawal addresses.

The deposit contract is pre-allocated from Shanghai onwards. If no contract is deployed at `DEPOSIT_CONTRACT_ADDRESS`, the call is skipped and the block remains valid.

Implementation: `fork.py:process_withdrawals` in Shanghai through Osaka.

## Base fee collection

After each user transaction, the base fee portion (`gas_used * base_fee_per_gas`) is sent to `FEE_COLLECTOR_ADDRESS` instead of being burned. This replaces Ethereum's EIP-1559 burn.

Implementation: `fork.py:process_transaction` in London through Osaka.

## Blob fee collection (Prague+)

After each user transaction with blobs, the blob gas fee is sent to `BLOB_FEE_COLLECTOR`.

Implementation: `fork.py:process_transaction` in Prague through Osaka.
