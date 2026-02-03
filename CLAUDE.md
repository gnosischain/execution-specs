# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Gnosis chain fork** of the Ethereum Execution Layer Specifications (EELS) — a Python reference implementation of Ethereum's execution client. It prioritizes readability and correctness over performance. The Gnosis fork adds chain-specific logic (base fee collection, block rewards contract minting, modified withdrawals via system calls).

Current branch `gnosis-osaka` tracks upstream through the Osaka hard fork. The `master` branch is the main branch. The open PR is #2 (`gnosis-osaka` -> `master`).

Gnosis specs are documented at https://github.com/gnosischain/specs (execution layer specs in `execution/` directory). The spec approach is delta-based: only differences from Ethereum are documented.

## Build and Development

Requires: Python 3.11+, `uv` (>=0.7.0), `geth` in `$PATH`. PyPy 7.3.19+ needed for full CI.

If system Python is < 3.11, install via `uv python install 3.11` and prefix tox commands with `UV_PYTHON_PREFERENCE=managed UV_PYTHON=3.11`.

```bash
# Clone with submodules (required for shared test fixtures)
git clone --recursive <repo-url>
# Or fetch submodules after clone
git submodule update --init --recursive
```

### Common Commands

```bash
# Run all tox environments (full CI suite)
uvx --with=tox-uv tox

# Run all checks in parallel
uvx --with=tox-uv tox run-parallel

# Static analysis only (codespell, ruff, mypy, ethereum-spec-lint, actionlint)
uvx --with=tox-uv tox -e static

# Fill tests (main test suite, Paris through Osaka)
uvx --with=tox-uv tox -e py3

# Run a specific test with pytest
uv run pytest tests/path/to/test.py::test_name -n auto --maxprocesses 6

# Run a single state test with EVM trace (useful for debugging)
uv run pytest 'tests/json_infra/test_state_tests.py::test_state_tests_frontier[stAttackTest - ContractCreationSpam - 0]' --evm_trace

# Lint and format
uv run ruff check              # check for issues
uv run ruff check --fix        # auto-fix fixable issues
uv run ruff format             # format code
uv run mypy                    # type checking

# Build spec documentation
uvx --with=tox-uv tox -e spec-docs

# Serve docs locally (localhost:8000)
uv run mkdocs serve

# Install pre-commit hooks
uvx pre-commit install
```

### CI Workflows (`.github/workflows/`)

**Core test pipeline** (`test.yaml`): Runs on PRs. Jobs: `static`, `py3` (fill Paris->Osaka), `pypy3`, `tests_pytest_py3`, `tests_pytest_pypy3`. Setup action (`.github/actions/setup-env/`) installs Rust, build-essential, tox, and downloads geth.

**Hive integration** (`hive-consume.yaml`): Runs on PRs touching hive paths or `forks/**` pushes. Tests generated fixtures against `go-ethereum-gnosis` via Hive (Docker-based client testing). Has 4 modes: Engine, RLP, Sync (simulator), Dev Mode (live Engine API). Uses `gnosischain/hive` repo (branch `sync-eest`) and `gnosis.yaml` client config.

**Manual hive workflows**: `eest_hive_gnosis.yaml` (single client, workflow_dispatch) and `eest_hive_gnosis_multi_client.yaml` (matrix of reth/geth/nethermind/erigon gnosis clients).

## Architecture

### Fork Structure (`src/ethereum/forks/`)

The core of the codebase. Each Ethereum hard fork has its own package under `src/ethereum/forks/` (frontier, homestead, ..., paris, shanghai, cancun, prague, osaka, amsterdam). Forks are ordered chronologically and each builds incrementally on the previous one — only files that change between forks are present.

Each fork package follows a consistent internal structure:
- `__init__.py` — `FORK_CRITERIA` (activation by block number or timestamp)
- `fork.py` — Block validation, transaction processing, state transition logic
- `blocks.py` — Block, Header, Receipt dataclasses
- `transactions.py` — Transaction types and encoding/decoding
- `state.py` — State management and account operations
- `trie.py` — Merkle Patricia trie implementation
- `fork_types.py` — Address, Account, and other fork-specific types
- `vm/` — EVM implementation
  - `interpreter.py` — EVM execution loop
  - `instructions/` — Opcodes by category (arithmetic, bitwise, memory, storage, stack, system)
  - `precompiled_contracts/` — Precompile implementations

### Gnosis-Specific Modifications

Gnosis changes are documented in `fork.py` docstrings (search for "Gnosis diff"). All forks Paris through Osaka are fully implemented.

**Per-fork Gnosis features:**

| Feature | Paris | Shanghai | Cancun | Prague | Osaka |
|---|---|---|---|---|---|
| Base fee collection to `FEE_COLLECTOR_ADDRESS` | Yes | Yes | Yes | Yes | Yes |
| Block rewards system call (`BLOCK_REWARDS_CONTRACT_ADDRESS`) | Yes | Yes | Yes | Yes | Yes |
| Withdrawals via system call to `DEPOSIT_CONTRACT_ADDRESS` | N/A | Yes | Yes | Yes | Yes |
| Blob fee collection to `BLOB_FEE_COLLECTOR` | N/A | N/A | N/A | Yes | Yes |

**Key constants** (consistent across forks):
```
SYSTEM_ADDRESS                  = 0xfffffffffffffffffffffffffffffffffffffffe
SYSTEM_TRANSACTION_GAS          = 30_000_000
BLOCK_REWARDS_CONTRACT_ADDRESS  = 0x2000000000000000000000000000000000000001
DEPOSIT_CONTRACT_ADDRESS        = 0xbabe2bed00000000000000000000000000000003
FEE_COLLECTOR_ADDRESS           = 0x1559000000000000000000000000000000000000
BLOB_FEE_COLLECTOR              = 0x1559000000000000000000000000000000000000
MAX_FAILED_WITHDRAWALS_TO_PROCESS = 4
```

**Gnosis-specific limits** (Osaka): `BLOB_COUNT_LIMIT = 2`, `MAX_BLOB_GAS_PER_BLOCK = 262144`.

**System transaction pattern**: `process_block_rewards()` calls reward contract with selector `f91c2898`, decodes `(address[], uint256[])` response. `process_withdrawals()` calls deposit contract with selector `79d0c0bc` and ABI-encoded withdrawal data.

**Spec references**: See `gnosischain/specs` repo — `execution/posdao-post-merge.md` (block rewards), `execution/withdrawals.md` (withdrawal system calls).

### Other Source Packages

- `src/ethereum_spec_tools/` — CLI tools: linter (`lint/`), sync tool, new fork scaffolding (`new_fork/`), EVM tools (`evm_tools/` — t8n transition tool, b11r, state tests)
- `src/ethereum_optimized/` — Performance-optimized alternative implementations
- `src/ethereum/crypto/` — Cryptographic primitives (keccak256, ECDSA, BLS, KZG)
- `src/ethereum/utils/` — Shared utilities (hex, numeric, byte operations)
- `packages/testing/` — Separate workspace package (`ethereum-execution-testing`) for test generation framework

### Gnosis-Specific Tool Modifications

- `src/ethereum_spec_tools/evm_tools/t8n/__init__.py` — Calls `process_block_rewards()` if fork supports it; manually builds withdrawals trie and calls `process_withdrawals()` for system calls
- `src/ethereum_spec_tools/evm_tools/loaders/fork_loader.py` — Added properties: `process_block_rewards()`, `has_process_block_rewards`, `SYSTEM_ADDRESS`
- `src/ethereum_spec_tools/evm_tools/loaders/fixture_loader.py` — Allows `SYSTEM_ADDRESS` as empty account in PoS forks

### Type System

Uses `ethereum-types` package for domain types: `U256`, `Uint`, `Bytes`, `Address`, etc. Full type annotations throughout; mypy runs in strict mode.

## Code Conventions

- **Line length**: 79 characters (enforced by ruff)
- **Max cyclomatic complexity**: 7
- **Imports**: explicit only (no star imports), relative within packages
- **Docstrings**: Google-style, imperative mood ("Return" not "Returns")
- **Naming**: Avoid EIP numbers in identifiers; use descriptive English words
- **Cross-fork changes**: Keep differences between forks minimal for clean diffs. When modifying multiple forks, start with one fork, get feedback, then propagate
- **Patch tool**: Use `python src/ethereum_spec_tools/patch_tool.py <source_fork> <target_fork1> <target_fork2>` to propagate unstaged changes across forks
- **Custom dictionary**: `whitelist.txt` for codespell exceptions

## Current Status (as of 2026-02-03)

**PR #2** (`gnosis-osaka` -> `master`): "Implement Gnosis spec post-shangai on forks/osaka"

- `static`: PASS (all lint/type checks)
- `py3`: PASS (50,738 tests, Paris->Osaka)
- `tests_pytest_py3` / `tests_pytest_pypy3`: PASS
- `pypy3`: FAIL — exit code 143 (killed by CI, timeout/OOM, not a test failure)
- Hive Engine/RLP/Sync: FAIL — Docker cache miss (ephemeral runners can't reliably share week-based cache keys)
- Hive Dev Mode: FAIL — merkle root mismatch because it uses **upstream Ethereum fixtures** (`FIXTURES_URL` points to `ethereum/execution-spec-tests`) against a Gnosis-configured client

See `plan.md` for pending tasks.
