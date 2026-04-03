# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Gnosis chain fork** of the Ethereum Execution Layer Specifications (EELS) — a Python reference implementation of Ethereum's execution client. It prioritizes readability and correctness over performance. See [`GNOSIS.md`](GNOSIS.md) for the full delta from upstream Ethereum, system transaction rules, and links to the authoritative specs.

The `master` branch is the main branch. The `forks/amsterdam` branch tracks upstream through Amsterdam.

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

There are two phases in the test pipeline: **fill** (generate fixtures from the EELS spec — proves spec is internally consistent) and **consume** (feed fixtures to a real client via Hive — proves client compatibility). Currently only fill runs automatically on PRs; consume has no working automated PR gate.

**Core test pipeline** (`test.yaml`): Runs on PRs. Fill only — no consume. Jobs: `static`, `py3` (fill Paris->Osaka), `pypy3`, `tests_pytest_py3`, `tests_pytest_pypy3`. Setup action (`.github/actions/setup-env/`) installs Rust, build-essential, tox, and downloads geth.

**Hive integration** (`hive-consume.yaml`): Runs on PRs touching hive paths or `forks/**` pushes. Intended to consume fixtures against `go-ethereum-gnosis` via Hive (4 modes: Engine, RLP, Sync, Dev Mode). Currently broken: it downloads upstream Ethereum fixtures (`FIXTURES_URL`) instead of generating Gnosis fixtures via fill, so the state roots never match. Uses `gnosischain/hive` repo (branch `master`) and `latest.yaml` client config.

**Manual hive workflows** (workflow_dispatch only, not automated on PRs):

- `eest_hive_gnosis.yaml` — fill then consume against a single Gnosis client. This is the correct pattern.
- `eest_hive_gnosis_multi_client.yaml` — fill once, then consume against 4 Gnosis clients (reth/geth/nethermind/erigon).

**All workflow files:**

| File                               | Trigger                           | What it does                                                                       |
|------------------------------------|-----------------------------------|------------------------------------------------------------------------------------|
| test.yaml                          | PR, push to master                | Core pipeline: static checks, py3 fill, pypy3 fill, framework unit tests           |
| test-docs.yaml                     | PR, push                          | mkdocs build, markdownlint, changelog validation                                   |
| hive-consume.yaml                  | PR (hive paths), push to forks/** | Hive integration: Engine/RLP/Sync simulators + Dev Mode against go-ethereum-gnosis  |
| benchmark.yaml                     | push to forks/**                  | Gas benchmarks, fixed opcode benchmarks                                            |
| eest_hive_gnosis.yaml              | manual                            | Fill + consume against a single Gnosis client                                      |
| eest_hive_gnosis_multi_client.yaml | manual                            | Fill once, then consume against 4 Gnosis clients (reth/geth/nethermind/erigon)     |
| eest_hive_matrix.yaml              | manual                            | Upstream hive matrix testing                                                       |
| run_eest_remote.yaml               | manual                            | Run EEST tests on a remote machine                                                 |
| release_fixture_full.yaml          | manual                            | Generate and publish full fixture releases                                         |
| release_fixture_feature.yaml       | manual                            | Generate fixtures for a feature branch                                             |
| gh-pages.yaml                      | push to master                    | Deploy spec docs to GitHub Pages                                                   |
| eip-rebase.yaml                    | manual                            | Rebase EIP feature branches                                                        |
| update-devnet-branch.yaml          | manual                            | Update devnet branches                                                             |

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

**Read [`GNOSIS.md`](GNOSIS.md) first.** It documents every delta from upstream Ethereum: system transaction rules, feature matrix by fork, constants, and links to the authoritative specs. When auditing or modifying Gnosis-specific code, cross-reference the implementation in `fork.py` against the spec URLs in that file.

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
