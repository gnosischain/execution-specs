# Plan: Gnosis Execution Specs — Pending Tasks

## Context

PR #2 (`gnosis-osaka` -> `master`) implements the Gnosis spec differences across Paris through Osaka forks. The core spec implementation and test fill suite pass (50,738 tests). However, **no consume step has ever run successfully against a Gnosis client in CI** — the fill proves the spec is internally consistent, but client compatibility is unverified in automated CI.

## Pending Tasks

### 1. Add automated fill+consume to PR CI (critical)

**Problem**: `test.yaml` only runs fill (generates fixtures from EELS spec). There is no automated consume step on PRs that validates fixtures against a real Gnosis client. The `hive-consume.yaml` workflow was supposed to do this but it downloads upstream Ethereum fixtures instead of generating Gnosis ones, so it always fails.

**The correct pattern already exists** in `eest_hive_gnosis.yaml` (manual workflow): fill first, then consume. This needs to become an automated PR check.

**Proposed approach**: Rework `hive-consume.yaml` to:

1. Add a `fill` job that generates Gnosis fixtures using the EELS spec (same as `eest_hive_gnosis.yaml` line 72-73)
2. Upload the generated fixtures as an artifact
3. In the consume jobs (Engine/RLP/Sync/Dev Mode), download those fixtures instead of `FIXTURES_URL`
4. Remove or replace the `FIXTURES_URL` env var pointing at `ethereum/execution-spec-tests`

**Files to modify**:

- `.github/workflows/hive-consume.yaml` — add fill job, wire artifacts, remove `FIXTURES_URL`

**Alternative**: Merge `eest_hive_gnosis.yaml` logic into `hive-consume.yaml` and trigger it on PRs. The multi-client variant could remain manual.

### 2. Consider adding `gnosischain/specs` as a submodule

**Rationale**: The Gnosis specs repo documents the delta from Ethereum. Adding it as a submodule at e.g. `specs/gnosis/` would:

- Pin the spec version the implementation targets
- Allow agents and developers to grep specs locally
- Enable potential CI validation that `fork.py` docstrings stay in sync with specs

**Steps**:

- `git submodule add https://github.com/gnosischain/specs.git specs/gnosis`
- Update `fork.py` "Gnosis diff" docstrings with references like `(ref: specs/gnosis/execution/withdrawals.md)`

### 3. Upstream rebase strategy

The `gnosis-osaka` branch is based on upstream `forks/osaka`. As upstream evolves (Amsterdam fork, etc.), the branch needs periodic rebases. Key files that will conflict:

- `fork.py` files (Gnosis modifications in Paris through Osaka)
- `tox.ini` (fork range, disabled environments)
- `.github/workflows/` (Gnosis-specific workflow changes)
- `src/ethereum_spec_tools/evm_tools/` (Gnosis tool modifications)

### 6. Re-enable pypy3 fill in CI (`test.yaml`)

**Status**: Commented out with TODO. The pypy3 job exceeds GitHub Actions resource limits (exit 143 / SIGTERM).

**Options**:

- Reduce `--maxprocesses` (currently 7 in tox.ini) to lower memory pressure
- Tune `PYPY_GC_MAX` / `PYPY_GC_MIN` env vars
- Split into multiple jobs by fork range
- Use a larger runner

### 7. Re-enable Hive consume in CI (`hive-consume.yaml`)

**Status**: All jobs commented out with TODO. Two issues must be fixed:

1. **Wrong fixtures**: `FIXTURES_URL` points at upstream Ethereum fixtures. Need a fill job that generates Gnosis fixtures first (see `eest_hive_gnosis.yaml` for the correct pattern), upload as artifact, then consume those.
2. **Docker cache**: `load-docker-images` hard-fails on ephemeral `ubuntu-latest` runners when cache misses. Need fallback to `docker pull`.

## Completed

- [x] Gnosis spec implementation: base fee collection (Paris+), block rewards (Paris+), withdrawal system calls (Shanghai+), blob fee collection (Prague+)
- [x] All fork.py modifications across Paris, Shanghai, Cancun, Prague, Osaka
- [x] t8n tool modifications for Gnosis system calls
- [x] Fork loader / fixture loader Gnosis support
- [x] Gnosis-specific tests: fee collector chain split, withdrawal system call tests
- [x] Test adaptations: blob counts, gas limits, deposit contract, beacon root, EIP-7934
- [x] Static checks pass (ruff, mypy, codespell, ethereum-spec-lint, actionlint)
- [x] py3 fill suite passes (50,738 tests, Paris->Osaka)
- [x] CI workflow adaptation to Gnosis infrastructure (hive repo, client configs, Docker images)
- [x] CLAUDE.md created with full project documentation
