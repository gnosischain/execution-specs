# Plan: Gnosis Execution Specs — Pending Tasks

## Context

PR #2 (`gnosis-osaka` -> `master`) implements the Gnosis spec differences across Paris through Osaka forks. The core spec implementation and test fill suite pass (50,738 tests). The remaining work is CI/infrastructure fixes to get all PR checks green.

## Pending Tasks

### 1. Fix Hive Dev Mode — Merkle root mismatch (critical)

**Problem**: `hive-consume.yaml` Dev Mode job downloads **upstream Ethereum fixtures** from `ethereum/execution-spec-tests` and feeds them to `go-ethereum-gnosis`. The Gnosis client computes a different state root because Gnosis has additional state transitions (fee collection, block rewards, withdrawal system calls).

**File**: `.github/workflows/hive-consume.yaml` line 48:
```yaml
FIXTURES_URL: https://github.com/ethereum/execution-spec-tests/releases/download/v5.3.0/fixtures_develop.tar.gz
```

**Options**:
- **A**: Generate Gnosis-specific fixtures via a prior `fill` step (like `eest_hive_gnosis_multi_client.yaml` already does) and use those instead of upstream fixtures
- **B**: Publish Gnosis fixture releases and point `FIXTURES_URL` at them
- **C**: Disable the hive-consume workflow for now and rely on the manual hive workflows for integration testing

### 2. Fix Hive Engine/RLP/Sync — Docker cache issue

**Problem**: The `cache-docker-images` / `load-docker-images` actions use a week-number-based cache key designed for persistent self-hosted runners. On ephemeral `ubuntu-latest` runners, cache restore can miss.

**File**: `.github/actions/load-docker-images/action.yaml` — hard fails if cache not found.

**Options**:
- **A**: Pull Docker images directly in each job instead of relying on cache (simpler, slightly slower)
- **B**: Switch `load-docker-images` to pull images on cache miss instead of failing
- **C**: Use self-hosted runners (requires infra setup)

Note: Even if the cache issue is fixed, Engine/RLP/Sync will also hit the same fixtures mismatch problem as Dev Mode (task 1).

### 3. Fix pypy3 CI timeout

**Problem**: Exit code 143 (SIGTERM) — the PyPy fill run exceeds GitHub Actions resource limits.

**Options**:
- **A**: Reduce `--maxprocesses` for pypy3 to lower memory pressure (currently 7 in tox.ini)
- **B**: Add `PYPY_GC_MAX` / `PYPY_GC_MIN` env vars in CI (already present in test.yaml but may need tuning)
- **C**: Split pypy3 into multiple jobs by fork range
- **D**: Use a larger runner or self-hosted runner

### 4. Consider adding `gnosischain/specs` as a submodule

**Rationale**: The Gnosis specs repo documents the delta from Ethereum. Adding it as a submodule at e.g. `specs/gnosis/` would:
- Pin the spec version the implementation targets
- Allow agents and developers to grep specs locally
- Enable potential CI validation that `fork.py` docstrings stay in sync with specs

**Steps**:
- `git submodule add https://github.com/gnosischain/specs.git specs/gnosis`
- Update `fork.py` "Gnosis diff" docstrings with references like `(ref: specs/gnosis/execution/withdrawals.md)`
- Add a note in CONTRIBUTING.md or CLAUDE.md

### 5. Upstream rebase strategy

The `gnosis-osaka` branch is based on upstream `forks/osaka`. As upstream evolves (Amsterdam fork, etc.), the branch needs periodic rebases. Key files that will conflict:
- `fork.py` files (Gnosis modifications in Paris through Osaka)
- `tox.ini` (fork range, disabled environments)
- `.github/workflows/` (Gnosis-specific workflow changes)
- `src/ethereum_spec_tools/evm_tools/` (Gnosis tool modifications)

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
