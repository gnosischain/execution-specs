# Plan: Gnosis Execution Specs — Pending Tasks

## Context

Gnosis fork of Ethereum EELS. Branch structure: `forks/osaka` (shipped), `forks/amsterdam` (active development), `mainnet` (production). Upstream is merged periodically into `forks/<name>` branches.

## Pending Tasks

### 1. Extend Hive consume to multi-client

**Status**: Single-client consume (nethermind-gnosis) implemented in PR [#12](https://github.com/gnosischain/execution-specs/pull/12). Next step is extending to all 4 Gnosis clients (reth, geth, nethermind, erigon) — either as a matrix in `hive-consume.yaml` or keeping the multi-client variant as a separate manual workflow.

### 2. Optimize fill scope for PR vs release

Currently `hive-consume.yaml` fills all forks on every PR. Once stabilized, switch to latest-fork-only for PRs and full fill on release or scheduled runs.

1. Add a `fill` job that generates Gnosis fixtures using the EELS spec (same as `eest_hive_gnosis.yaml` line 72-73)
2. Upload the generated fixtures as an artifact
3. In the consume jobs (Engine/RLP/Sync/Dev Mode), download those fixtures instead of `FIXTURES_URL`
4. Remove or replace the `FIXTURES_URL` env var pointing at `ethereum/execution-spec-tests`

**Files to modify**:

- `.github/workflows/hive-consume.yaml` — add fill job, wire artifacts, remove `FIXTURES_URL`

**Alternative**: Merge `eest_hive_gnosis.yaml` logic into `hive-consume.yaml` and trigger it on PRs. The multi-client variant could remain manual.

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
- [x] Branch structure: `forks/osaka`, `forks/amsterdam`, `mainnet` (upstream merge strategy)
- [x] Hive consume fix: fill+consume with nethermind-gnosis — PR [#12](https://github.com/gnosischain/execution-specs/pull/12)
