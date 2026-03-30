# Devnet Branch Workflow

## Overview

EIP branches (`eips/amsterdam/eip-XXXX`) are developed independently off `forks/amsterdam`. Devnet branches (`devnets/bal/N`) combine multiple EIPs into a single integration branch for testing.

**All updates use merge, never rebase.** Merge resolves conflicts once, doesn't rewrite history, and doesn't require force pushes that break collaborators.

## Architecture

```
forks/amsterdam  (base fork branch, receives ongoing fixes)
├── eips/amsterdam/eip-7708   (ETH transfer logs)
├── eips/amsterdam/eip-7778   (Block gas without refunds)
├── eips/amsterdam/eip-7843   (SLOTNUM opcode)
├── eips/amsterdam/eip-7928   (Block-level access lists)
├── eips/amsterdam/eip-7954   (Increase max contract size)
├── eips/amsterdam/eip-8024   (Backward compat SWAPN/DUPN/EXCHANGE)
└── eips/amsterdam/eip-8037   (State creation gas cost increase)

devnets/bal/3  (all of the above merged together)
```

## Building a Devnet Branch

Start from `forks/amsterdam` and merge each EIP branch in sequence:

```bash
git checkout -b devnets/bal/3 forks/amsterdam
git merge eips/amsterdam/eip-7708
git merge eips/amsterdam/eip-7778
git merge eips/amsterdam/eip-7843
git merge eips/amsterdam/eip-7928
git merge eips/amsterdam/eip-7954
git merge eips/amsterdam/eip-8024
git merge eips/amsterdam/eip-8037
```

Resolve any EIP-vs-EIP conflicts as they arise.

## Updating an EIP Branch

When an EIP branch needs to catch up with `forks/amsterdam`:

```bash
git checkout eips/amsterdam/eip-XXXX
git merge forks/amsterdam
# resolve conflicts once
```

### Verification

After merging, verify the EIP spec is correct:

```bash
# Fill tests on upstream's version (before)
git checkout upstream/eips/amsterdam/eip-XXXX
uv run fill tests/amsterdam/eipXXXX_*/ --output=/tmp/XXXX-upstream --until=Amsterdam --clean

# Fill tests on local merge (after)
git checkout eips/amsterdam/eip-XXXX
uv run fill tests/amsterdam/eipXXXX_*/ --output=/tmp/XXXX-local --until=Amsterdam --clean

# Compare — no output means identical fixtures
uv run hasher compare /tmp/XXXX-upstream /tmp/XXXX-local
```

If upstream doesn't have an updated EIP branch, diff against the upstream version to check conflict resolutions:

```bash
git diff upstream/eips/amsterdam/eip-XXXX -- src/ethereum/forks/amsterdam/
```

## Keeping the Devnet Branch Current

Two maintenance paths:

### Incremental (normal)

When `forks/amsterdam` gets updates:
```bash
git checkout devnets/bal/3
git merge forks/amsterdam
```

When an EIP branch gets new commits:
```bash
git checkout devnets/bal/3
git merge eips/amsterdam/eip-XXXX
```

### Rebuild (when the branch gets too messy)

Start fresh and re-merge everything:
```bash
git checkout -b devnets/bal/3 forks/amsterdam
git merge eips/amsterdam/eip-7708
git merge eips/amsterdam/eip-7778
# ... all EIPs
```

## Why Merge, Not Rebase

| | Merge | Rebase |
|---|---|---|
| Conflicts | Resolve once | Resolve per commit |
| Force push | No | Yes |
| Breaks collaborators | No | Yes |
| Speed | Faster | Slower |
| History | Merge commits | Linear |

Clean linear history doesn't matter for a disposable integration branch. Not breaking collaborators does.
