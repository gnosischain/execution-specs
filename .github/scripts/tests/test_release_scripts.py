"""
Test the CI release helper scripts.

Each test invokes the script via ``uv run`` to validate the actual CLI
interface, matching how GitHub Actions calls them.
"""

import json
import subprocess
import tarfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent
REPO_ROOT = SCRIPTS_DIR.parent.parent

BUILD_MATRIX_SCRIPT = SCRIPTS_DIR / "generate_build_matrix.py"
TARBALL_SCRIPT = SCRIPTS_DIR / "create_release_tarball.py"


def run_script(script: Path, *args: str) -> subprocess.CompletedProcess:
    """Run a uv inline-deps script and return the result."""
    return subprocess.run(
        ["uv", "run", "-q", str(script), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def parse_matrix_output(
    stdout: str,
) -> tuple[list[dict], list[dict]]:
    """Parse build_matrix and combine_matrix from script stdout."""
    lines = {
        k: v
        for line in stdout.strip().splitlines()
        if "=" in line
        for k, v in [line.split("=", 1)]
    }
    return (
        json.loads(lines["build_matrix"]),
        json.loads(lines["combine_matrix"]),
    )


class TestGenerateBuildMatrix:
    """Test generate_build_matrix.py."""

    def test_all_mode_includes_non_feature_only(self):
        """Verify --all excludes feature_only entries."""
        result = run_script(BUILD_MATRIX_SCRIPT, "--all")
        assert result.returncode == 0
        matrix, _ = parse_matrix_output(result.stdout)
        features = {e["feature"] for e in matrix}
        assert "stable" in features
        assert "benchmark" in features
        assert "benchmark_fast" not in features
        assert "bal" not in features

    def test_split_feature_produces_entries_per_range(self):
        """Verify a split feature expands into one entry per range."""
        result = run_script(BUILD_MATRIX_SCRIPT, "stable")
        assert result.returncode == 0
        matrix, combine = parse_matrix_output(result.stdout)
        assert len(matrix) > 1
        combine_features = [c["feature"] for c in combine]
        assert "stable" in combine_features
        labels = [e["label"] for e in matrix]
        assert all(lbl != "" for lbl in labels)
        assert all(e["from_fork"] != "" for e in matrix)
        assert all(e["until_fork"] != "" for e in matrix)

    def test_unsplit_feature_produces_single_entry(self):
        """Verify a feature without fork-ranges produces one entry."""
        result = run_script(BUILD_MATRIX_SCRIPT, "benchmark")
        assert result.returncode == 0
        matrix, combine = parse_matrix_output(result.stdout)
        assert len(matrix) == 1
        assert combine == []
        assert matrix[0]["label"] == ""
        assert matrix[0]["from_fork"] == ""
        assert matrix[0]["until_fork"] == ""

    def test_feature_only_can_be_requested_explicitly(self):
        """Verify feature_only entries work when named directly."""
        result = run_script(BUILD_MATRIX_SCRIPT, "bal")
        assert result.returncode == 0
        matrix, combine = parse_matrix_output(result.stdout)
        assert len(matrix) == 1
        assert matrix[0]["feature"] == "bal"
        assert combine == []

    def test_multiple_features(self):
        """Verify passing multiple feature names."""
        result = run_script(BUILD_MATRIX_SCRIPT, "stable", "benchmark")
        assert result.returncode == 0
        matrix, combine = parse_matrix_output(result.stdout)
        features = [e["feature"] for e in matrix]
        assert "stable" in features
        assert "benchmark" in features
        combine_features = [c["feature"] for c in combine]
        assert "stable" in combine_features
        assert "benchmark" not in combine_features

    def test_fork_ranges_deduplicated_across_features(self):
        """Verify shared fork ranges are built once, not per feature."""
        result = run_script(BUILD_MATRIX_SCRIPT, "stable", "develop")
        assert result.returncode == 0
        matrix, combine = parse_matrix_output(result.stdout)

        # Stable and develop share pre-cancun..osaka; only bpo and
        # amsterdam are unique to develop.
        labels = [e["label"] for e in matrix]
        assert labels.count("pre-cancun") == 1
        assert labels.count("cancun") == 1
        assert labels.count("prague") == 1
        assert labels.count("osaka") == 1

        # Combine matrix maps each feature to its applicable labels.
        by_feature = {c["feature"]: c["labels"] for c in combine}
        assert "pre-cancun" in by_feature["stable"]
        assert "osaka" in by_feature["stable"]
        assert "bpo" not in by_feature["stable"]
        assert "bpo" in by_feature["develop"]
        assert "amsterdam" in by_feature["develop"]

    def test_unknown_feature_fails(self):
        """Verify error exit for unknown feature name."""
        result = run_script(BUILD_MATRIX_SCRIPT, "nonexistent")
        assert result.returncode == 1
        assert "not found" in result.stderr

    def test_no_args_fails(self):
        """Verify error exit when no arguments provided."""
        result = run_script(BUILD_MATRIX_SCRIPT)
        assert result.returncode == 1
        assert "Usage" in result.stderr

    def test_output_is_valid_github_actions_format(self):
        """Verify output lines are key=value for GITHUB_OUTPUT."""
        result = run_script(BUILD_MATRIX_SCRIPT, "--all")
        assert result.returncode == 0
        lines = result.stdout.strip().splitlines()
        assert len(lines) == 2
        assert lines[0].startswith("build_matrix=")
        assert lines[1].startswith("combine_matrix=")


class TestCreateReleaseTarball:
    """Test create_release_tarball.py."""

    def test_tarball_structure(self, tmp_path):
        """Verify tarball has fixtures/ prefix and correct contents."""
        src = tmp_path / "fixtures"
        (src / "blockchain_tests" / "for_cancun").mkdir(parents=True)
        (src / "blockchain_tests_engine_x" / "pre_alloc").mkdir(parents=True)
        (src / ".meta").mkdir()

        (src / "blockchain_tests" / "for_cancun" / "t.json").write_text("{}")
        pre_alloc = src / "blockchain_tests_engine_x" / "pre_alloc"
        (pre_alloc / "g.json").write_text("{}")
        (src / ".meta" / "fixtures.ini").write_text("[meta]")

        out = tmp_path / "output.tar.gz"
        result = run_script(TARBALL_SCRIPT, str(src), str(out))
        assert result.returncode == 0
        assert out.exists()

        with tarfile.open(out, "r:gz") as tar:
            names = sorted(tar.getnames())

        assert all(n.startswith("fixtures/") for n in names)
        assert "fixtures/blockchain_tests/for_cancun/t.json" in names
        assert "fixtures/blockchain_tests_engine_x/pre_alloc/g.json" in names
        assert "fixtures/.meta/fixtures.ini" in names

    def test_excludes_non_fixture_files(self, tmp_path):
        """Verify .log, .html, etc. are excluded from tarball."""
        src = tmp_path / "fixtures"
        src.mkdir()
        (src / "test.json").write_text("{}")
        (src / "debug.log").write_text("log")
        (src / "report.html").write_text("<html>")
        (src / "data.csv").write_text("a,b")

        out = tmp_path / "output.tar.gz"
        result = run_script(TARBALL_SCRIPT, str(src), str(out))
        assert result.returncode == 0

        with tarfile.open(out, "r:gz") as tar:
            names = tar.getnames()

        assert "fixtures/test.json" in names
        assert len(names) == 1

    def test_nonexistent_dir_fails(self, tmp_path):
        """Verify error for non-existent source directory."""
        result = run_script(
            TARBALL_SCRIPT,
            str(tmp_path / "nope"),
            str(tmp_path / "out.tar.gz"),
        )
        assert result.returncode == 1
        assert "not a directory" in result.stderr

    def test_no_args_fails(self):
        """Verify error when no arguments provided."""
        result = run_script(TARBALL_SCRIPT)
        assert result.returncode == 1
        assert "Usage" in result.stderr
