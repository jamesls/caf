import os
from pathlib import Path

from caf.generator import FileGenerator


def generated_files(rootdir: Path) -> list[Path]:
    return [
        Path(root, filename)
        for root, _, filenames in os.walk(rootdir)
        if '.metadata' not in root
        for filename in filenames
    ]


def test_filegenerator_constructs_with_none_limits(tmp_path: Path) -> None:
    FileGenerator(str(tmp_path), None, None, lambda: 1)


def test_generate_files_creates_metadata_directory(tmp_path: Path) -> None:
    gen = FileGenerator(str(tmp_path), 1, float('inf'), lambda: 100)
    gen.generate_files()

    assert (tmp_path / '.metadata' / 'roots').exists()
    assert (tmp_path / '.metadata' / 'all').exists()


def test_generate_files_respects_max_files_zero(tmp_path: Path) -> None:
    generator = FileGenerator(
        str(tmp_path),
        max_files=0,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 1024,
    )
    generator.generate_files()

    assert generated_files(tmp_path) == []


def test_generate_files_respects_disk_usage_constraint(
    tmp_path: Path,
) -> None:
    target_size = 3 * 1024  # 3KB total
    generator = FileGenerator(
        str(tmp_path),
        max_files=float('inf'),
        max_disk_usage=target_size,
        file_size_chooser=lambda: 1024,
    )
    generator.generate_files()

    total_size = sum(path.stat().st_size for path in generated_files(tmp_path))

    assert total_size <= target_size


def test_generate_files_creates_large_files(tmp_path: Path) -> None:
    generator = FileGenerator(
        str(tmp_path),
        max_files=1,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 512 * 1024,  # 512KB
    )
    generator.generate_files()

    files = generated_files(tmp_path)

    assert len(files) == 1
    assert files[0].stat().st_size == 512 * 1024


def test_generate_files_creates_minimal_size_files(tmp_path: Path) -> None:
    generator = FileGenerator(
        str(tmp_path),
        max_files=1,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 60,  # Header size
    )
    generator.generate_files()

    files = generated_files(tmp_path)

    assert len(files) == 1
    assert files[0].stat().st_size == 60


def test_generate_files_uses_three_level_directory_layout(
    tmp_path: Path,
) -> None:
    generator = FileGenerator(
        str(tmp_path),
        max_files=1,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 1024,
    )
    generator.generate_files()

    files = generated_files(tmp_path)

    assert len(files) == 1
    parts = files[0].relative_to(tmp_path).parts
    assert len(parts) == 4
    for shard in parts[:3]:
        assert len(shard) == 2
        assert all(c in '0123456789abcdef' for c in shard)
    basename = parts[3]
    assert len(basename) == 34
    assert all(c in '0123456789abcdef' for c in basename)
