import os

from caf.generator import FileGenerator


def test_filegenerator_accepts_none_for_infinite_limits(tmp_path):
    gen = FileGenerator(str(tmp_path), None, None, lambda: 1)
    assert gen is not None


def test_generate_files_creates_metadata_directory(tmp_path):
    gen = FileGenerator(str(tmp_path), 1, float('inf'), lambda: 100)
    gen.generate_files()

    assert (tmp_path / '.metadata' / 'roots').exists()
    assert (tmp_path / '.metadata' / 'all').exists()


def test_generate_files_respects_max_files_zero(tmp_path):
    generator = FileGenerator(
        str(tmp_path),
        max_files=0,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 1024,
    )
    generator.generate_files()

    files = []
    for root, _, filenames in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        for filename in filenames:
            files.append(os.path.join(root, filename))

    assert len(files) == 0


def test_generate_files_respects_disk_usage_constraint(tmp_path):
    target_size = 3 * 1024  # 3KB total
    generator = FileGenerator(
        str(tmp_path),
        max_files=float('inf'),
        max_disk_usage=target_size,
        file_size_chooser=lambda: 1024,
    )
    generator.generate_files()

    total_size = 0
    for root, _, filenames in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        for filename in filenames:
            file_path = os.path.join(root, filename)
            total_size += os.path.getsize(file_path)

    assert total_size <= target_size


def test_generate_files_creates_large_files(tmp_path):
    generator = FileGenerator(
        str(tmp_path),
        max_files=1,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 512 * 1024,  # 512KB
    )
    generator.generate_files()

    files = []
    for root, _, filenames in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        for filename in filenames:
            files.append(os.path.join(root, filename))

    assert len(files) == 1
    assert os.path.getsize(files[0]) == 512 * 1024


def test_generate_files_creates_minimal_size_files(tmp_path):
    generator = FileGenerator(
        str(tmp_path),
        max_files=1,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 60,  # Header size
    )
    generator.generate_files()

    files = []
    for root, _, filenames in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        for filename in filenames:
            files.append(os.path.join(root, filename))

    assert len(files) == 1
    assert os.path.getsize(files[0]) >= 60


def test_generate_files_uses_three_level_directory_layout(tmp_path):
    generator = FileGenerator(
        str(tmp_path),
        max_files=1,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 1024,
    )
    generator.generate_files()

    files = []
    for root, _, filenames in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        for filename in filenames:
            files.append(os.path.join(root, filename))

    assert len(files) == 1
    rel = os.path.relpath(files[0], str(tmp_path))
    parts = rel.split(os.sep)
    assert len(parts) == 4
    for shard in parts[:3]:
        assert len(shard) == 2
        assert all(c in '0123456789abcdef' for c in shard)
    basename = parts[3]
    assert len(basename) == 34
    assert all(c in '0123456789abcdef' for c in basename)
