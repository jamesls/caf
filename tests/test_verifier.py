import os
import hashlib

from caf.generator import FileGenerator
from caf.verifier import (
    FileVerifier,
    RepeatedByte,
    Truncated,
    ZeroFilled,
)


def test_verify_files_detects_invalid_checksum(tmp_path):
    gen = FileGenerator(str(tmp_path), 1, float('inf'), lambda: 1024)
    gen.generate_files()

    for root, _, files in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        if files:
            file_path = os.path.join(root, files[0])
            with open(file_path, 'r+b') as f:
                f.seek(100)
                f.write(b'corrupt_data' * 20)
            break

    verifier = FileVerifier(str(tmp_path))
    result = verifier.verify_files()
    assert not result.success


def test_verify_files_detects_corrupted_root_metadata(tmp_path, capsys):
    gen = FileGenerator(str(tmp_path), 1, float('inf'), lambda: 100)
    gen.generate_files()

    meta = tmp_path / '.metadata'
    with open(meta / 'all', 'wb') as f:
        f.write(b'bad')

    verifier = FileVerifier(str(tmp_path))
    result = verifier.verify_files()
    assert not result.success
    assert "Root hash is not valid" in capsys.readouterr().err


def test_verify_files_detects_invalid_file_content(tmp_path, capsys):
    hex_hash = 'aabbcc' + ('0' * 34)
    d = tmp_path / 'aa' / 'bb' / 'cc'
    d.mkdir(parents=True)
    path = d / hex_hash[6:]

    path.write_bytes(b'\x00' * 60 + b'invalid data')

    meta_dir = tmp_path / '.metadata' / 'roots'
    meta_dir.mkdir(parents=True)
    (meta_dir / 'dummy').touch()
    (tmp_path / '.metadata' / 'all').write_text('dummy')

    verifier = FileVerifier(str(tmp_path))
    result = verifier.verify_files()

    captured = capsys.readouterr()
    assert not result.success
    assert (
        "Invalid checksum" in captured.err
        or "Header corrupted" in captured.err
    )


def test_verify_files_fails_for_four_level_layout(tmp_path, capsys):
    generator = FileGenerator(
        str(tmp_path),
        max_files=float('inf'),
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 1024,
    )

    temp, file_hash = generator.generate_single_file_enhanced(
        generator.ROOT_HASH,
        file_size=1024,
        buffer_size=generator.BUFFER_WRITE_SIZE,
        temp_dir=str(tmp_path),
    )
    hex_hash = file_hash.hex()
    path = (
        tmp_path
        / hex_hash[:2]
        / hex_hash[2:4]
        / hex_hash[4:6]
        / hex_hash[6:8]
        / hex_hash[8:]
    )
    path.parent.mkdir(parents=True)
    os.rename(temp, path)

    roots_dir = tmp_path / '.metadata' / 'roots'
    roots_dir.mkdir(parents=True)
    (roots_dir / hex_hash).touch()
    roots_hash = hashlib.blake2b(digest_size=20)
    for filename in sorted(os.listdir(roots_dir)):
        roots_hash.update(filename.encode('ascii'))
    (tmp_path / '.metadata' / 'all').write_bytes(
        roots_hash.hexdigest().encode('ascii')
    )

    verifier = FileVerifier(str(tmp_path))
    result = verifier.verify_files()
    assert not result.success
    assert 'Invalid CAF path layout' in capsys.readouterr().err


def test_verify_files_succeeds_for_clean_files(tmp_path):
    generator = FileGenerator(
        str(tmp_path),
        max_files=3,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 1024,
    )
    generator.generate_files()

    verifier = FileVerifier(str(tmp_path))
    result = verifier.verify_files()
    assert result.success


def test_verify_files_detects_zeroed_content(tmp_path, capsys):
    generator = FileGenerator(
        str(tmp_path),
        max_files=2,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 2048,
    )
    generator.generate_files()

    for root, _, files in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        if files:
            file_path = os.path.join(root, files[0])
            with open(file_path, 'r+b') as f:
                f.seek(100)
                f.write(b'\x00' * 500)
            break

    verifier = FileVerifier(str(tmp_path))
    result = verifier.verify_files()
    assert not result.success

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert 'CONTENT CORRUPTED' in output


def test_verify_files_reports_truncated_file_as_corruption(tmp_path, capsys):
    generator = FileGenerator(
        str(tmp_path),
        max_files=1,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 4096,
    )
    generator.generate_files()

    for root, _, files in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        if files:
            file_path = os.path.join(root, files[0])
            original_size = os.path.getsize(file_path)
            with open(file_path, 'r+b') as f:
                f.truncate(original_size - 512)
            break

    verifier = FileVerifier(str(tmp_path), analysis_chunk_size=256)
    result = verifier.verify_files()
    assert not result.success

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert 'CONTENT CORRUPTED' in output
    assert 'PATH MISMATCH' not in output
    assert 'truncated' in output

    assert len(result.reports) == 1
    regions = result.reports[0].corrupted_regions
    truncated_regions = [
        r for r in regions if isinstance(r.pattern, Truncated)
    ]
    assert len(truncated_regions) >= 1
    assert truncated_regions[0].pattern.missing_bytes == 512


def test_verify_files_with_different_chunk_sizes(tmp_path):
    generator = FileGenerator(
        str(tmp_path),
        max_files=1,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 4096,
    )
    generator.generate_files()

    chunk_sizes = [256, 1024, 2048]

    for chunk_size in chunk_sizes:
        verifier = FileVerifier(str(tmp_path), analysis_chunk_size=chunk_size)
        result = verifier.verify_files()
        assert result.success


def test_verify_files_detects_broken_file_chain(tmp_path):
    generator = FileGenerator(
        str(tmp_path),
        max_files=5,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 1024,
    )
    generator.generate_files()

    verifier = FileVerifier(str(tmp_path))
    result = verifier.verify_files()
    assert result.success

    files = []
    for root, _, filenames in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        for filename in filenames:
            files.append(os.path.join(root, filename))

    if len(files) > 1:
        for file_path in files:
            with open(file_path, 'rb') as f:
                parent_hash = f.read(20)

            if parent_hash != b'\x00' * 20:
                os.remove(file_path)
                break

        verifier = FileVerifier(str(tmp_path))
        result = verifier.verify_files()
        assert not result.success


def test_verify_files_detects_corrupted_metadata(tmp_path, capsys):
    generator = FileGenerator(
        str(tmp_path),
        max_files=2,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 1024,
    )
    generator.generate_files()

    metadata_file = tmp_path / '.metadata' / 'all'
    with open(metadata_file, 'wb') as f:
        f.write(b'corrupted_metadata')

    verifier = FileVerifier(str(tmp_path))
    result = verifier.verify_files()
    assert not result.success

    captured = capsys.readouterr()
    assert 'Root hash is not valid' in captured.err


def test_verify_files_reports_zero_filled_corruption(tmp_path, capsys):
    generator = FileGenerator(
        str(tmp_path),
        max_files=1,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 4096,
    )
    generator.generate_files()

    for root, _, files in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        if files:
            file_path = os.path.join(root, files[0])
            with open(file_path, 'r+b') as f:
                f.seek(1000)
                f.write(b'\x00' * 1024)
            break

    verifier = FileVerifier(str(tmp_path), analysis_chunk_size=256)
    result = verifier.verify_files()
    assert not result.success

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert 'zero-filled' in output
    assert 'All bytes are 0x00' in output

    assert len(result.reports) == 1
    regions = result.reports[0].corrupted_regions
    zero_filled = [r for r in regions if isinstance(r.pattern, ZeroFilled)]
    assert len(zero_filled) >= 1


def test_verify_files_reports_repeated_byte_corruption(tmp_path, capsys):
    generator = FileGenerator(
        str(tmp_path),
        max_files=1,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 4096,
    )
    generator.generate_files()

    for root, _, files in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        if files:
            file_path = os.path.join(root, files[0])
            with open(file_path, 'r+b') as f:
                f.seek(1500)
                f.write(b'\xff' * 1024)
            break

    verifier = FileVerifier(str(tmp_path), analysis_chunk_size=512)
    result = verifier.verify_files()
    assert not result.success

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert 'repeated-byte' in output
    assert '0xff' in output

    assert len(result.reports) == 1
    regions = result.reports[0].corrupted_regions
    repeated = [r for r in regions if isinstance(r.pattern, RepeatedByte)]
    assert len(repeated) >= 1
    assert repeated[0].pattern.byte_value == 0xFF


def test_verify_files_generates_corruption_visualization(tmp_path, capsys):
    generator = FileGenerator(
        str(tmp_path),
        max_files=1,
        max_disk_usage=float('inf'),
        file_size_chooser=lambda: 8192,
    )
    generator.generate_files()

    for root, _, files in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        if files:
            file_path = os.path.join(root, files[0])
            with open(file_path, 'r+b') as f:
                f.seek(500)
                f.write(b'\x00' * 500)
                f.seek(7000)
                f.write(b'\xff' * 500)
            break

    verifier = FileVerifier(str(tmp_path), analysis_chunk_size=256)
    result = verifier.verify_files()
    assert not result.success

    captured = capsys.readouterr()
    output = captured.out + captured.err

    assert 'Visualization:' in output
    assert '━' in output or '█' in output  # Unicode bar characters
    assert '0%' in output and '100%' in output
