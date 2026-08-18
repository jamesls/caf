import hashlib
import os
import struct
from pathlib import Path

from click.testing import CliRunner

from caf.cli import main
from caf.constants import (
    BLAKE2B_DIGEST_SIZE,
    HEADER_SIZE,
    ROOT_PARENT_HASH,
)
from caf.content import ContentStream
from caf.paths import hash_to_path
from caf.verifier import FileVerifier


def craft_store_with_reserved_bytes(rootdir: str, reserved: bytes) -> str:
    file_length = 1024
    content_seed = hashlib.sha256(b'quirk-seed').digest()[:16]
    header = bytearray(HEADER_SIZE)
    header[0:20] = ROOT_PARENT_HASH
    header[20:36] = content_seed
    header[36:44] = struct.pack('>Q', file_length)
    header[44:52] = hashlib.sha3_256(header[:44]).digest()[:8]
    header[52:60] = reserved

    content = ContentStream(content_seed).read(file_length - HEADER_SIZE)
    file_bytes = bytes(header) + content
    digest = hashlib.blake2b(
        file_bytes, digest_size=BLAKE2B_DIGEST_SIZE
    ).hexdigest()

    path = hash_to_path(rootdir, digest)
    os.makedirs(os.path.dirname(path))
    with open(path, 'wb') as f:
        f.write(file_bytes)

    roots_dir = os.path.join(rootdir, '.metadata', 'roots')
    os.makedirs(roots_dir)
    with open(os.path.join(roots_dir, digest), 'w'):
        pass
    all_digest = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE)
    all_digest.update(digest.encode('ascii'))
    with open(os.path.join(rootdir, '.metadata', 'all'), 'wb') as f:
        f.write(all_digest.hexdigest().encode('ascii'))
    return path


def test_verify_accepts_nonzero_reserved_bytes(tmp_path: Path) -> None:
    craft_store_with_reserved_bytes(str(tmp_path), b'\xff' * 8)
    result = FileVerifier(str(tmp_path)).verify_files()
    assert result.success


def test_dev_show_rejects_nonzero_reserved_bytes(tmp_path: Path) -> None:
    path = craft_store_with_reserved_bytes(str(tmp_path), b'\xff' * 8)
    result = CliRunner().invoke(
        main, ['dev', 'show', path, '--verify-checksum']
    )
    assert result.exit_code == 1
    assert 'All zeros: no' in result.output


def test_corrupted_reserved_byte_reports_path_mismatch(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ['gen', '--directory', str(tmp_path), '--max-files', '1']
    )
    assert result.exit_code == 0
    target = None
    for root, _, filenames in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        for filename in filenames:
            target = os.path.join(root, filename)
    assert target is not None
    with open(target, 'r+b') as f:
        f.seek(55)
        f.write(b'\xff')

    result = runner.invoke(main, ['verify', '--directory', str(tmp_path)])
    assert result.exit_code == 1
    assert 'PATH MISMATCH' in result.output


def test_unknown_distribution_parameter_is_runtime_error(
    tmp_path: Path,
) -> None:
    result = CliRunner().invoke(
        main,
        [
            'gen',
            '--directory',
            str(tmp_path),
            '--max-files',
            '1',
            '--file-size',
            'Type=normal,Mean=1024,StdDev=0,Foo=2',
        ],
    )
    assert result.exit_code == 1
    assert isinstance(result.exception, TypeError)


def test_missing_distribution_parameter_is_runtime_error(
    tmp_path: Path,
) -> None:
    result = CliRunner().invoke(
        main,
        [
            'gen',
            '--directory',
            str(tmp_path),
            '--max-files',
            '1',
            '--file-size',
            'Type=normal,Mean=1024',
        ],
    )
    assert result.exit_code == 1
    assert isinstance(result.exception, TypeError)
