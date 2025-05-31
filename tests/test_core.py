import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from caf.generator import FileGenerator
from caf.verifier import FileVerifier


def test_filegenerator_infinite_defaults(tmp_path):
    gen = FileGenerator(str(tmp_path), None, None, lambda: 1)
    assert gen._max_files == float('inf')
    assert gen._max_disk_usage == float('inf')


def test_write_root_sha_existing_dir(tmp_path, monkeypatch):
    gen = FileGenerator(str(tmp_path), 0, 0, lambda: 1)
    roots_dir = tmp_path / '.metadata' / 'roots'
    roots_dir.mkdir(parents=True)

    def fake_makedirs(path):
        raise OSError()

    monkeypatch.setattr(os, 'makedirs', fake_makedirs)
    gen._write_root_sha('abc')
    assert (roots_dir / 'abc').exists()
    assert (tmp_path / '.metadata' / 'all').exists()


def test_verify_invalid_checksum(tmp_path):
    gen = FileGenerator(str(tmp_path), 1, float('inf'), lambda: 32)
    gen.generate_files()
    # corrupt a file
    for root, _, files in os.walk(tmp_path):
        for filename in files:
            if '.metadata' in root:
                continue
            with open(os.path.join(root, filename), 'ab') as f:
                f.write(b'corrupt')
            break
        break
    verifier = FileVerifier(str(tmp_path))
    assert not verifier.verify_files()


def test_verify_known_roots_mismatch(tmp_path, capsys):
    verifier = FileVerifier(str(tmp_path))
    roots_dir = tmp_path / '.metadata' / 'roots'
    roots_dir.mkdir(parents=True)
    (roots_dir / 'a').touch()
    (roots_dir / 'b').touch()
    meta = tmp_path / '.metadata'
    meta.mkdir(exist_ok=True)
    with open(meta / 'all', 'wb') as f:
        f.write(b'bad')
    verifier._verify_known_roots(['a', 'b'])
    assert "Root hash is not valid" in capsys.readouterr().err
    assert not verifier._verification_succeeded


def test_validate_checksum_bad(tmp_path, capsys):
    d = tmp_path / 'aa' / 'bb'
    d.mkdir(parents=True)
    path = d / 'ccc'
    path.write_bytes(b'data')
    verifier = FileVerifier(str(tmp_path))
    verifier._validate_checksum(str(path))
    assert "Invalid checksum" in capsys.readouterr().err
    assert not verifier._verification_succeeded
