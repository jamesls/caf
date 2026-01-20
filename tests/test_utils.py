from caf.paths import parse_hash_from_path


def test_parse_hash_from_path_parses_three_level_layout(tmp_path):
    hex_hash = 'abcdef0123456789abcdef0123456789abcdef01'
    path = (
        tmp_path / hex_hash[:2] / hex_hash[2:4] / hex_hash[4:6] / hex_hash[6:]
    )
    assert parse_hash_from_path(str(path)) == hex_hash


def test_parse_hash_from_path_rejects_four_level_layout(tmp_path):
    hex_hash = 'abcdef0123456789abcdef0123456789abcdef01'
    path = (
        tmp_path
        / hex_hash[:2]
        / hex_hash[2:4]
        / hex_hash[4:6]
        / hex_hash[6:8]
        / hex_hash[8:]
    )
    assert parse_hash_from_path(str(path)) == ''


def test_parse_hash_from_path_ignores_metadata_paths(tmp_path):
    hex_hash = 'abcdef0123456789abcdef0123456789abcdef01'
    path = tmp_path / '.metadata' / 'roots' / hex_hash
    assert parse_hash_from_path(str(path)) == ''
