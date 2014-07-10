import os
from binascii import hexlify
from random import randint
import tempfile
import hashlib

BUFFER_WRITE_SIZE = 1024 * 1024
TEMP_DIR = tempfile.gettempdir()


def generate_single_file_link(parent_hash,
                              file_size, buffer_size=BUFFER_WRITE_SIZE,
                              temp_dir=TEMP_DIR):
    sha1 = hashlib.sha1(parent_hash)
    amount_remaining = file_size
    temp_filename = os.path.join(
        temp_dir,
        hexlify(parent_hash[:8]).decode('ascii') + str(randint(1, 100000)))

    with open(temp_filename, 'wb') as f:
        f.write(parent_hash)
        while amount_remaining > 0:
            chunk_size = min(buffer_size, amount_remaining)
            random_data = os.urandom(chunk_size)
            f.write(random_data)
            sha1.update(random_data)
            amount_remaining -= chunk_size
    return temp_filename, sha1.digest()


if __name__ == '__main__':
    # Demo of generating the random content.
    temp_filename, sha1_hash = generate_single_file_link(
        b'\x00' * 20, file_size=4048)
    final_filename = os.path.join(b'test', hexlify(sha1_hash))
    os.rename(temp_filename, final_filename)
    print("Generating:", final_filename)
    for _ in range(10):
        temp_filename, sha1_hash = generate_single_file_link(
            sha1_hash, file_size=4048)
        final_filename = os.path.join(b'test', hexlify(sha1_hash))
        os.rename(temp_filename, final_filename)
        print("Generating:", final_filename)
    print('\n')
    # Demo of verifying
    current_filename = final_filename
    while os.path.basename(current_filename) != b'0' * 40:
        # First verify that sha1(current_filename) == current_filename
        print("Verifying", current_filename)
        with open(current_filename, 'rb') as f:
            actual = hashlib.sha1(f.read()).hexdigest().encode('ascii')
            expected = os.path.basename(current_filename)
            if actual != expected:
                import pdb; pdb.set_trace() 
            f.seek(0)
            current_filename = os.path.join(b'test', hexlify(f.read(20)))
