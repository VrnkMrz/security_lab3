from flask import Flask, render_template, request, send_file
import hashlib
import os
from io import BytesIO
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from lab1.lab1 import linear_congruential_generator
from lab2.lab2 import derive_key_from_passphrase

app = Flask(__name__)
def pad_plaintext(plaintext, block_size):
    pad_length = block_size - (len(plaintext) % block_size)
    padding = bytes([pad_length]) * pad_length
    print(f"Padding: {padding}, Pad length: {pad_length}, Original length: {len(plaintext)}")
    return plaintext + padding


def unpad_plaintext(padded_plaintext):
    pad_length = padded_plaintext[-1]
    if pad_length > len(padded_plaintext):
        raise ValueError("Invalid padding.")
    print(f"Removing padding: Last byte (pad length): {pad_length}")
    return padded_plaintext[:-pad_length]


def rc5_encrypt_block(block, round_keys):
    left, right = int.from_bytes(block[:2], 'big'), int.from_bytes(block[2:], 'big')
    for round_key in round_keys[:20]:
        left = (left ^ round_key) & 0xFFFF
        right = (right ^ round_key) & 0xFFFF
    return left.to_bytes(2, 'big') + right.to_bytes(2, 'big')


def rc5_decrypt_block(block, round_keys):
    left, right = int.from_bytes(block[:2], 'big'), int.from_bytes(block[2:], 'big')
    for round_key in reversed(round_keys[:20]):
        left = (left ^ round_key) & 0xFFFF
        right = (right ^ round_key) & 0xFFFF
    return left.to_bytes(2, 'big') + right.to_bytes(2, 'big')


def rc5_cbc_encrypt(plaintext, key, iv, block_size=4):
    round_keys = [int.from_bytes(key[i:i + 2], 'big') for i in range(0, len(key), 2)]
    padded_plaintext = pad_plaintext(plaintext, block_size)
    blocks = [padded_plaintext[i:i + block_size] for i in range(0, len(padded_plaintext), block_size)]
    encrypted_blocks = []
    previous_block = iv

    print(f"Initial IV (encryption): {iv}")

    for i, block in enumerate(blocks):
        xor_block = bytes(a ^ b for a, b in zip(block, previous_block))
        print(f"Block {i}: Before XOR: {block}, After XOR with IV: {xor_block}")

        encrypted_block = rc5_encrypt_block(xor_block, round_keys)
        encrypted_blocks.append(encrypted_block)
        previous_block = encrypted_block
        print(f"Block {i}: Encrypted: {encrypted_block}")

    return b''.join(encrypted_blocks)


def rc5_cbc_decrypt(ciphertext, key, iv, block_size=4):
    round_keys = [int.from_bytes(key[i:i + 2], 'big') for i in range(0, len(key), 2)]
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    decrypted_blocks = []
    previous_block = iv

    print(f"Initial IV (decryption): {iv}")

    for i, block in enumerate(blocks):
        decrypted_block = rc5_decrypt_block(block, round_keys)
        print(f"Block {i}: Decrypted block: {decrypted_block}")

        xor_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
        decrypted_blocks.append(xor_block)
        print(f"Block {i}: After XOR with IV: {xor_block}")

        previous_block = block

    padded_plaintext = b''.join(decrypted_blocks)
    return unpad_plaintext(padded_plaintext)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    passphrase = request.form['passphrase']
    key_size = 64
    file = request.files['file']

    key = derive_key_from_passphrase(passphrase, key_size)

    iv_sequence = linear_congruential_generator(11, 12 ** 3, 987, 2 ** 25 - 1, 4)
    iv = bytes(iv_sequence)

    plaintext = file.read()

    ciphertext = rc5_cbc_encrypt(plaintext, key, iv)

    encrypted_iv = rc5_encrypt_block(iv, [int.from_bytes(key[:2], 'big')])  # 16-bit word size
    final_ciphertext = encrypted_iv + ciphertext

    return send_file(BytesIO(final_ciphertext), as_attachment=True, download_name=f"encrypted_{file.filename}")


@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    passphrase = request.form['passphrase']
    key_size = 64
    file = request.files['file']

    key = derive_key_from_passphrase(passphrase, key_size)

    encrypted_data = file.read()

    encrypted_iv = encrypted_data[:4]
    ciphertext = encrypted_data[4:]

    iv = rc5_decrypt_block(encrypted_iv, [int.from_bytes(key[:2], 'big')])
    iv = iv[:4]
    print(f"Decrypted IV: {iv}")

    plaintext = rc5_cbc_decrypt(ciphertext, key, iv)
    return send_file(BytesIO(plaintext), as_attachment=True, download_name=f"decrypted_{file.filename}")


if __name__ == '__main__':
    app.run(debug=True)
