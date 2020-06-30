import os

from Crypto.Cipher import AES  # lib install command: $ pip install pycryptodome

# constants

BLOCK_SIZE = 16  # 16 bytes = 128 bits also key size and iv size
KEY_SIZE = 16
NONCE_SIZE = 4  # counter size as well
IV_CTR_SIZE = 8
PAD_TYPE = "PKCS5"
ENCODING = 'utf-8'

ECB = "ECB"
CBC = "CBC"
CFB = "OFB"
OFB = "OFB"
CTR = "CTR"

# Methods


def pad(plain_text):
    """
    func to pad cleartext to be multiples of 16-byte blocks.
    If you want to encrypt a text message that is not multiples of 16-byte blocks,
    the text message must be padded with additional bytes to make the text message to be multiples of 16-byte blocks.
    """
    number_of_bytes_to_pad = BLOCK_SIZE - len(plain_text) % BLOCK_SIZE
    ascii_string = chr(number_of_bytes_to_pad)
    padding_str = number_of_bytes_to_pad * ascii_string
    padded_plain_text = plain_text + padding_str.encode(ENCODING)
    return padded_plain_text


def xor(byte, byte_other):
    result = bytes([a ^ b for a, b in zip(byte, byte_other)])
    return result

    # encryption


def aes_block_encrypt(key, data_block, is_final_block, padding):
    if padding != PAD_TYPE:
        raise Exception("Wrong pad type, use PKCS5")
    cipher = AES.new(key, AES.MODE_ECB)
    if is_final_block:
        data_block = pad(data_block)
    encrypted_block = cipher.encrypt(data_block)
    return encrypted_block


def ecb_encrypt(key, data_array):
    cipher_text = bytearray('', ENCODING)

    for i in range((len(data_array) // BLOCK_SIZE) + 1):
        tmp_slice = slice(BLOCK_SIZE * i, BLOCK_SIZE * (i + 1))
        if len(data_array[tmp_slice]) < BLOCK_SIZE and len(data_array[tmp_slice]) != 0:
            is_final_block = True
        else:
            is_final_block = False
        tmp_block = data_array[tmp_slice]
        cipher_text_block = aes_block_encrypt(key, tmp_block, is_final_block, PAD_TYPE)
        cipher_text += cipher_text_block

    return cipher_text


def cbc_encrypt(key, data_array, iv):
    cipher_text = bytearray('', ENCODING)
    cipher_text_block = bytearray('', ENCODING)

    for i in range((len(data_array) // BLOCK_SIZE) + 1):
        tmp_slice = slice(BLOCK_SIZE * i, BLOCK_SIZE * (i + 1))
        if len(data_array[tmp_slice]) < BLOCK_SIZE and len(data_array[tmp_slice]) != 0:
            is_final_block = True
        else:
            is_final_block = False
        tmp_block = data_array[tmp_slice]
        if i == 0 and is_final_block:
            tmp_block = pad(tmp_block)
            is_final_block = False
            cipher_text_block = aes_block_encrypt(key, xor(tmp_block, iv), is_final_block, PAD_TYPE)
            cipher_text += cipher_text_block
        elif i == 0 and not is_final_block:
            cipher_text_block = aes_block_encrypt(key, xor(tmp_block, iv), is_final_block, PAD_TYPE)
            cipher_text += cipher_text_block
        elif is_final_block:
            tmp_block = pad(tmp_block)
            is_final_block = False
            cipher_text_block = aes_block_encrypt(key, xor(tmp_block, cipher_text_block), is_final_block, PAD_TYPE)
            cipher_text += cipher_text_block
        else:
            cipher_text_block = aes_block_encrypt(key, xor(tmp_block, cipher_text_block), is_final_block, PAD_TYPE)
            cipher_text += cipher_text_block
    return cipher_text


def cfb_encrypt(key, data_array, iv):
    cipher_text = bytearray('', ENCODING)
    iter_cipher_block = bytearray('', ENCODING)

    for i in range((len(data_array) // BLOCK_SIZE) + 1):
        tmp_slice = slice(BLOCK_SIZE * i, BLOCK_SIZE * (i + 1))
        if len(data_array[tmp_slice]) < BLOCK_SIZE and len(data_array[tmp_slice]) != 0:
            is_final_block = True
        else:
            is_final_block = False
        tmp_block = data_array[tmp_slice]
        if i == 0 and is_final_block:
            is_final_block = False
            cipher_text_block = aes_block_encrypt(key, iv, is_final_block, PAD_TYPE)
            tmp_block = pad(tmp_block)
            iter_cipher_block = xor(tmp_block, cipher_text_block)
            cipher_text += iter_cipher_block
        elif i == 0 and not is_final_block:
            cipher_text_block = aes_block_encrypt(key, iv, is_final_block, PAD_TYPE)
            iter_cipher_block = xor(tmp_block, cipher_text_block)
            cipher_text += iter_cipher_block
        elif is_final_block:
            tmp_block = pad(tmp_block)
            is_final_block = False
            cipher_text_block = aes_block_encrypt(key, iter_cipher_block, is_final_block, PAD_TYPE)
            iter_cipher_block = xor(tmp_block, cipher_text_block)
            cipher_text += iter_cipher_block
        else:
            cipher_text_block = aes_block_encrypt(key, iter_cipher_block, is_final_block, PAD_TYPE)
            iter_cipher_block = xor(tmp_block, cipher_text_block)
            cipher_text += iter_cipher_block
    return cipher_text


def ofb_encrypt(key, data_array, iv):
    cipher_text = bytearray('', ENCODING)
    cipher_text_block = bytearray('', ENCODING)

    for i in range((len(data_array) // BLOCK_SIZE) + 1):
        tmp_slice = slice(BLOCK_SIZE * i, BLOCK_SIZE * (i + 1))
        if len(data_array[tmp_slice]) < BLOCK_SIZE and len(data_array[tmp_slice]) != 0:
            is_final_block = True
        else:
            is_final_block = False
        tmp_block = data_array[tmp_slice]
        if i == 0 and is_final_block:
            is_final_block = False
            cipher_text_block = aes_block_encrypt(key, iv, is_final_block, PAD_TYPE)
            iter_cipher_block = xor(tmp_block, cipher_text_block)
            cipher_text += iter_cipher_block
        elif i == 0 and not is_final_block:
            cipher_text_block = aes_block_encrypt(key, iv, is_final_block, PAD_TYPE)
            iter_cipher_block = xor(tmp_block, cipher_text_block)
            cipher_text += iter_cipher_block
        elif is_final_block:
            tmp_block = pad(tmp_block)
            is_final_block = False
            cipher_text_block = aes_block_encrypt(key, cipher_text_block, is_final_block, PAD_TYPE)
            iter_cipher_block = xor(tmp_block, cipher_text_block)
            cipher_text += iter_cipher_block
        else:
            cipher_text_block = aes_block_encrypt(key, cipher_text_block, is_final_block, PAD_TYPE)
            iter_cipher_block = xor(tmp_block, cipher_text_block)
            cipher_text += iter_cipher_block
    return cipher_text


def ctr_encrypt(key, data_array, nonce, iv_ctr):
    cipher_text = bytearray('', ENCODING)

    for i in range((len(data_array) // BLOCK_SIZE) + 1):
        tmp_slice = slice(BLOCK_SIZE * i, BLOCK_SIZE * (i + 1))
        if len(data_array[tmp_slice]) < BLOCK_SIZE and len(data_array[tmp_slice]) != 0:
            is_final_block = True
        else:
            is_final_block = False
        tmp_block = data_array[tmp_slice]
        counter = i.to_bytes(NONCE_SIZE, 'big')
        iv_nonce_ctr = nonce + iv_ctr + counter
        if is_final_block:
            is_final_block = False
            tmp_block = pad(tmp_block)
        cipher_text_block = aes_block_encrypt(key, iv_nonce_ctr, is_final_block, PAD_TYPE)
        iter_cipher_block = xor(tmp_block, cipher_text_block)
        cipher_text += iter_cipher_block
    return cipher_text


def aes_encrypt(key, data, mode, iv, nonce=None):
    if mode == ECB:
        return ecb_encrypt(key, data)
    if mode == CBC:
        return cbc_encrypt(key, data, iv)
    if mode == CFB:
        return cfb_encrypt(key, data, iv).hex()
    if mode == OFB:
        return ofb_encrypt(key, data, iv).hex()
    if mode == CTR:
        return ctr_encrypt(key, data, iv, nonce).hex()
    raise ValueError("Wrong Encryption Type")

# decryption


def aes_block_decrypt(key, data_block):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_block = cipher.decrypt(data_block)
    return decrypted_block


def ecb_decrypt(key, data_array):
    plain_text = bytearray('', ENCODING)

    for i in range((len(data_array) // BLOCK_SIZE) + 1):
        tmp_slice = slice(BLOCK_SIZE * i, BLOCK_SIZE * (i + 1))
        tmp_block = data_array[tmp_slice]
        plain_text_block = aes_block_decrypt(key, tmp_block)
        plain_text += plain_text_block
    return plain_text


def cbc_decrypt(key, data_array, iv):
    plain_text = bytearray('', ENCODING)
    prev_block = bytearray('', ENCODING)

    for i in range((len(data_array) // BLOCK_SIZE) + 1):
        tmp_slice = slice(BLOCK_SIZE * i, BLOCK_SIZE * (i + 1))
        tmp_block = data_array[tmp_slice]
        if i == 0:
            plain_text += xor(aes_block_decrypt(key, tmp_block), iv)
            prev_block = tmp_block
        else:
            plain_text += xor(aes_block_decrypt(key, tmp_block), prev_block)
    return plain_text


def cfb_decrypt(key, data_array, iv):
    plain_text = bytearray('', ENCODING)
    prev_block = bytearray('', ENCODING)

    for i in range((len(data_array) // BLOCK_SIZE) + 1):
        tmp_slice = slice(BLOCK_SIZE * i, BLOCK_SIZE * (i + 1))
        tmp_block = data_array[tmp_slice]
        if i == 0:
            plain_text += xor(tmp_block, aes_block_encrypt(key, iv, False, PAD_TYPE))
            prev_block = tmp_block
        else:
            plain_text += xor(prev_block, aes_block_encrypt(key, tmp_block, False, PAD_TYPE))
            prev_block = tmp_block
    return plain_text


def ofb_decrypt(key, data_array, iv):
    plain_text = bytearray('', ENCODING)
    prev_block = bytearray('', ENCODING)

    for i in range((len(data_array) // BLOCK_SIZE) + 1):
        tmp_slice = slice(BLOCK_SIZE * i, BLOCK_SIZE * (i + 1))
        tmp_block = data_array[tmp_slice]
        if i == 0:
            prev_block = aes_block_encrypt(key, iv, False, PAD_TYPE)
            plain_text += xor(tmp_block, prev_block)
        else:
            plain_text += xor(tmp_block, aes_block_encrypt(key, prev_block, False, PAD_TYPE))
            prev_block = aes_block_encrypt(key, prev_block, False, PAD_TYPE)
    return plain_text


def ctr_decrypt(key, data_array, nonce, iv_ctr):
    plain_text = bytearray('', ENCODING)

    for i in range((len(data_array) // BLOCK_SIZE) + 1):
        tmp_slice = slice(BLOCK_SIZE * i, BLOCK_SIZE * (i + 1))
        tmp_block = data_array[tmp_slice]
        counter = i.to_bytes(NONCE_SIZE, 'big')
        iv_nonce_ctr = nonce + iv_ctr + counter
        cipher_block = aes_block_encrypt(key, iv_nonce_ctr, False, PAD_TYPE)
        iter_plain_block = xor(tmp_block, cipher_block)
        plain_text += iter_plain_block
    return plain_text


def aes_decrypt(key, data, mode, iv, nonce=None):
    if mode == ECB:
        return ecb_decrypt(key, data)
    if mode == CBC:
        return cbc_decrypt(key, data, iv)
    if mode == CFB:
        return cfb_decrypt(key, data, iv).hex()
    if mode == OFB:
        return ofb_decrypt(key, data, iv).hex()
    if mode == CTR:
        return ctr_decrypt(key, data, iv, nonce).hex()
    raise ValueError("Wrong Decryption Type")

# tests

test_key = os.urandom(BLOCK_SIZE)
test_text = os.urandom(BLOCK_SIZE * 2 + 8)
test_iv = os.urandom(BLOCK_SIZE)
t_nonce = os.urandom(NONCE_SIZE)
t_iv_ctr = os.urandom(IV_CTR_SIZE)

print("Let's start testing: \n")

print("Random text 2,5 blocks:", test_text.hex())
print("Random key:", test_key.hex())
print("Random IV:", test_iv.hex(), "\n")
print("ECB:", aes_encrypt(test_key, test_text, ECB, test_iv).hex())
print("CBC:", aes_encrypt(test_key, test_text, CBC, test_iv).hex())
print("CFB:", aes_encrypt(test_key, test_text, CFB, test_iv))
print("OFB:", aes_encrypt(test_key, test_text, OFB, test_iv))
print("CTR:", aes_encrypt(test_key, test_text, CTR, t_nonce, t_iv_ctr), "\n")
print("Fuck-Up:", aes_encrypt(test_key, test_text, "LOL", test_iv))

print("Now decrypt tests: \n")

print("ECB:", aes_decrypt(test_key, ecb_encrypt(test_key, test_text), ECB, test_iv).hex())
print("CBC:", aes_decrypt(test_key, cbc_encrypt(test_key, test_text, test_iv), CBC, test_iv).hex())
print("CFB:", aes_decrypt(test_key, cfb_encrypt(test_key, test_text, test_iv), CFB, test_iv).hex())
print("OFB:", aes_decrypt(test_key, ofb_encrypt(test_key, test_text, test_iv), OFB, test_iv).hex())
print("CTR:", aes_decrypt(test_key, ctr_encrypt(test_key, test_text, t_nonce, t_iv_ctr), CTR, t_iv_ctr, t_nonce, ).hex(), "\n")

print("Decryption of CBC: \n")

# NUMBER ONE

print("CBC key: 140b41b22a29beb4061bda66b6747e14")
print(
    "CBC Ciphertext 1: 4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81",
    "\n")

key_1 = b'140b41b22a29beb4061bda66b6747e14'
cbc_text_1 = b'4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'
sl_1 = slice(0, 16)
sl_text_1 = slice(16, len(cbc_text_1))
iv_1 = cbc_text_1[sl_1]
cbc_cipher_text_1 = cbc_text_1[sl_text_1]

plain_text_1 = cbc_decrypt(key_1, cbc_cipher_text_1, iv_1)
print("1st text decoding:", plain_text_1.hex(), "\n")

# NUMBER TWOOOOOOOOOO

print("CBC key: 140b41b22a29beb4061bda66b6747e14")
print(
    "CBC Ciphertext 2: 5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253",
    "\n")

key_2 = b'140b41b22a29beb4061bda66b6747e14'
cbc_text_2 = b'5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'
sl_2 = slice(0, 16)
sl_text_2 = slice(16, len(cbc_text_2))
iv_2 = cbc_text_2[sl_2]
cbc_cipher_text_2 = cbc_text_2[sl_text_2]
plain_text_2 = cbc_decrypt(key_2, cbc_cipher_text_2, iv_2)
print("2nd text decoding:", plain_text_2.hex(), "\n")

# NUMBER THREEEEEEEEE
print("Decryption of CTR: \n")
print("CTR key: 36f18357be4dbd77f050515c73fcf9f2")
print(
    "CTR Ciphertext 1: 69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329",
    "\n")

key_3 = b'36f18357be4dbd77f050515c73fcf9f2'
cbc_text_3 = b'69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'
sl_3 = slice(0, 16)
sl_text_3 = slice(16, len(cbc_text_3))
iv_3 = cbc_text_2[sl_3]
cbc_cipher_text_3 = cbc_text_3[sl_text_3]
plain_text_3 = ctr_decrypt(key_3, cbc_cipher_text_3, t_nonce, t_iv_ctr)
print("3rd text decoding:", plain_text_3.hex(), "\n")

# NUMBER CHETЫRE

print("CTR key: 36f18357be4dbd77f050515c73fcf9f2")
print("CTR Ciphertext 2: 770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451",
      "\n")

key_4 = b'36f18357be4dbd77f050515c73fcf9f2'
cbc_text_4 = b'770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'
sl_4 = slice(0, 16)
sl_text_4 = slice(16, len(cbc_text_4))
iv_4 = cbc_text_2[sl_4]
cbc_cipher_text_4 = cbc_text_4[sl_text_4]
plain_text_4 = ctr_decrypt(key_4, cbc_cipher_text_4, t_nonce, t_iv_ctr)
print("4th text decoding:", plain_text_4.hex(), "\n")

print(1)
