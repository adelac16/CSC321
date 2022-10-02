from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from base64 import b64decode
from Crypto.Util.Padding import unpad


def read_image():
    file = open("mustang.bmp", "rb")
    data = file.read()
    file.close()
    return data

def write_image(data):
    file = open("CBC_encrypted.bmp", "wb")
    file.write(data)
    file.close()


def encrypt_decrypt_block(data, key, IV):
    ct = encrypt_block(data, key, IV)
    decrypt_block(ct, key, IV)


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def encrypt_block(data, key, vector):
    if type(data) != bytes:             # checks if data is already bytes
        data = data.encode('UTF-8')     # converts data to bytes
    data = byte_xor(data, vector)       # xor vector and data
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(data)     # encrypts block
    return ct_bytes


def CBC_encrypt(body, key, IV):
    enc = b''
    n = 16  # chunk length
    blocks = [body[i:i + n] for i in range(0, len(body), n)]
    for block in blocks:
        if len(block) < 16:
            block = pad(block, 16)
        enc_block = encrypt_block(block, key, IV)
        IV = enc_block
        enc += enc_block
    return enc


def decrypt_block(ct, key, vector):
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        pt = cipher.decrypt(ct)
        pt = byte_xor(pt, vector)
        pt = unpad(pt, 16)
        # print("The message was: ", pt)
        return pt
    except (ValueError, KeyError):
        print("Incorrect decryption")


def CBC_decrypt(body, key, IV):
    dec = b''
    n = 16
    blocks = [body[i:i + n] for i in range(0, len(body), n)]
    for block in blocks:
        dec_block = decrypt_block(block, key, IV)
        IV = block
        dec += dec_block
    return dec


if __name__ == '__main__':
    key = get_random_bytes(16)
    IV = get_random_bytes(16)
    data = input("input a string to encrypt: ")
    enc = encrypt_block(data, key, IV)
    print(f'encrypted string: {enc}')
    dec = decrypt_block(enc, key, IV)
    print(f'decrypted string: {dec}')


