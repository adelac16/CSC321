from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import urllib.parse
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
    if len(data) < 16:
        data = pad(data, 16)
    data = byte_xor(data, vector)       # xor vector and data
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(data)     # encrypts block
    return ct_bytes


def CBC_encrypt(body, key, IV):
    enc = b''
    n = 16  # chunk length
    blocks = [body[i:i + n] for i in range(0, len(body), n)]
    for block in blocks:
        enc_block = encrypt_block(block, key, IV)
        IV = enc_block          # changes vector to encrypted ciphertext block
        enc += enc_block
    return enc


def decrypt_block(ct, key, vector):
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        pt = cipher.decrypt(ct)             # decrypts with key
        pt = byte_xor(pt, vector)           # xor with vector
        # print("The message was: ", pt)
        return pt
    except (ValueError, KeyError):
        print("Incorrect decryption")


def CBC_decrypt(body, key, IV):
    dec = b''
    n = 16
    blocks = [body[i:i + n] for i in range(0, len(body), n)]
    for block in blocks:
        dec_block = decrypt_block(block, key, IV)   #decrypts current block
        IV = block          # changes vector to previous ciphertext block
        if dec_block == blocks[-1]:
            dec_block = unpad(dec_block, 16)
        dec += dec_block
    return dec


def parse_data(data):
    data = data.replace(";", urllib.parse.quote(";"))
    data = data.replace("=", urllib.parse.quote("="))
    return data


def submit(key, IV):
    prepend = "userid=456;userdata="
    append = ";session-id=31337"
    data =input("What is your message? ")
    data = parse_data(data)
    data = prepend + data + append
    ct = CBC_encrypt(data, key, IV)
    return ct


def verify(data, key, IV):
    pt = CBC_decrypt(data, key, IV)
    print(pt)
    return b';admin=true' in pt

def bit_flip(ct):
    n = 16
    blocks = [ct[i:i + n] for i in range(0, len(ct), n)]



if __name__ == '__main__':
    key = get_random_bytes(16)      # same key throughout whole program
    IV = get_random_bytes(16)       # same IV throughout whole program
    # enc = CBC_encrypt(data, key, IV)
    # print(f'encrypted string: {enc}')
    # dec = CBC_decrypt(enc, key, IV)
    # print(f'decrypted string: {dec}')
    ct = submit(key, IV)
    print(ct)
    print(f'admin? {verify(ct, key, IV)}')


