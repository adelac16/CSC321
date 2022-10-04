import json
from base64 import b64encode
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


def encrypt_block(data, key, vector):
    if type(data) != bytes:             # checks if data is already bytes
        data = data.encode('UTF-8')     # converts data to bytes
    if len(data) < 16:
        data = pad(data, 16)
    data = byte_xor(data, vector)       # xor vector and data
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(data)     # encrypts block
    return ct_bytes


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def CBC_image(body, key, IV):
    enc = b''
    n = 16  # chunk length
    blocks = [body[i:i + n] for i in range(0, len(body), n)]
    for block in blocks:
        enc_block = encrypt_block(block, key, IV)
        IV = enc_block  # changes vector to encrypted ciphertext block
        enc += enc_block
    return enc


if __name__ == '__main__':
    key = get_random_bytes(16)
    IV = get_random_bytes(16)
    img = read_image()
    img_header = img[0:54]
    enc_image_list = CBC_image(img[55:-1], key, IV)
    enc_image = img_header + enc_image_list
    write_image(enc_image)

