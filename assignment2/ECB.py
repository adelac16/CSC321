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
    file = open("ECB_encrypted.bmp", "wb")
    file.write(data)
    file.close()


def encrypt_block(data, key):
    if type(data) != bytes:             # checks if data is already bytes
        data = data.encode('UTF-8')     # converts data to bytes
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'ciphertext': ct})
    print(result)
    return result


def decrypt_block(json_input, key):
    try:
        b64 = json.loads(json_input)
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")


def encrypt_decrypt_block(data, key):
    jsonCt = encrypt_block(data, key)
    decrypt_block(jsonCt, key)


if __name__ == '__main__':
    img = read_image()
    img_header = img[0:54]
    key = get_random_bytes(16)
    inText = input("input a string to encrypt: ")
    data = inText
    encrypt_decrypt_block(data, key)

