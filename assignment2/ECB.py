import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from base64 import b64decode
from Crypto.Util.Padding import unpad


def encrypt_text(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'ciphertext': ct})
    print(result)
    #
    # cipher = AES.new(key, AES.MODE_ECB)
    # print(cipher)
    # ciphertext = cipher.encrypt(text)
    return (result)


def decrypt_text(json_input, key):
    try:
        b64 = json.loads(json_input)
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")


if __name__ == '__main__':
    key = get_random_bytes(16)
    # text = input("input a string to encrypt: ")
    data = b"secret"
    jsonCt = encrypt_text(data, key)
    decrypt_text(jsonCt, key)
