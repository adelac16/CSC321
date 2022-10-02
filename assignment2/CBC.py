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


def encrypt_block(data, key):
    if type(data) != bytes:             # checks if data is already bytes
        data = data.encode('UTF-8')     # converts data to bytes
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(data)
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'ciphertext': ct})
    return result.encode('UTF-8')


# def decrypt_block(json_input, key):
#     try:
#         b64 = json.loads(json_input)
#         ct = b64decode(b64['ciphertext'])
#         cipher = AES.new(key, AES.MODE_ECB)
#         pt = unpad(cipher.decrypt(ct), AES.block_size)
#         print("The message was: ", pt)
#     except (ValueError, KeyError):
#         print("Incorrect decryption")
#
#
# def encrypt_decrypt_block(data, key):
#     jsonCt = encrypt_block(data, key)
#     decrypt_block(jsonCt, key)


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def CBC_block(data, vector, key):
    # print(data)
    xor_data = byte_xor(data, vector)
    enc_block = encrypt_block(xor_data, key)
    return enc_block


def CBC_image(img_body):
    key = get_random_bytes(16)
    IV = get_random_bytes(128)
    enc_image = []
    start = 0
    end = start + 16
    while start < len(img_body):
        enc_block = CBC_block(IV, img_body[start:end], key)
        IV = enc_block
        enc_image.append(enc_block)
        start += 16
        end = start + 16
        if end > len(img_body):
            end = len(img_body)
    return enc_image



if __name__ == '__main__':
    img = read_image()
    img_header = img[0:54]
    # inText = input("input a string to encrypt: ")
    # data = inText
    enc_image_list = CBC_image(img[55:-1])
    enc_image_list.insert(0, img_header)
    file = open("CBC_encrypted.bmp", "wb")
    print("writing to file")
    for i in enc_image_list:
        file.write(i)
    file.close()

