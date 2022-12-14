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
    print('writing image')
    file = open("ECB_encrypted.bmp", "wb")
    file.write(data)
    file.close()

def encrypt_block(data, key):
    if type(data) != bytes:             # checks if data is already bytes
        data = data.encode('UTF-8')     # converts data to bytes
    if len(data)<16:                    # checks for incomplete block
            data = pad(data, 16, style='pkcs7')   # pads
    cipher = AES.new(key, AES.MODE_ECB) # create cipher
    ct_bytes = cipher.encrypt(data)     # encrypt block
    return ct_bytes

def encrypt_img(header, body, key): 
    enc_img = b''
    n = 16 # chunk length
    blocks = [body[i:i+n] for i in range(0, len(body), n)]  # break image into 16 byte blocks (AES stdrd.)
    for block in blocks:                        # iterate
        enc_block = encrypt_block(block, key)   # encrypt 1 block at a time
        enc_img += enc_block                    # append ciphertext to message
    return (header + enc_img)                   # append header and return

if __name__ == '__main__':
    img = read_image()  # read image
    # get header, body, and key
    header = img[0:54]
    body = img[54:]
    key = get_random_bytes(16)
    # encrypt
    enc_img = encrypt_img(header, body, key)
    # write to result
    write_image(enc_img)

