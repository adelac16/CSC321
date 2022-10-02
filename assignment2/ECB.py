import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from base64 import b64decode
from Crypto.Util.Padding import unpad

#def decrypt_block(json_input, key):
#    try:
#        b64 = json.loads(json_input)
#        ct = b64decode(b64['ciphertext'])
#        cipher = AES.new(key, AES.MODE_ECB)
#        pt = unpad(cipher.decrypt(ct), AES.block_size)
#        print("The message was: ", pt)
#    except (ValueError, KeyError):
#        print("Incorrect decryption")
#
#
#def encrypt_decrypt_block(data, key):
#    jsonCt = encrypt_block(data, key)
#    decrypt_block(jsonCt, key)


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
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(data)
    return ct_bytes

def encrypt_img(header, body, key): 
    enc_img = b''
    n = 16 # chunk length
    blocks = [body[i:i+n] for i in range(0, len(body), n)]
    for block in blocks:
        if len(block)<16:
            block = pad(block, 16, style='pkcs7')
        enc_block = encrypt_block(block, key)
        enc_img += enc_block
    return (header + enc_img)

if __name__ == '__main__':
    # read image
    img = read_image()
    # get header, body, and key
    header = img[0:54]
    body = img[54:]
    key = get_random_bytes(16)
    # encrypt
    enc_img = encrypt_img(header, body, key)
    # write to result
    write_image(enc_img)

