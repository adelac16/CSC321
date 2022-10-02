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
    file = open("ECB_encrypted.bmp", "wb")
    file.write(data)
    file.close()


def encrypt_block(data, key):
    if type(data) != bytes:             # checks if data is already bytes
        data = data.encode('UTF-8')     # converts data to bytes
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return ct_bytes


def encrypt_img(header, body, key):
    enc_img = []
    start_idx = 0
    end_idx = 16
    #encrypt one block at a time
    while start_idx < len(body):
        # encrypt block and append to result
        enc_block = encrypt_block(body[start_idx:end_idx], key)
        enc_img.append(enc_block)
        # increment indices
        start_idx += 16
        end_idx += 16
        # padding for last block
        if end_idx > len(body):
            pad = b''
            pad_len = 16-(end_idx-len(body)) # length of pad
            # add required # of bytes
            for i in range(pad_len):
                pad += bytes(pad_len)
            print(pad) # is this even right
            end_idx = len(body)
    enc_img.insert(0, header)
    return enc_img

if __name__ == '__main__':
    # read image
    img = read_image()
    # get header, body, and key
    header = img[0:54]
    body = img[54:]
    key = get_random_bytes(16)
    # encrypt
    enc_img_list = encrypt_img(header, body, key)
    #print(enc_img_list)
    # write to result
    #data = b''.join(enc_img_list)
    #print('writing image')
    #write_image(data)

