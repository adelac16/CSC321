from PIL import Image
import numpy as np

def read_image():
    file = open("mustang.bmp","rb")
    data = file.read()
    file.close()
    return data

def write_image(data):
    file = open("CBC_encrypted.bmp","wb")
    file.write(data)
    file.close()

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
    img = read_image()
    img_header = img[0:54] #header is in this portion of bytes, 138 if 54 doesn't work
    print(img_header)
    #write_image(img)