from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import urllib.parse
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
    n = 16  # block length
    blocks = [body[i:i + n] for i in range(0, len(body), n)]    # split message to blocks
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
    blocks = [body[i:i + n] for i in range(0, len(body), n)]    # splits ciphertext to blocks
    for block in blocks:
        dec_block = decrypt_block(block, key, IV)   #decrypts current block
        IV = block          # changes vector to previous ciphertext block
        if block == blocks[-1]:         # unpad last block
            try:
                dec_block = unpad(dec_block, 16)
            except ValueError:      # catches when no padding on last block
                pass
        dec += dec_block    # append decrypted blocks to output
    return dec


def parse_data(data):
    data = data.replace(";", urllib.parse.quote(";"))
    data = data.replace("=", urllib.parse.quote("="))
    return data


def submit(data, key, IV):
    data = parse_data(data)     # url encode = and ;
    data = full_message(data)   # append and prepend text
    ct = CBC_encrypt(data, key, IV)
    return ct


def full_message(msg):
    prepend = "userid=456;userdata="
    append = ";session-id=31337"
    msg = prepend + msg + append
    return msg


def pad_message(blockedMsg):
    newMsg = []
    for block in blockedMsg:
        if len(blockedMsg) < 16:
            block = pad(block, 16)
        newMsg.append(block)
    return newMsg



def verify(data, key, IV):
    pt = CBC_decrypt(data, key, IV)
    print(f"verify ct: {pt}")
    return b';admin=true;' in pt

def bit_flip(ct, origIn):
    n = 16          # set block size
    ctBlocks = [ct[i:i + n] for i in range(0, len(ct), n)]
    msg = full_message(origIn)      # get original message with append and prepend
    msg = msg.encode('UTF-8')       # encode message to bytes
    msgBlocks = [msg[i:i + n] for i in range(0, len(msg), n)]   # split message to blocks
    msgBlocks = pad_message(msgBlocks)      # pad message
    ctBytes = ctBlocks[0][0:13]         # first bytes from first block of ct(length of ;admin=true;)
    msgBytes = msgBlocks[1][0:13]       # first bytes from second block of pt(length of ;admin=true;)
    injectStr = ";admin=true;".encode('UTF-8')  # get bytes of injected string ;admin=true;
    zeroOut = byte_xor(ctBytes, msgBytes)       # zeros out when xor in next block
    injectCt = byte_xor(zeroOut, injectStr)     # xor zerod out bytes with injected bytes
    ctBlockOne = ctBlocks[0]
    ctBlocks[0] = injectCt + ctBlockOne[len(injectCt):]     # inject ct into first block
    newCt = b''
    for i in ctBlocks:      # create new ct with injected ct
        newCt += i
    return newCt


if __name__ == '__main__':
    key = get_random_bytes(16)      # same key throughout whole program
    IV = get_random_bytes(16)       # same IV throughout whole program
    msg = input("What is your message? ")
    ct = submit(msg, key, IV)
    inject = bit_flip(ct, msg)      # get inject ct
    print(f'admin? {verify(ct, key, IV)}')
    print(f'what about now? {verify(inject, key, IV)}')


