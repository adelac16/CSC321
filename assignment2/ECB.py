from PIL import Image
import numpy as np

def read_image():
    file = open("mustang.bmp","rb")
    data = file.read()
    file.close()
    return data

def write_image(data):
    file = open("ECB_encrypted.bmp","wb")
    file.write(data)
    file.close()

if __name__ == '__main__':
    img = read_image()
    img_header = img[0:14] #header is in this portion of bytes
    #write_image(img)