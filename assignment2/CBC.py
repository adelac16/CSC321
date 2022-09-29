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

if __name__ == '__main__':
    img = read_image()
    img_header = img[0:54] #header is in this portion of bytes, 138 if 54 doesn't work
    print(img_header)
    #write_image(img)