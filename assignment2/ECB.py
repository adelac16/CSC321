from PIL import Image
import numpy as np

def read_image():
    img_arr = Image.open('./mustang.bmp')
    img_arr = np.array(Image.open('./mustang.bmp'))
    return img_arr

def write_image(img_arr):
    im = Image.fromarray(img_arr)
    im.save("ECB_encrypted.jpeg")

if __name__ == '__main__':
    pass