
# importing the required module
import matplotlib.pyplot as plt
  
# RSA ---------------------------------------------
def rsa():
    x = [512,1024,2048,4096]
    y = [17894.7,5226.2,906.8,120.4]

    plt.plot(x, y)

    plt.xlabel('key size (bits)')
    plt.ylabel('thoroughput (signs/second)')
    plt.title('RSA Key Size vs. Thoroughput')
    plt.show()

# AES-128 ---------------------------------------------
def aes_cbc():
    x = [16,64,256,1024,8192]
    y = [134528.89,147759.17,145654.38,152140.36,152388.64]

    plt.plot(x, y)

    plt.xlabel('block size (bytes)')
    plt.ylabel('thoroughput (bytes/second, 1000\'s)')
    plt.title('AES_128 Block Size vs. Thoroughput (CBC)')
    plt.show()

if __name__=='__main__':
    aes_cbc()
    rsa()