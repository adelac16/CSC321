
# importing the required module
import matplotlib.pyplot as plt
  
# RSA ---------------------------------------------
def rsa():
    x = [512,1024,2048,4096]
    sign = [17894.7,5226.2,906.8,120.4]
    verify = [139309.5, 54719.1, 16818.7, 4562.8]

    plt.plot(x, sign, label = "sign (encrypt)")
    plt.plot(x, verify, label = "verify (decrypt)")

    plt.xlabel('key size (bits)')
    plt.ylabel('throughput (sign/verify per s)')
    plt.title('RSA Key Size vs. Throughput')
    plt.legend(loc='best')
    plt.show()

# AES ---------------------------------------------
def aes_cbc():
    x = [16,64,256,1024,8192]
    aes_128 = [134528.89,147759.17,145654.38,152140.36,152388.64]
    aes_192 = [113691.73, 123578.75, 125737.87, 125960.29, 126821.91]
    aes_256 = [98455.62, 106025.94, 106282.52, 108247.89, 108502.73]

    plt.plot(x, aes_128, label='AES 128')
    plt.plot(x, aes_192, label='AES 192')
    plt.plot(x, aes_256, label='AES 256')

    plt.xlabel('message size (# bytes)')
    plt.ylabel('throughput (bytes/second, 1000\'s)')
    plt.title('AES Block Size vs. Throughput (CBC)')
    plt.legend(loc='best')
    plt.show()

if __name__=='__main__':
    aes_cbc()
    #rsa()