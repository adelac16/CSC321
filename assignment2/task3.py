
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
    plt.title('RSA Key Size vs. Thoroughput')
    plt.legend(loc='best')
    plt.show()

# AES-128 ---------------------------------------------
def aes_cbc():
    x = [16,64,256,1024,8192]
    y = [134528.89,147759.17,145654.38,152140.36,152388.64]

    plt.plot(x, y)

    plt.xlabel('block size (bytes)')
    plt.ylabel('throughput (bytes/second, 1000\'s)')
    plt.title('AES_128 Block Size vs. Thoroughput (CBC)')
    plt.show()

if __name__=='__main__':
    #aes_cbc()
    rsa()