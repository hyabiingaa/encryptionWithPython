from Crypto.Cipher import AES,DES,DES3,Blowfish,CAST,ARC2,ARC4
from Crypto import Random
from pysm4 import encrypt_cbc, decrypt_cbc
from binascii import b2a_hex
import string
import random
import os
import xlwt


   # 生成指定长度的秘钥
def keyGenerater(length):
    if length not in (16, 24, 32):
        return None
    x = string.ascii_letters + string.digits
    return ''.join([random.choice(x) for i in range(length)])

#传入数据（明文和秘钥）校验
def align(str, isKey=False,isAES=True):
# 如果接受的字符串是密码，需要确保其长度为16    
 if isKey:
     if isAES:
        if len(str) > 16:
            return str[0:16]
        else:
            return align(str)
     else:
         if len(str) > 8:
             return str[0:8]
         else:
             return align(str)
# 如果接受的字符串是明文或长度不足的密码，则确保其长度为16的整数倍    
 else:
    zerocount = 16-len(str) % 16
    for i in range(0, zerocount):
        str = str + '\0'
    return str

#AES加密
def encrypt_AES_CBC(str, key):#补全字符串    
    str = align(str)
    key = align(key, True)
    # 生成长度等于AES块大小的不可重复的密钥向量
    iv = Random.new().read(AES.block_size)
    # 初始化AES    
    AESCipher = AES.new(key, AES.MODE_CBC,iv)
    # 加密    
    cipher = AESCipher.encrypt(str)
    return b2a_hex(cipher)
    #return cipher

#  DES 加密
def encrypt_DES_CBC(str, key):
    str = align(str)
    key = align(key, True,False)
    iv = Random.new().read(8)  #iv值必须是8位
    DESCipher = DES.new(key, DES.MODE_CBC,iv)
    cipher = DESCipher.encrypt(str)
    return b2a_hex(cipher)
    #return cipher
#  DES3 加密
def encrypt_DES3_CBC(str, key):
    str = align(str)
    #key = align(key, True)
    iv = Random.new().read(DES3.block_size)
    cipher1 = DES3.new(key, DES3.MODE_CBC, iv)  # 密文生成器，采用MODE_CBC加密模式
    cipher = iv + cipher1.encrypt(str)
    #return cipher
    return b2a_hex(cipher)

#blowfish加密
def encrypt_Blowfish_CBC(str,key):
    str = align(str)
    iv = Random.new().read(Blowfish.block_size)
    cipher1 = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    cipher = iv + cipher1.encrypt(str)
    return b2a_hex(cipher)

#CAST加密
def encrypt_CAST_CBC(str,key):
    str = align(str)
    iv = Random.new().read(CAST.block_size)
    cipher1 = CAST.new(key, CAST.MODE_CBC, iv)
    cipher = iv + cipher1.encrypt(str)
    return b2a_hex(cipher)

#RC2加密
def encrypt_RC2_CBC(str,key):
    str = align(str)
    iv = Random.new().read(ARC2.block_size)
    cipher1 = ARC2.new(key, ARC2.MODE_CBC, iv)
    cipher = iv + cipher1.encrypt(str)
    return b2a_hex(cipher)

#RC4加密
#def encrypt_RC4_CBC(str,key):
#    str = align(str)
#    iv = Random.new().read(ARC4.block_size)
#    cipher1 = ARC4.new(key)
#    cipher = iv + cipher1.encrypt(str)
#    return b2a_hex(cipher)

#sm4加密
def encrypt_SM4_CBC(str,key):
    str = align(str)
    iv = ''.join(random.sample(string.ascii_letters + string.digits, 8))#8位
    cipher1 = encrypt_cbc(str,key, iv)
    cipher = bytes(cipher1, "utf-8")
    return b2a_hex(cipher)

#读取明文，调用加密算法加密并存储密文
def createFile(key, dirpath,filepath):
    files = os.listdir(dirpath)  # 得到文件夹下的所有文件名称
    txts = []
    for file in files:  # 遍历文件夹
        position = dirpath + '\\' + file  # 构造绝对路径，"\\"，其中一个'\'为转义符
        print(position)
        with open(position, "r", encoding='utf-8') as f:  # 打开文件
            text = f.read()  # 读取文件
            #crypto_AES = encrypt_AES_CBC(text, key)
            #crypto_DES = encrypt_DES_CBC(text, key)
            #crypto_DES3 = encrypt_DES3_CBC(text, key)
            #crypto_Blowfish = encrypt_Blowfish_CBC(text, key)
            #crypto_CAST = encrypt_CAST_CBC(text, key)
            #crypto_RC2 = encrypt_RC2_CBC(text, key)
            #crypto_RC4 = encrypt_RC4_CBC(text, key)
            crypto_SM4 = encrypt_SM4_CBC(text, key)
            print(type(crypto_SM4))
            s=crypto_SM4.decode()
            #s=crypto_DES.decode()
            print(type(s))
            str = ' '.join([bin(ord(c)).replace('0b', '') for c in s])
            print(type(str))
            fh = open(filepath+ file, 'w', encoding='utf-8')
            fh.write(str)
        fh.close()
            #savedBinFile = open(filepath+ file,"wb")  # open a file, if not exist, create it
            #savedBinFile.write(str)
    #savedBinFile.close()
    f.close()


#密文写入excel
def writeExcel(filepath,dirpath):
    # coding=utf-8
    file_path = filepath  # 要写入的文件
    f = xlwt.Workbook(encoding='utf-8', style_compression=0)
    sheet = f.add_sheet('sheet1')
    pathDir = os.listdir(dirpath)  # txt文件放置在sub文件夹中，用来获取sub文件夹内所有文件目录
    i = 0
    for s in pathDir:
        newDir = os.path.join(dirpath+"\\", s)  # 把获取的文件路径整合
        f1 = open(newDir)
        line = f1.read()
        sheet.write(i, 0, line)
        i = i + 1
    print(i)
    f.save(file_path)


def readExcelToList():
        # coding=utf-8
   # file_path = 'E:\\dataAnalysis\\cvs\\data_AES.xls'  # 要写入的文件
    #f = xlwt.Workbook(encoding='gbk', style_compression=0)
    #sheet = f.add_sheet('sheet1')
    pathDir = os.listdir("E:\\dataAnalysis\\deal\\data\\AES")  # txt文件放置在sub文件夹中，用来获取sub文件夹内所有文件目录
    print("=======")
    print(type(pathDir))
    i = 0
    Cryptogram = []
    Label = []
    for s in pathDir:
        newDir = os.path.join("E:\\dataAnalysis\\deal\\data\\AES\\", s)  # 把获取的文件路径整合
        f1 = open(newDir)
        line = f1.read()
        Cryptogram.append(line)
        Label.append(1)
            # sheet.write(i, 0, str(line))
          # i = i + 1
    print(i)
    return Cryptogram,Label



if __name__ == '__main__':
    #key = keyGenerater(16)
    #print(key)
    key = "6PyEDp4xmNyceVCf"
    #dirpath_AES = "E:\\dataAnalysis\\Plaintext\\data\\bc\\AES"
    #filepath_AES ="E:\\dataAnalysis\\ciphertext\\data\\bc\\AES\\AES_"
    #dirpath_DES = "E:\\dataAnalysis\\Plaintext\\data\\bc\\\DES"
    #filepath_DES = "E:\\dataAnalysis\\ciphertext\\data\\bc\\\DES\\DES_"
    #dirpath_DES3 = "E:\\dataAnalysis\\Plaintext\\data\\DES3"
    #filepath_DES3 = "E:\\dataAnalysis\\ciphertext\\data\\DES3\\DES3_"
    #dirpath_01_AES = "E:\\dataAnalysis\\Plaintext\\data\\bc\\01\\AES"
    #filepath_01_AES = "E:\\dataAnalysis\\ciphertext\\data\\bc\\01\\AES\\AES_"
    #dirpath_01_DES = "E:\\dataAnalysis\\Plaintext\\data\\bc\\01\\DES"
    #filepath_01_DES = "E:\\dataAnalysis\\ciphertext\\data\\bc\\01\\DES\\DES_"
    #明文
    dirpath_NIST_Plaintext = "E:\\pycharm_workspace\\dataanalysis\\new\\1KB_randomPlainText"
    #AES加密密文
    filepath_NIST_AES = "E:\\pycharm_workspace\\dataanalysis\\ciphertext\\NIST\\AES\\AES_"
    #3DES加密密文
    filepath_NIST_3DES = "E:\\pycharm_workspace\\dataanalysis\\ciphertext\\NIST\\3DES\\3DES_"
    #Blowfish加密密文
    filepath_NIST_Blowfish = "E:\\pycharm_workspace\\dataanalysis\\ciphertext\\NIST\\Blowfish\\Blowfish_"
    #CAST加密密文
    filepath_NIST_CAST = "E:\\pycharm_workspace\\dataanalysis\\ciphertext\\NIST\\CAST\\CAST_"
    #ARC2加密密文
    filepath_NIST_ARC2 = "E:\\pycharm_workspace\\dataanalysis\\ciphertext\\NIST\\RC2\\RC2_"
    #ARC4加密密文
    filepath_NIST_ARC4 = "E:\\pycharm_workspace\\dataanalysis\\ciphertext\\NIST\\RC4\\RC4_"
    #SM4加密密文
    filepath_NIST_SM4 = "E:\\pycharm_workspace\\dataanalysis\\ciphertext\\NIST\\SM4\\SM4_"
    #createFile(key,dirpath_NIST_Plaintext,filepath_NIST_SM4)
    #createFile(key,dirpath_AES,filepath_AES)
    #deal()
    #s='4f2158ba903dc84c954335facbe73790687dce9ffbb13fce1d438b7e01443f0e07a5ced79e4b82c2a2531eb87fa350e49e52704816eaee84c23c56591dd1fcefd5d41ce807b80863afa7da3dfcf3720a19f01a6e820ef3b12bf0f847b28055f291f31b644ab55d2949937a5b06db5798b4d6b0140c661ec57c844b401adb022af2c2c0208a3e2bbd2119aba07131f80a72ad71a7f8d8f7f9436170a332621178455f8b6e080360cf7216c82685c982f7be3ae02f7deaf12a0dedb04efedfceecb37a34849dd18cc1d2183aacfa2e83a304986a18b19e1985be2cd0ff1967102de07a6665ce771b0298c127b1913c7ef9db511fc98bfe519a4bdc1177b16a47abd6929de6625c3e3d4cca900b871c19cc6d9fe6cecca1cc22cf1ac214262ebc09ac7aca989f016dcb23893430bc47c33d406774ed1f99d12b14267cd6296f04773ca69b2f1d81cf2d5338b6aa1468659b48b4e12e567b671f39ed8051ee5bddc1fabecd584e9da4e8c90003040b48be8df8c921c9cb35106ee4f64ab6a0a8a733f20f3b466c23b8b77bc4e5b2a4505b7983d8cd91ee1ff0bfefb7421db74f67cfb8e8ffc8404b572d3b484098b1cdbe0d4593c79aea03ef3c125f2c0a9e3e9e2a4176ad3c782902d5bc4b2157c4f4078b6b6f2abf508f9dd7d26012ec86b3d0961cbb8a6b52b07e3eb0350db8e026e97aeb33c4826242c189ef081ea2202bc2d725e58c68d5d5c08512a560de7df4103392c0866ec0a0847cf9e04a46816b466ae972a3b000eada7c55df4a9020e1399dda750b24aedb1fb5a1603eee710fc3f912b9631f56f267cd58878bdddb35725a4950591e19da145c76b48d422f7df4ed1dc6c7bb7939f54a1ef0eb4f6c4c7c13cb9c7177e69aeb2f19341025de4ea70a9d2d8bbfcf5017c10829889f8339333d770cf7d1e5b4d325a0b1fd4462cb5749b5b8b3a8cc278a1dae228d7db434a7c1a19197a02b275e260208f18343b35979cf6248c13c06d2646aaf0748f3dd2aefbce5f022c5e7da17f3f09fb65cb9fe0dfd119d748c37f32371aa9de288adb121c04684e1671d51093e820e2d317935a0612b361ead0540de7d62ef30067bceec8f2856df5b5e9e4effd98735ed44d31b00cf328c89fa6788100ecb49add964107a0c239de254078a39f9afb1ba4d269837893aa5b17a2bf7f0a3e322664b909af4e16fa93f49fed97ea22f5a033e28cf9cb8ed58dcd2cad111176e394d4404c45b9f9a83801bd09205a5a67a03721367f52b9c9ae7234c5429d73b5bb090fd724880307868c55e4ac0d01ca909ca4e08e876e34fa5ab9df9988185778ac118403d98d4c2e90527dbae9e45ffb47b7aea66c33291b2e054d7130412861eab8c3931e9b595573cdb2031220b49c239196b7516ad826562a6151b0dc191c204c8f3dd7e6b746bfbc6c4a80de4bddd14900995254b07d783e0a5825c18afce9b9c65'
    #print(' '.join([bin(ord(c)).replace('0b', '') for c in s]))

    #Cryptogram, Label = readExcelToList()
    #print(Cryptogram)
    #print(Label)
    #dataset = {}
   # dataset = dict(zip(Cryptogram,Label))
    #print('字典Cryptogram的值对应字典Label的值输出：', dataset)
    writeFilePath = 'E:\\pycharm_workspace\\dataanalysis\\cvs\\NIST_data_SM4.xls'
    writeDirPath = "E:\\pycharm_workspace\\dataanalysis\\ciphertext\\NIST\\SM4\\"
    writeExcel(writeFilePath,writeDirPath)
