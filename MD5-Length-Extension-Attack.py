import struct
from math import(floor,sin)
from bitarray import bitarray
import hashlib #用于验证hash算法是否正确
import urllib.parse
import sys
class MD5():
    def __init__(self):
        self.A,self.B,self.C,self.D=(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
        self._string=""
        self.length=0
    def hash(self):
        pro=self.step_2(self.step_1())
        self.step_4(pro)
        return self.step_5()
    # @classmethod
    def step_1(self):
        bit_array=bitarray(endian="big")
        bit_array.frombytes(self._string.encode('utf-8'))
        bit_array.append(1)
        while len(bit_array)%512!=448:
            bit_array.append(0)
        return bitarray(bit_array,endian="little")
    # @classmethod
    def step_2(self,step_1_result):
        length=(len(self._string)*8+self.length)%pow(2,64)
        length_bit_array=bitarray(endian='little')
        length_bit_array.frombytes(struct.pack('<Q',length))
        result=step_1_result.copy()
        result.extend(length_bit_array)
        return result
    def step_4(self,step_2_result):
        F=lambda x,y,z:(x&y)|(~x&z)
        G=lambda x,y,z:(x&z)|(y&~z)
        H=lambda x,y,z:x^y^z
        I=lambda x,y,z:y^(x|~z)
        rotate_left=lambda x,n:(x<<n)|(x>>(32-n)) #左循环移位函数
        modular_add=lambda a,b:(a+b)%pow(2,32)    #模2^32加法
        T=[floor(pow(2,32)*abs(sin(i+1)))for i in range(64)]
        N=len(step_2_result)//32 #消息的总字数
        for chunk_index in range(N//16): #512bit分组数
            start=chunk_index*512
            X=[step_2_result[start+(x*32):start+(x*32)+32]for x in range(16)]#连续的16个字
            X=[int.from_bytes(word.tobytes(),byteorder="little")for word in X]#将每一个字从byte转化为int
            A=self.A
            B=self.B
            C=self.C
            D=self.D
            for i in range(64):
                if 0<=i<=15:
                    k=i
                    s=[7,12,17,22]
                    temp=F(B,C,D)
                elif 16<=i<=31:
                    k=(1+5*i)%16
                    s=[5,9,14,20]
                    temp=G(B,C,D)
                elif 32<=i<=47:
                    k=(5+3*i)%16
                    s=[4,11,16,23]
                    temp=H(B,C,D)
                elif 48<=i<=63:
                    k=(7*i)%16
                    s=[6,10,15,21]
                    temp=I(B,C,D)
                temp=modular_add(temp,X[k])
                temp=modular_add(temp,T[i])
                temp=modular_add(temp,A)
                temp=rotate_left(temp,s[i%4])
                temp=modular_add(temp,B)
                A=D
                D=C
                C=B
                B=temp
            self.A=modular_add(A,self.A)
            self.B=modular_add(B,self.B)
            self.C=modular_add(C,self.C)
            self.D=modular_add(D,self.D)
    def  step_5(self):
        A = struct.unpack("<I", struct.pack(">I", self.A))[0]
        B = struct.unpack("<I", struct.pack(">I", self.B))[0]
        C = struct.unpack("<I", struct.pack(">I", self.C))[0]
        D = struct.unpack("<I", struct.pack(">I", self.D))[0]
        return f"{format(A, '08x')}{format(B, '08x')}{format(C, '08x')}{format(D, '08x')}"
    def comput_magic_number(self,md5str):
        self.A=struct.unpack('I',bytes.fromhex(md5str[0:8]))[0]
        self.B=struct.unpack('I',bytes.fromhex(md5str[8:16]))[0]
        self.C=struct.unpack('I',bytes.fromhex(md5str[16:24]))[0]
        self.D=struct.unpack('I',bytes.fromhex(md5str[24:32]))[0]
        # print('A=%s\nB=%s\nC=%s\nD=%s\n' % (hex(self.A), hex(self.B), hex(self.C), hex(self.D)))
    def extension_attack(self,md5str,str_append,length):
        self.comput_magic_number(md5str)
        self._string=str_append
        self.length=length
        md5=self.hash()
        return md5
def payload(length,str_append):
    pad = ''
    n0 = ((56 - (length + 1) % 64) % 64)
    pad += '\x80'
    pad += '\x00'*n0 +struct.pack('Q', length*8).decode('utf-8')
    return pad + str_append
if len(sys.argv) < 3:
    print("Usage: ", sys.argv[0], " <md5string> <string_to_append> [length of plaintext of md5string]")
    sys.exit()
msg=sys.argv[1]
str_append=sys.argv[2]
length=int(sys.argv[3])
payload=payload(length,str_append)
print("payload"+repr(payload))
print("urlencode-payload:"+urllib.parse.quote_plus(payload)[3:])
length=len(payload)*8-len(str_append)*8+length*8
m2=MD5()
s=m2.extension_attack(md5str=msg,str_append=str_append,length=length)
print("md5:"+s)


