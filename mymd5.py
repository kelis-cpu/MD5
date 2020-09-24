import struct
from enum import Enum
from math import(floor,sin)
from bitarray import bitarray
import hashlib #用于验证hash算法是否正确
from iv import MD5Buffer

class MD5Buffer(Enum):
    A=0x67452301
    B=0xEFCDAB89
    C=0x98BADCFE
    D=0X10325476
class MD5(object):
    _string=None
    _buffers={
    MD5Buffer.A:None,
    MD5Buffer.B:None,
    MD5Buffer.C:None,
    MD5Buffer.D:None,
    }
    @classmethod
    def hash(cls,string):
        cls._string=string
        pro=cls._step_2(cls._step_1())
        cls._step_3()
        cls._step_4(pro)
        return cls._step_5()
    @classmethod
    def _step_1(cls):
        bit_array=bitarray(endian="big")
        bit_array.frombytes(cls._string.encode('utf-8'))
        bit_array.append(1)
        while len(bit_array)%512!=448:
            bit_array.append(0)
        return bitarray(bit_array,endian="little")
    @classmethod
    def _step_2(cls,step_1_result):
        length=(len(cls._string)*8)%pow(2,64)
        length_bit_array=bitarray(endian='little')
        length_bit_array.frombytes(struct.pack('<Q',length))
        result=step_1_result.copy()
        result.extend(length_bit_array)
        return result
    @classmethod
    def _step_3(cls):
        for buffer_type in cls._buffers.keys():
            cls._buffers[buffer_type]=buffer_type.value
    @classmethod
    def _step_4(cls,step_2_result):
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
            A=cls._buffers[MD5Buffer.A]
            B=cls._buffers[MD5Buffer.B]
            C=cls._buffers[MD5Buffer.C]
            D=cls._buffers[MD5Buffer.D]
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
            cls._buffers[MD5Buffer.A]=modular_add(A,cls._buffers[MD5Buffer.A])
            cls._buffers[MD5Buffer.B]=modular_add(B,cls._buffers[MD5Buffer.B])
            cls._buffers[MD5Buffer.C]=modular_add(C,cls._buffers[MD5Buffer.C])
            cls._buffers[MD5Buffer.D]=modular_add(D,cls._buffers[MD5Buffer.D])
    @classmethod
    def  _step_5(cls):
        A = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5Buffer.A]))[0]
        B = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5Buffer.B]))[0]
        C = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5Buffer.C]))[0]
        D = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5Buffer.D]))[0]
        return f"{format(A, '08x')}{format(B, '08x')}{format(C, '08x')}{format(D, '08x')}"
if __name__ == '__main__':
    msg=input()
    md5str=MD5.hash(msg)
    print("MyMD5加密结果:"+md5str)
    print("hashlib加密结果:"+hashlib.md5(msg.encode('utf-8')).hexdigest())

