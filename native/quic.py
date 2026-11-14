"""QUIC v1 Initial inspection using RFC 9001 and the TV's existing OpenSSL.

Only public Initial keys are derived. Application traffic is never decrypted.
Unknown versions, invalid authentication and unsupported frames pass unchanged.
"""
import binascii
import ctypes
import hashlib
import hmac
import os
import struct


def expand(secret,label,size):
    label=b'tls13 '+label
    info=struct.pack('!H',size)+bytes(bytearray([len(label)]))+label+b'\x00'
    return hmac.new(secret,info+b'\x01',hashlib.sha256).digest()[:size]


class Crypto(object):
    def __init__(self):
        self.lib=ctypes.CDLL('libcrypto.so.1.0.0')
        p=ctypes.c_void_p; i=ctypes.c_int; s=ctypes.c_char_p
        signatures={
            'EVP_CIPHER_CTX_new':(p,[]),'EVP_CIPHER_CTX_free':(None,[p]),
            'EVP_aes_128_ecb':(p,[]),'EVP_aes_128_gcm':(p,[]),
            'EVP_CIPHER_CTX_set_padding':(i,[p,i]),'EVP_CIPHER_CTX_ctrl':(i,[p,i,i,p]),
            'EVP_EncryptInit_ex':(i,[p,p,p,s,s]),'EVP_DecryptInit_ex':(i,[p,p,p,s,s]),
            'EVP_EncryptUpdate':(i,[p,p,ctypes.POINTER(i),s,i]),'EVP_DecryptUpdate':(i,[p,p,ctypes.POINTER(i),s,i]),
            'EVP_EncryptFinal_ex':(i,[p,p,ctypes.POINTER(i)]),'EVP_DecryptFinal_ex':(i,[p,p,ctypes.POINTER(i)])}
        for name,(ret,args) in signatures.items():
            f=getattr(self.lib,name); f.restype=ret; f.argtypes=args

    def mask(self,key,sample):
        lib=self.lib; ctx=lib.EVP_CIPHER_CTX_new()
        try:
            out=ctypes.create_string_buffer(32); n=ctypes.c_int()
            if lib.EVP_EncryptInit_ex(ctx,lib.EVP_aes_128_ecb(),None,key,None)!=1: raise ValueError('AES init')
            lib.EVP_CIPHER_CTX_set_padding(ctx,0)
            if lib.EVP_EncryptUpdate(ctx,out,ctypes.byref(n),sample,len(sample))!=1: raise ValueError('AES update')
            return out.raw[:n.value]
        finally: lib.EVP_CIPHER_CTX_free(ctx)

    def gcm(self,key,nonce,header,data,encrypt=False):
        lib=self.lib; ctx=lib.EVP_CIPHER_CTX_new()
        try:
            init=lib.EVP_EncryptInit_ex if encrypt else lib.EVP_DecryptInit_ex
            update=lib.EVP_EncryptUpdate if encrypt else lib.EVP_DecryptUpdate
            final=lib.EVP_EncryptFinal_ex if encrypt else lib.EVP_DecryptFinal_ex
            if init(ctx,lib.EVP_aes_128_gcm(),None,None,None)!=1: raise ValueError('GCM init')
            if lib.EVP_CIPHER_CTX_ctrl(ctx,0x9,len(nonce),None)!=1: raise ValueError('GCM IV')
            if init(ctx,None,None,key,nonce)!=1: raise ValueError('GCM key')
            n=ctypes.c_int(); out=ctypes.create_string_buffer(len(data)+32)
            if update(ctx,None,ctypes.byref(n),header,len(header))!=1: raise ValueError('GCM AAD')
            body=data if encrypt else data[:-16]
            if not encrypt:
                tag=ctypes.create_string_buffer(data[-16:])
                if lib.EVP_CIPHER_CTX_ctrl(ctx,0x11,16,tag)!=1: raise ValueError('GCM tag')
            if update(ctx,out,ctypes.byref(n),body,len(body))!=1: raise ValueError('GCM body')
            length=n.value
            if final(ctx,ctypes.byref(out,length),ctypes.byref(n))!=1: raise ValueError('QUIC authentication failed')
            result=out.raw[:length+n.value]
            if encrypt:
                tag=ctypes.create_string_buffer(16)
                if lib.EVP_CIPHER_CTX_ctrl(ctx,0x10,16,tag)!=1: raise ValueError('GCM get tag')
                result+=tag.raw
            return result
        finally: lib.EVP_CIPHER_CTX_free(ctx)


def varint(data,p):
    b=bytearray(data)
    if p>=len(b): raise ValueError('short QUIC varint')
    length=1<<(b[p]>>6)
    if p+length>len(b): raise ValueError('short QUIC varint body')
    value=b[p]&63
    for j in range(1,length): value=(value<<8)+b[p+j]
    return value,p+length


class Initial(object):
    def __init__(self): self.crypto=Crypto()

    def decode(self,data):
        b=bytearray(data)
        if len(b)<24 or b[0]&0xf0!=0xc0 or data[1:5]!=b'\x00\x00\x00\x01': return None
        n=b[5]
        if n>20 or len(b)<7+n: return None
        dcid=data[6:6+n]; p=6+n
        n=b[p]; p+=1
        if n>20: return None
        p+=n
        token,p=varint(data,p); p+=token
        length,p=varint(data,p)
        if p+length>len(data) or length<20: return None
        end=p+length
        salt=binascii.unhexlify(b'38762cf7f55934b34d179ae6a4c80cadccbb7f0a')
        secret=hmac.new(salt,dcid,hashlib.sha256).digest()
        client=expand(secret,b'client in',32)
        key=expand(client,b'quic key',16); iv=expand(client,b'quic iv',12); hp=expand(client,b'quic hp',16)
        mask=bytearray(self.crypto.mask(hp,data[p+4:p+20]))
        b[0]^=mask[0]&15
        pnlen=(b[0]&3)+1
        number=0
        for j in range(pnlen):
            b[p+j]^=mask[j+1]; number=(number<<8)+b[p+j]
        nonce=bytearray(iv)
        for j in range(8): nonce[11-j]^=(number>>(8*j))&255
        header=bytes(b[:p+pnlen])
        plain=self.crypto.gcm(key,bytes(nonce),header,data[p+pnlen:end])
        chunks=[]; q=0
        while q<len(plain):
            kind,q=varint(plain,q)
            if kind in (0,1): continue
            if kind in (2,3):
                largest,q=varint(plain,q); delay,q=varint(plain,q)
                count,q=varint(plain,q); first,q=varint(plain,q)
                if count>256: raise ValueError('ACK range bound')
                for _ in range(count*2): _,q=varint(plain,q)
                if kind==3:
                    for _ in range(3): _,q=varint(plain,q)
                continue
            if kind==6:
                offset,q=varint(plain,q); size,q=varint(plain,q)
                if offset+size>32768 or q+size>len(plain): raise ValueError('CRYPTO frame bound')
                chunks.append((offset,plain[q:q+size])); q+=size
                continue
            break
        return {'dcid':binascii.hexlify(dcid).decode(),'chunks':chunks,'plain':plain,'header':header,'key':key,'nonce':bytes(nonce),'hp':hp,'pn_offset':p}

    def reseal_test(self,decoded,plain):
        """Used only by the on-device wire test to change SNI in a supplied Initial."""
        header=decoded['header']
        data=bytearray(header+self.crypto.gcm(decoded['key'],decoded['nonce'],header,plain,True))
        p=decoded['pn_offset']
        mask=bytearray(self.crypto.mask(decoded['hp'],bytes(data[p+4:p+20])))
        pnlen=(data[0]&3)+1
        data[0]^=mask[0]&15
        for j in range(pnlen): data[p+j]^=mask[j+1]
        return bytes(data)
