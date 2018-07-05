#!/usr/bin/env python
"""
Cryptography URI Locator Key
cilok.py 
created by Rolly Maulana Awangga

"""
from pbkdf2 import PBKDF2
import config
from Crypto.Cipher import AES

	
def tailfill(ln):
               chars=[]
               for i in range(ln):
                       chars.append("X")
               return "".join(chars)

def urlEncode16(uri):
	ln = len(uri)
	multihex = (ln//16)*16+16
	sp = multihex - ln - len(str(ln))
	if ln>9:
		dt = str(ln)+uri+tailfill(sp)
	else:
		dt = "0"+str(ln)+uri+tailfill(sp-1)
	return encodeData16(dt)

def encodeData16(msg):
	key=PBKDF2(config.passphrase,config.salt).read(32)
	obj=AES.new(key,AES.MODE_CBC,config.iv)
	cp = obj.encrypt(msg)
	return cp.hex()#.encode("hex")


