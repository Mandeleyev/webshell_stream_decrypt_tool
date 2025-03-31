from urllib.parse import unquote
import re
import base64
import gzip
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#webshell涉及到的解密算法
def XOR(cipher,key):
    cipher = bytearray(cipher)
    for i in range(len(cipher)):
        key_stream=key[i+1&15]
        cipher[i]=cipher[i]^key_stream
    return cipher

'''def Godzilla_decrypt(request_body):'''
def AES_decrypt_in_ECB_mode(ciphertext,key):#明文以字节形式输入
    cipher=AES.new(key,AES.MODE_ECB)
    plaintext_bytes=cipher.decrypt(ciphertext)
    plaintext=unpad(plaintext_bytes,AES.block_size)
    return plaintext#输出字节，要decode


#哥斯拉流量请求体返回体解密
#php
#请求体
def php_xor_base64(body,key):#php_xor_base64模式下key不暴露在流量中的
    try:
        pattern=r"(?<==).*$"
        encrypted_body=re.findall(pattern,body)[0]
        decrypted_body=XOR(base64.b64decode(unquote(encrypted_body)),key.encode()).decode('utf-8')
        return decrypted_body
    except:
        decrypted_body=gzip.decompress(XOR(base64.b64decode(unquote(encrypted_body)),key.encode())).decode('utf-8')
        return decrypted_body
def php_eval_xor_base64(body):
    try:
        pattern=r"'(.*?)'"#这个pattern提取引号之间的内容
        pattern2=r"(?<==).*$"#提取等号后面的内容
        pattern3=r"[0-9a-f]{16}"#提取xor的密钥
        unquoted_body=unquote(body)
        body_ls=unquoted_body.split("&") #把body内容划分为shell与其实际执行的操作
        encoded_script=re.findall(pattern,body_ls[0])[0]
        encrypted_execution=re.findall(pattern2,body_ls[1])[0]
        webshell_script=base64.b64decode(encoded_script[::-1]).decode('utf-8')
        xor_key=re.findall(pattern3,webshell_script)[0].encode()#从shell中提取key        
        shell_execution=XOR(base64.b64decode(unquote(encrypted_execution)),xor_key).decode('utf-8')#xor shell的操作内容
        return webshell_script,shell_execution
    except:
        shell_execution=gzip.decompress(XOR(base64.b64decode(unquote(encrypted_execution)),xor_key)).decode('utf-8')#xor shell的操作内容
        return webshell_script,shell_execution
#raw的加解密是通用的        
def php_xor_raw(body,key,encode):#php_xor_raw和php_base64的response不一样的地方在于其首尾没有两段md5的一半拼接；输入的数据是hex字串格式的
    try:
        decrypted_body=XOR(bytes.fromhex(body),key.encode()).decode('utf-8')
        return decrypted_body
    except:
        decrypted_body=gzip.decompress(XOR(bytes.fromhex(body),key.encode())).decode(encode)
        return decrypted_body
#响应体
def php_base64_response(body,key,encode):
    encrypted_body=body[16:len(body)-16]
    decrypted_body=gzip.decompress(XOR(base64.b64decode(encrypted_body),key.encode())).decode(encode)
    return decrypted_body

#jsp
#请求体
def java_aes_base64(body,key,encode):
    try:
        pattern=r"(?<==).*$"
        encrypted_body=re.findall(pattern,body)[0]
        decrypted_body=AES_decrypt_in_ECB_mode(base64.b64decode(unquote(encrypted_body)),key.encode()).decode(encode)
        return decrypted_body
    except:
        decrypted_body=gzip.decompress(AES_decrypt_in_ECB_mode(base64.b64decode(unquote(encrypted_body)),key.encode())).decode(encode)
        return decrypted_body
def java_aes_raw(body,key,encode):
    try:
        decrypted_body=AES_decrypt_in_ECB_mode(bytes.fromhex(body),key.encode()).decode(encode)
        return decrypted_body
    except:
        decrypted_body=gzip.decompress(AES_decrypt_in_ECB_mode(bytes.fromhex(body),key.encode())).decode(encode)
        return decrypted_body        
#响应体
def java_aes_base64_response(body,key,encode):
    encrypted_body=body[16:len(body)-16]
    decrypted_body=gzip.decompress(AES_decrypt_in_ECB_mode(base64.b64decode(encrypted_body),key.encode())).decode(encode)
    return decrypted_body

#冰蝎流量解密(冰蝎似乎不同的语言产生的请求体和响应体是相同的)
def default_aes(body,key,encode):
    oringinal_msg=AES_decrypt_in_ECB_mode(base64.b64decode(body),key.encode()).decode(encode)
    return oringinal_msg
def aes_with_magic(body,key,encode):#因为复制非ascii字符容易出问题，这里输入hex串的原始数据
    body_without_magic=body[0:-2*(int(key[0:2],16)%16)]
    oringinal_msg=AES_decrypt_in_ECB_mode(base64.b64decode(bytes.fromhex(body_without_magic).decode()),key.encode()).decode(encode)
    return oringinal_msg
def default_xor_base64(body,key):
    try:
        return XOR(base64.b64decode(body),key.encode()).decode()
    except:
        return gzip.decompress(XOR(base64.b64decode(body),key.encode())).decode()
def default_xor(body,key):
    try:
        return XOR(bytes.fromhex(body),key.encode()).decode()
    except:
        return gzip.decompress(XOR(bytes.fromhex(body),key.encode())).decode()

if __name__=="__main__":#功能测试
    key='e45e329feb5d925b'
    print(aes_with_magic(body,key,'latin-1'))
