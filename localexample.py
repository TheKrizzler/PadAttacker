import padattacker
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b'supersecretkey42' # Key specified for oracle function

def decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext[16:])
    return decrypted

def oracleFunction(ciphertext):
    try:
        decrypted_data = decrypt(ciphertext, key)
        unpad(decrypted_data, AES.block_size)
        return True
    except ValueError:
        return False

exampleCiphertext = bytes.fromhex("c43bf9131048c8c2eeb8aa2b5183209eee86a7cae9bb50f2c74c00572d5be4c927f5a87f16ac3e009d324f130d3e8a54c0629e7e669c632b40928df238db41decfe3befdcc99b8155effd52c0550baa3fa3f761f8b71f9492c2cbda190db1a59ce190ae824e543a53f21851b4457e57690e5a25fa60874d989923e6bb30c2e4d")
attack = padattacker.PaddingOracle(ciphertext=exampleCiphertext, oracle=oracleFunction)

attack.decrypt()