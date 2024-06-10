# PadAttacker
A simple python tool for automatically perfoming padding oracle attacks. 

This tool is still in development and currently only supports the decrypt() method. The encrypt() method should be implemented soon. Any feedback, as well as suggestions, is welcome and appreciated.

## Usage
Create a PaddingOracle object. This object has three properties: PaddingOracle.ciphertext (given in bytes), PaddingOracle.oracle, and PaddingOracle.blockSize. The oracle function specified should return True if the ciphertext passed to it is padded correctly, and False if not.

## Example usage
```
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
```
```
[*] Starting padding oracle attack
[*] Ciphertext: c43bf9131048c8c2eeb8aa2b5183209eee86a7cae9bb50f2c74c00572d5be4c927f5a87f16ac3e009d324f130d3e8a54c0629e7e669c632b40928df238db41decfe3befdcc99b8155effd52c0550baa3fa3f761f8b71f9492c2cbda190db1a59ce190ae824e543a53f21851b4457e57690e5a25fa60874d989923e6bb30c2e4d
[*] Attack complete
[*] Decrypted ciphertext: b'This is a demonstration of PadAttacker, a tool for automating padding oracle attacks, written in Python.\x08\x08\x08\x08\x08\x08\x08\x08'
```
### Disclaimer
PadAttacker is a tool designed exclusively for use in Capture The Flag (CTF) competitions and educational purposes. It is not intended for any illegal or malicious activities. The creators and distributors of PadAttacker do not condone or support the use of this tool for unauthorized access or any activities that violate applicable laws and regulations. Users are responsible for ensuring that their use of PadAttacker complies with all relevant legal requirements
