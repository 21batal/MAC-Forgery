#!/usr/bin/env python
# coding: utf-8

# In[3]:


import hashlib
import hmac

class SecureHMACServer:
    def __init__(self):
        self.SECRET_KEY = b''

    def input_secret_key(self):
        print("\n" + "="*50)
        print(" SECURE HMAC-MD5 SERVER SETUP ".center(50, '='))
        while True:
            key = input("\n[SETUP] Enter SECRET_KEY: ").strip()
            if key:
                self.SECRET_KEY = key.encode()
                print(f"[CONFIG] Using key: {key} ({len(self.SECRET_KEY)} bytes)")
                break
            print("[ERROR] Key cannot be empty")

    def hmac_md5(self, msg_bytes):
        return hmac.new(self.SECRET_KEY, msg_bytes, hashlib.md5).hexdigest()

    def verify_hmac(self, msg_bytes, mac_hex):
        expected = self.hmac_md5(msg_bytes)
        print("\n[VERIFICATION]")
        print(f"  Expected: {expected}")
        print(f"  Received: {mac_hex}")
        return hmac.compare_digest(mac_hex, expected)

    def run(self):
        self.input_secret_key()

        print("\n" + "="*50)
        print(" MESSAGE CONFIGURATION ".center(50, '='))
        orig_msg = input("\n[MESSAGE] Enter original message: ").strip()
        orig_msg_bytes = orig_msg.encode()
        orig_mac = self.hmac_md5(orig_msg_bytes)

        print("\n" + "-"*50)
        print(" SERVER OUTPUT ".center(50, '-'))
        print(f"  Key Length: {len(self.SECRET_KEY)} bytes")
        print(f"  Message: {orig_msg}")
        print(f"  HMAC: {orig_mac}")

        print("\n[TEST] Verifying original message...")
        if self.verify_hmac(orig_msg_bytes, orig_mac):
            print("[RESULT] Valid HMAC - message authenticated")
        else:
            print("[ALERT] Verification failed!")

        print("\n" + "="*50)
        print(" ATTACK SIMULATION ".center(50, '='))
        while True:
            try:
                forged_hex = input("\n[ATTACK] Forged message (hex): ").strip()
                forged_bytes = bytes.fromhex(forged_hex)
                break
            except ValueError:
                print("[ERROR] Invalid hex input")

        forged_mac = input("[ATTACK] Forged HMAC (hex): ").strip()

        print("\n[VERIFICATION]")
        print(f"  Forged Message: {forged_bytes}")
        print(f"  Forged HMAC: {forged_mac}")

        if self.verify_hmac(forged_bytes, forged_mac):
            print("\n[RESULT] ATTACK FAILED (expected)")
        else:
            print("\n[RESULT] SECURITY BREACH!")

if __name__ == "__main__":
    server = SecureHMACServer()
    server.run()


# In[ ]:




