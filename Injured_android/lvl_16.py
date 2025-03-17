from base64 import b64decode
from Crypto.Cipher import DES

key = b"{Captur3Th1sToo}"[:8]
ciphertext = b64decode("kOC6ZrdMXEnfIKWihcBNLTWIhDiINUfSQyYrFsTpEBGZy1KmfPMTwtba8CXa/WVAVoJ1ACvJMd8f/MF97/7UaeNCQvC9OD4lZ/vQN6LmpBU=")
cipher = DES.new(key, DES.MODE_ECB)

plaintext = cipher.decrypt(ciphertext)

pad_len = plaintext[-1]
if all(p == pad_len for p in plaintext[-pad_len:]):
    plaintext = plaintext[:-pad_len]

print(plaintext.decode("utf-8"))


key = b"Captur3Th1s"[:8]
ciphertext = b64decode("+D8wTKFawdpzDeaQweqRF9JrNCJIBc9xR+mQXdIwIj+jYtTA3uVc+g8K68YFw7QMFCc8sbDwXL8=")
cipher = DES.new(key, DES.MODE_ECB)

plaintext = cipher.decrypt(ciphertext)

pad_len = plaintext[-1]
if all(p == pad_len for p in plaintext[-pad_len:]):
    plaintext = plaintext[:-pad_len]

print(plaintext.decode("utf-8"))
