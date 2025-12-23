from Crypto.Cipher import AES
import binascii

def decrypt_file(input_path, output_path):
    # AES-256 key and IV (must match export_results)
    KEY_HEX = "df1691257d753ffc96f06edec78116182607c1ff3973ed7e3bb035bce871f1bb"
    IV_HEX = "f191c79a6ab0f7be391eb1f2407a2074"

    key = binascii.unhexlify(KEY_HEX)   # 32 bytes
    iv = binascii.unhexlify(IV_HEX)     # 16 bytes

    # Read encrypted data
    with open(input_path, "rb") as f:
        ciphertext = f.read()

    # Decrypt with AES-CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(ciphertext)

    # Remove PKCS#7 padding
    pad_len = data[-1]
    data = data[:-pad_len]

    # Save decrypted CSV
    with open(output_path, "wb") as f:
        f.write(data)

    print(f"File decrypted successfully and saved as: {output_path}")


if __name__ == "__main__":
    decrypt_file("election_results.aes", "decrypted_results.csv")
