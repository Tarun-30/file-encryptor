from cryptography.fernet import Fernet
import os

# Generate and save key
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Load existing key
def load_key():
    return open("secret.key", "rb").read()

# Encrypt file
def encrypt_file(filename, key):
    f = Fernet(key)
    
    with open(filename, "rb") as file:
        file_data = file.read()
    
    encrypted_data = f.encrypt(file_data)
    
    with open(filename + ".enc", "wb") as file:
        file.write(encrypted_data)
    
    print(f"[+] File encrypted: {filename}.enc")

# Decrypt file
def decrypt_file(filename, key):
    f = Fernet(key)
    
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    
    decrypted_data = f.decrypt(encrypted_data)
    
    output_file = filename.replace(".enc", "")
    
    with open(output_file, "wb") as file:
        file.write(decrypted_data)
    
    print(f"[+] File decrypted: {output_file}")

# Main menu
def main():
    print("=== File Encryption Tool ===")
    print("1. Generate Key")
    print("2. Encrypt File")
    print("3. Decrypt File")
    
    choice = input("Enter your choice: ")

    if choice == "1":
        generate_key()
        print("[+] Key generated and saved as secret.key")

    elif choice == "2":
        filename = input("Enter file name to encrypt: ")
        if not os.path.exists("secret.key"):
            print("[-] Key not found! Generate key first.")
            return
        key = load_key()
        encrypt_file(filename, key)

    elif choice == "3":
        filename = input("Enter file name to decrypt (.enc): ")
        if not os.path.exists("secret.key"):
            print("[-] Key not found!")
            return
        key = load_key()
        decrypt_file(filename, key)

    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()