#!/usr/bin/env python3
import os
import sys
import json
import base64
import getpass
import secrets
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
from web3.middleware import geth_poa_middleware

# Constants for file names and key derivation
PRIVATE_KEY_FILE = "user_private_key.enc"
KDF_ITERATIONS = 100000

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a symmetric key from a passphrase and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode())

def encrypt_private_key(private_key_bytes: bytes, passphrase: str) -> bytes:
    """
    Encrypt the private key using AES-GCM.
    Output layout: salt (16 bytes) | nonce (12 bytes) | ciphertext.
    """
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, private_key_bytes, None)
    return salt + nonce + ciphertext

def decrypt_private_key(encrypted_data: bytes, passphrase: str) -> bytes:
    """
    Decrypt the private key. Assumes the first 16 bytes are the salt,
    the next 12 bytes are the nonce, and the rest is the ciphertext.
    """
    try:
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        key = derive_key(passphrase, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError("Failed to decrypt private key. Incorrect passphrase or corrupted file.") from e

def generate_and_store_private_key(passphrase: str):
    """Generate a new Ethereum private key, encrypt it, and store it locally."""
    account = Account.create()  # Generate new account
    private_key = account.privateKey  # bytes
    encrypted = encrypt_private_key(private_key, passphrase)
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(encrypted)
    print("New private key generated and stored securely.")
    print("Your account address is:", account.address)
    return account

def load_private_key(passphrase: str):
    """Load and decrypt the stored private key."""
    if not os.path.exists(PRIVATE_KEY_FILE):
        raise FileNotFoundError("Private key file not found. Run the script to generate one first.")
    with open(PRIVATE_KEY_FILE, "rb") as f:
        encrypted_data = f.read()
    private_key_bytes = decrypt_private_key(encrypted_data, passphrase)
    account = Account.from_key(private_key_bytes)
    return account

def sign_message(account, message: str) -> str:
    """
    Sign the message using the user's private key.
    Returns a hexadecimal representation of the signature.
    """
    message_encoded = encode_defunct(text=message)
    signed_message = Account.sign_message(message_encoded, private_key=account.privateKey)
    return signed_message.signature.hex()

def encrypt_with_tee_public_key(message: str, tee_public_key_pem: str) -> str:
    """
    Encrypt the message using the provided TEE public key (PEM format)
    via RSA-OAEP. Returns the encrypted message as a base64 string.
    """
    try:
        public_key = serialization.load_pem_public_key(tee_public_key_pem.encode())
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        raise ValueError("Failed to encrypt message with TEE public key. Ensure it is valid PEM format.") from e

def create_ephemeral_wallet():
    """Create a new ephemeral Ethereum account."""
    ephemeral_account = Account.create()
    return ephemeral_account

def send_transaction(web3, contract, ephemeral_account, encrypted_message: str):
    """
    Build, sign, and send a transaction to the smart contract's sendTx function
    using the ephemeral wallet.
    """
    try:
        tx = contract.functions.sendTx(encrypted_message).buildTransaction({
            'from': ephemeral_account.address,
            'nonce': web3.eth.get_transaction_count(ephemeral_account.address),
            'gas': 300000,  # Gas limit example
            'gasPrice': web3.toWei('10', 'gwei')
        })
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=ephemeral_account.privateKey)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        return tx_hash.hex()
    except Exception as e:
        raise RuntimeError("Failed to send transaction to the smart contract.") from e

def main():
    print("Welcome to Matcha - 'It's a TEE for bankers! (R)'")
    
    # Step 1: Check for an existing private key; if not, generate one.
    if not os.path.exists(PRIVATE_KEY_FILE):
        print("No private key found. Generating a new one...")
        passphrase = getpass.getpass("Enter a passphrase to secure your private key: ")
        generate_and_store_private_key(passphrase)
    else:
        print("Private key found.")
    
    # Step 3: Ask for the TEE public key (PEM format)
    tee_public_key_pem = input("Enter the TEE public key (PEM format): ").strip()
    if not tee_public_key_pem.startswith("-----BEGIN"):
        print("Invalid TEE public key format. Must be in PEM format.")
        sys.exit(1)
    
    # Step 4: Ask for the Smart Contract address
    sc_address = input("Enter the TEE Smart Contract address (0x...): ").strip()
    if not Web3.isAddress(sc_address):
        print("Invalid smart contract address.")
        sys.exit(1)
    
    # Set up a Web3 connection
    provider_url = input("Enter your Ethereum provider URL (e.g., Infura endpoint): ").strip()
    web3 = Web3(Web3.HTTPProvider(provider_url))
    if not web3.isConnected():
        print("Failed to connect to Ethereum provider. Check your URL.")
        sys.exit(1)
    # Inject middleware if using a PoA chain
    web3.middleware_onion.inject(geth_poa_middleware, layer=0)
    
    # Minimal ABI for the contract (only sendTx function)
    contract_abi = [
        {
            "inputs": [
                {
                    "internalType": "string",
                    "name": "message",
                    "type": "string"
                }
            ],
            "name": "sendTx",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }
    ]
    contract = web3.eth.contract(address=Web3.toChecksumAddress(sc_address), abi=contract_abi)
    
    while True:
        print("\n--- Create a New Transaction ---")
        dest_address = input("Enter destination bank address (0x...): ").strip()
        if not Web3.isAddress(dest_address):
            print("Invalid destination address. Please try again.")
            continue
        try:
            amount = float(input("Enter amount of USDC to send: ").strip())
        except ValueError:
            print("Invalid amount. Please enter a numeric value.")
            continue
        
        # Confirm details
        print(f"\nTransaction Details:\n  Destination: {dest_address}\n  Amount: {amount} USDC")
        confirm = input("Confirm transaction? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("Transaction cancelled.")
            continue
        
        # Ask for passphrase to decrypt private key
        passphrase = getpass.getpass("Enter your passphrase to unlock your private key: ")
        try:
            user_account = load_private_key(passphrase)
        except Exception as e:
            print(f"Error: {e}")
            continue
        
        # Generate a timestamp
        timestamp = datetime.utcnow().isoformat()
        # Build the base message: destination|amount|timestamp
        base_message = f"{dest_address}|{amount}|{timestamp}"
        try:
            signature = sign_message(user_account, base_message)
        except Exception as e:
            print("Failed to sign message:", e)
            continue
        
        # Full message includes the signature
        full_message = f"{dest_address}|{amount}|{timestamp}|{signature}"
        print("\n[DEBUG] Full message (before encryption):")
        print(full_message)
        
        # Encrypt the message with the TEE public key
        try:
            encrypted_message = encrypt_with_tee_public_key(full_message, tee_public_key_pem)
        except Exception as e:
            print("Encryption failed:", e)
            continue
        print("\nEncrypted message (base64):")
        print(encrypted_message)
        
        # Create an ephemeral wallet
        ephemeral_account = create_ephemeral_wallet()
        print("\nEphemeral wallet created.")
        print("Ephemeral wallet public address (for gas fees):", ephemeral_account.address)
        
        # Instruct the user to fund the ephemeral wallet
        input("Press Enter once you have funded the ephemeral wallet for gas fees...")
        
        # Send transaction to the TEE Smart Contract
        try:
            tx_hash = send_transaction(web3, contract, ephemeral_account, encrypted_message)
            print("Transaction sent! TX Hash:", tx_hash)
        except Exception as e:
            print("Error sending transaction:", e)
        
        again = input("\nDo you want to send another transaction? (yes/no): ").strip().lower()
        if again != "yes":
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting Matcha. Goodbye!")
