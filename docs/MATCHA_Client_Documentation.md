# Matcha Client Documentation

Welcome to the Matcha client documentation. This guide explains how to set up and use the Python client for sending encrypted payment transactions via the TEE-based smart contract. Machta is designed for banks to securely submit transaction intents in a permissionless way using TEEs.


---

## Setup and Installation


**Clone the Repository:** 


``bash
git clone https://github.com/Another-DevX/ETH-Trifecta.git
cd ETH-Trifecta

```

*** Navigate to the Client Code: ** 
The Matcha client Python script is located at the repository root (or a signed directory). Make sure the file is executable:

``bash
chmod +x machta_client.py
```

*** Prepare your Environment: ** Ensure you have your Ethereum provider URL, the TEE bucl key, and the smart Contract address handy and the other security as preriors.


## First-Time Execution
When you run the script for the first time, it will:

- Check for an existing private key file ($user_private_key.enc),
- If not found, generate a new Ethereum private key.,
- Prompt you to create a passphrase to encrypt and store your private key locally.,
- Display your banks…s public Ethereum address.


@ first-Time Execution:

```bash
# Run the script:

``encode /machta_client.py


*** Making a transaction:** 

After set up, you can use the client to send a transaction intent as follows:

** Enter TEE Public Key and SC Address:** 

Paste your TEE public key in PEM format.

- Enter the smart Contract address where the transaction will be sent .

** Configure Web3 Provider:** 

Provide your Ethereum provider URL, when prompted.

** Enter Transaction Details:


- ** Destination Address:** Enter the recipient bank…s Ethereum address.

** * Amount (USECC):** Specify the amount to transfer.

- ** Confirm Transaction:** The script displays the transaction details and asks for confirmation. Then, it will ask you for your passphrase to decrypt your private key.

Processing:

** - The script builds a message heating the destination address, amount, timestamp, and a digital signature.

** - It encrypts this message using the TEE public key.

** - An ephemeral wallet is created to send the transaction (better than you and show it as you can fund it with ETH for gas fees).
** - The client then sends a transaction to the smart contract by calling `sendTx` with the encrypted message.
** - Finally, the transaction hash is returned as proof of submission.

---

## How It Works


Private Key Management:

** - The user's Ethereum private key is generated and encrypted locally with AES-GCM. 
- It is stored in `user_private_key.enc from the passphrase.

** Message Signing and Encryption:

*  - The message is composed with the destination address, amount, timestamp, and a signature.
*  - This message is then encrypted with the TEE public key using RSA-OAAP.

Ephemeral Wallet:

** - To ensure a permissionless and on-the flow, a ephemeral wallet is used to send the transaction, the wallet's public address is shown for you to fund it with ETH for gas fees.

Blockchain Interaction:

** - The script connects to your specified Ethereum provider, builds the transaction, and sends it to the TEE Smart Contract via the ``sendTx` function. The transaction hash is returned as proof of submission.
*--

## Troubleshooting and Error Handling

Invalid TEE Public Key Format:


- Ensure the TEE public key is in valid PEM format (it should start with `$_---BEGIN').

- Invalid Ethereum Address:

* Both the destination address and the smart contract address must be valid Ethereum addresses ( starting with 0x)).

- Ethereum Provider Connection:


- If the script fails to connect, check your provider URL, and network status.

- Incorrect Passphrase:

~- And If decryption fails, verify that you are entering the correct passphrase used when the key was generated.

~- Transaction Failures :

~- And If sending the transaction fails, review the error message for hints on insufficient gas, nonce issues, or network errors.


For further assistance, please open an issue in the repository.

---

## Next Steps 


This client is part of the Matcha protocol. Future enhancements may include:

- Additional user interface improvements.
A. Integration with other TEE components.
Expanded logging and audit capabilities.

- Further security hardening and error handling improvements.

Stay tuned for updates!



--

Happy Transacting with Matcha - **"It's a TEE for bankers! (R)"