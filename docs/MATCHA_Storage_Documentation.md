# MatchaStorage Contract Usage Documentation

This document explains how to interact with the **MatchaStorage** smart contract deployed as part of the Matcha protocol. The contract stores pending transactions in a queue, allows the TEE wallet to process them, and maintains an encrypted on-chain database. Below you will find details on deployment, available functions, and examples on how to use them.

---

## Overview

The **MatchaStorage** contract is designed to serve as on-chain storage for encrypted transaction messages and an encrypted database representing the order book. Key features include:

- **Transaction Queue:**  
  Any wallet can submit an encrypted transaction string via the `sendTx` function. Each submission is added to a queue and emits an event that can be monitored by the TEE.
  
- **TEE Processing:**  
  The preconfigured TEE wallet (set during deployment) can call `popTx` to retrieve the next pending transaction from the queue for processing. Only the TEE wallet is authorized to process transactions.
  
- **Database Updates:**  
  Once the queue is empty, the TEE wallet can update the encrypted database by calling `updateEncryptedDatabase`. This ensures that the database is updated only after all pending transactions have been processed.
  
- **Administration:**  
  The contract owner (usually the deployer) can update the TEE wallet address using `setTEEWallet` if necessary.

---

## Deployment

When deploying the **MatchaStorage** contract, provide the following constructor parameters:

1. **TEE Wallet Address:**  
   The Ethereum address of the TEE wallet which is authorized to process transactions and update the database.
   
2. **Initial Encrypted Database:**  
   A string representing the initial encrypted state of the order book/database.

For example, using Remix or a deployment script:

```solidity
new MatchaStorage(0xTEE_WALLET_ADDRESS, "initial_encrypted_database_value");


Interacting with the Contract

1. Submitting a Transaction (sendTx)
Purpose:
Allow any wallet to submit an encrypted transaction string.

Function:

function sendTx(string calldata _txMessage) external;
Usage:

Input:

_txMessage: An encrypted transaction message (string) produced by the client.

Effect:
The transaction is added to the queue (using internal indices) and an event TransactionQueued is emitted with the index and the message.

Example (via Web3.js):

const txMessage = "encrypted_transaction_string";
await contract.methods.sendTx(txMessage).send({ from: userAddress });

2. Processing a Transaction (popTx)
Purpose:
Allow the TEE wallet to retrieve (pop) the next pending transaction from the queue.

Function:

function popTx() external onlyTEE returns (string memory);
Usage:

Access:
Only callable by the TEE wallet.

Effect:
Returns the next transaction in the queue and emits a TransactionProcessed event. The queue's head is incremented.

Example (via Web3.js):

const txMessage = await contract.methods.popTx().call({ from: teeWalletAddress });
console.log("Processed Transaction:", txMessage);

3. Updating the Encrypted Database (updateEncryptedDatabase)
Purpose:
Allow the TEE wallet to update the encrypted database once all transactions have been processed.

Function:

function updateEncryptedDatabase(string calldata _newEncryptedDatabase) external onlyTEE;
Usage:

Precondition:
The transaction queue must be empty (i.e. getQueueLength() == 0).

Effect:
Updates the encryptedDatabase state variable and emits a DatabaseUpdated event.

Example (via Web3.js):

const newDatabaseValue = "new_encrypted_database_value";
await contract.methods.updateEncryptedDatabase(newDatabaseValue).send({ from: teeWalletAddress });
4. Checking the Queue Length (getQueueLength)
Purpose:
Retrieve the number of pending transactions.

Function:

function getQueueLength() public view returns (uint256);
Usage:

Effect:
Returns the difference between the tail and head indices of the queue.

Example (via Web3.js):

const length = await contract.methods.getQueueLength().call();
console.log("Pending Transactions:", length);
5. Retrieving a Specific Transaction (getTransaction)
Purpose:
Retrieve a specific transaction from the queue by index.

Function:

function getTransaction(uint256 index) external view returns (string memory);
Usage:

Input:

index: Must be between the current head and tail.

Effect:
Returns the transaction message stored at that index.

Example (via Web3.js):

const txMessage = await contract.methods.getTransaction(0).call();
console.log("Transaction at index 0:", txMessage);
6. Changing the TEE Wallet (setTEEWallet)
Purpose:
Allow the contract owner to update the TEE wallet address if needed.

Function:

function setTEEWallet(address _newTEEWallet) external onlyOwner;
Usage:

Access:
Only callable by the owner.

Effect:
Updates the teeWallet state variable and emits a TEEWalletChanged event.

Example (via Web3.js):


const newTeeAddress = "0xNEW_TEE_WALLET_ADDRESS";
await contract.methods.setTEEWallet(newTeeAddress).send({ from: ownerAddress });