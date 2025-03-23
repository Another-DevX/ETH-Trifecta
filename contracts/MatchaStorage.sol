// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MatchaStorage
 * @notice This contract implements an on-chain storage for the Matcha protocol.
 * It maintains a queue of pending transactions (as strings) that are submitted
 * permissionlessly via the sendTx function. It emits an event for every submitted
 * transaction for the TEE to capture.
 *
 * The contract also stores an encrypted database (as a string) that is updated by
 * a preconfigured TEE wallet. The TEE wallet is allowed to process (pop) transactions
 * from the queue and update the encrypted database – but only if the queue is empty.
 * The owner (the deployer) can change the TEE wallet if needed.
 */
contract MatchaStorage {
    // Owner of the contract (deployer)
    address public owner;
    // Address of the TEE wallet allowed to process transactions and update the database
    address public teeWallet;

    // Queue implementation using a mapping with head and tail indices
    mapping(uint256 => string) private transactionQueue;
    uint256 private head;
    uint256 private tail;

    // Encrypted database storage
    string public encryptedDatabase;

    // Events
    event TransactionQueued(uint256 indexed index, string txMessage);
    event TransactionProcessed(uint256 indexed index, string txMessage);
    event DatabaseUpdated(string newDatabase);
    event TEEWalletChanged(address newTEEWallet);

    // Modifiers
    modifier onlyTEE() {
        require(msg.sender == teeWallet, "Caller is not the TEE wallet");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    /**
     * @notice Constructor sets the initial TEE wallet and the initial encrypted database.
     * @param _teeWallet The preconfigured TEE wallet address.
     * @param _initialEncryptedDatabase The initial encrypted database string.
     */
    constructor(address _teeWallet, string memory _initialEncryptedDatabase) {
        require(_teeWallet != address(0), "Invalid TEE wallet address");
        owner = msg.sender;
        teeWallet = _teeWallet;
        encryptedDatabase = _initialEncryptedDatabase;
    }

    /**
     * @notice Submits a transaction intent to the queue. This function is permissionless.
     * @param _txMessage The encrypted transaction message (as a string) submitted by any wallet.
     * Emits a TransactionQueued event.
     */
    function sendTx(string calldata _txMessage) external {
        transactionQueue[tail] = _txMessage;
        emit TransactionQueued(tail, _txMessage);
        tail++;
    }

    /**
     * @notice Called by the TEE wallet to process (pop) the next transaction from the queue.
     * @return The transaction message at the front of the queue.
     */
    function popTx() external onlyTEE returns (string memory) {
        require(getQueueLength() > 0, "Queue is empty");
        string memory txMessage = transactionQueue[head];
        delete transactionQueue[head];
        emit TransactionProcessed(head, txMessage);
        head++;
        return txMessage;
    }

    /**
     * @notice Updates the encrypted database.
     * Can only be called by the TEE wallet and only if the transaction queue is empty.
     * @param _newEncryptedDatabase The new encrypted database string.
     */
    function updateEncryptedDatabase(string calldata _newEncryptedDatabase) external onlyTEE {
        require(getQueueLength() == 0, "Queue must be empty to update database");
        require(
            keccak256(bytes(_newEncryptedDatabase)) != keccak256(bytes(encryptedDatabase)),
            "New database must be different"
        );
        encryptedDatabase = _newEncryptedDatabase;
        emit DatabaseUpdated(_newEncryptedDatabase);
    }

    /**
     * @notice Returns the current length of the transaction queue.
     * @return The number of pending transactions.
     */
    function getQueueLength() public view returns (uint256) {
        return tail - head;
    }

    /**
     * @notice Allows the owner to change the TEE wallet address.
     * @param _newTEEWallet The new TEE wallet address.
     */
    function setTEEWallet(address _newTEEWallet) external onlyOwner {
        require(_newTEEWallet != address(0), "Invalid TEE wallet address");
        teeWallet = _newTEEWallet;
        emit TEEWalletChanged(_newTEEWallet);
    }

    /**
     * @notice (Optional) Returns a transaction message from the queue at a specific index.
     * @param index The index within the queue (must be between head and tail).
     * @return The transaction message string.
     */
    function getTransaction(uint256 index) external view returns (string memory) {
        require(index >= head && index < tail, "Index out of bounds");
        return transactionQueue[index];
    }
}
