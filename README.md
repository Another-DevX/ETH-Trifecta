<p align="center">
  <img src="https://github.com/Another-DevX/ETH-Trifecta/blob/main/logo/matcha.jpg?raw=true" width="300" alt="Matcha logo" />
</p>

<h1 align="center">Matcha</h1>
<h3 align="center"><i>It's a TEE for bankers!®</i></h3>

---

## 🧠 What is Matcha?

**Matcha** is a privacy-preserving interbank transaction engine built for Ethereum using **Trusted Execution Environments (TEEs)**.

With Matcha, banks can settle transactions over a **public blockchain** without revealing sensitive transaction details — enabling trustless, verifiable finance while keeping balance sheets private.

It’s permissionless, verifiable, and secure — powered by the magic of TEEs and Merkle trees.

---

## 🔒 How It Works

1. **📤 Bank Intent Submission**  
   Any bank creates a **signed transaction intent**, encrypts it, and uploads it to a smart contract on Ethereum using **any wallet**. No whitelists — Matcha is permissionless by design.

2. **🛡️ TEE Event Listener**  
   The TEE continuously monitors blockchain events. When a new transaction intent is posted, it pulls the data directly from the smart contract storage (encrypted with TEE public's key).

3. **✅ Enclave Verification & Execution**  
   Inside the secure enclave, Matcha verifies the intent:
   - Checks the digital signature
   - Validates sender balances
   - Prevents double-spending  
   If valid, it executes the transaction and updates the **Merkle tree state**.

4. **🌿 State Commitment On-Chain**  
   The updated Merkle root is written back to the smart contract. This is the only public state exposed — ensuring **transactional privacy with cryptographic accountability**.

---

## 🌍 Why Matcha?

- ✅ **Private by Default** — Transactions never leak sensitive metadata
- 🧩 **Composable** — Easy integration with public Ethereum and rollups
- 🔐 **Secure & Auditable** — Powered by remote attestation and cryptographic proofs
- ⚙️ **Efficient** — Off-chain compute, on-chain finality

---

## 📦 Repository Structure

- `contracts/` – Solidity smart contracts for intent storage and Merkle root updates  
- `tee/` – Enclave code (Intel SGX or compatible runtime)  
- `scripts/` – Transaction intent creation, signing, and publishing helpers  
- `docs/` – Presentation, Video, additional documentation, architecture, and diagrams  
- `logo/` – Every version of this beautiful design.  

---

## 🛠️ Getting Started

> Full setup instructions coming soon. This is a live hackathon project!

---

## 🧪 Built At

**ETHGlobal Trifecta 2025**  
Track: **Trusted Execution Environments (TEEs)**  
https://ethglobal.com/events/trifecta

---

## 📄 License

MIT

---

## 🫱🏽‍🫲🏽 Contributing

Contributions welcome! Open an issue, submit a PR, or brew a fresh idea.

---

<p align="center">
  ☕️ Built with privacy, precision, and a little Matcha by <a href="https://x.com/ariutokintumi" target="_blank">ariutokintumi</a>
</p>
