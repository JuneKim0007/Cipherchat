# SecureChat

SecureChat is a simple secure messaging framework that demonstrate a secure message exchanging protocols using Triple DH key exchange.
It provides outlines for asynchronous chatting, handshake-based session establishment and message ratcheting for forward secrecy.  

This project does **not** implement a real network layer, but rather a framework demonstrating secure message workflows.

## Definitions

- **Handshake**: establishes a session and exchange session-only public keys between two entities(Alice and Bob).  
- **Ephemeral Key**: A temporary key pair used only for a single occasion such as handshake establishment, message flow changes to provide forward secrecy.  
- **Message Ratcheting**: Updating session keys with each message for forward secrecy
- **Asynchronous Operation**: Ensures out-of-order message processes by caching (ratcheted) keys.

## How it works
1. **Session Initialization**
     * Each participant generates key pairs(Pub_Key, Priv_Key) that is ephemeral to a session using an elliptic curve (P-256).
     * These keys are temporary and used only for the current session to derive shared secrets via Diffie-Hellman.
     * Public keys are exchanged via a handshake.
3. **Key Derivation**
     * Both sides derive a shared secret using Diffie–Hellman.
     * Initial session keys are generated from the shared secret.
4. **Message Exchange**
   * Each message is encrypted using the current session key.
   * After sending/receiving a message, keys are ratcheted to update the session state, ensuring forward secrecy.
   * If the flow of messages changes, a new ephemeral key pair is generated and used with the existing root key to create a new chain.
6. **Asynchronous Chat**
   * Session caches track key state for proper decryption and ratcheting.

## Features
* **Triple Diffie–Hellman Handshake**: Establishes a secure session and generates ephemeral key pairs.  
* **Message Ratcheting**: Ratchet keys per message for forward secrecy.  
* **Asynchronous Support**: Out-of-order messages can be decrypted correctly.  
* **Security**: Ensure the validity of a session and  messages's integrity and confidentiality.

## test cases:
  * to see predefined test cases, simply run "go run ./tests.go"
