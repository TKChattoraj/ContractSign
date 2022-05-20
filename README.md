# ContractSign
Python program to read, encrypt and sign a contract using RSA

Titan sells Charlie 1 dog bowl for 1 BTC.  

This application walks through that contractal process:
1.  Loads the Contract--a text file right now.
2.  Charlie and Titan each generate RSA private public key pairs for separate encryption and signature keys.
3.  Charlie sends encryption public key to Titan.
4.  Titan receives the key, saves,loads it.
5.  App verifies that loaded key is the same as Charlie's public key.
6.  Titan encrypts the contract using Charlie's public key.  He sends it, and Titan's public encryption key to Charlie.  
7.  Charlie receives from Titan.  Uses his private encryption key to decrypt the contract.  
8.  App verifies it is the same as the original contract.
9.  Charlie hashes the contract (SHA256) and uses his private signature key to sign the contract.
10.  Charlie uses Titan's encryption public key to encrypt the contract.
11.  Charlie sends the encrypted contract, signatue, and his signature public key to Titan.
12.  Titan decrypts the contract and verifies it is the same as the original.
13.  Titan verifies Charlie's signature using Charlie's signature public key.  
14.  Commented out is an ECDSA signature and verification.  
