Authors: Jean, Jemimah, Pinky, Yzère

## Key Generation
### _The Locksmith’s Workshop_
Before any secret message can be whispered in the shadows, before any code can be cracked or protected, something must happen first: **the forging of the keys**. In this program, key generation is the very first step and probably the most important one—it’s like creating the locks and keys before you send any secret messages. When you run the `generate` command, the system quietly creates *two* powerful duos of keys. One for encryption/decryption and another for signing/verification. Each set has a private key (which you keep secret) and a public key (which you share with others). The encryption keys are used to secure the message, while the signing keys are used to prove who actually sent the message. Think of it as preparing your armor and signature seal before stepping into a war.

Here’s how it works in simpler terms: you want to send a message, but it’s got to be private. The recipient gives you a lock (their public key) that only they have the key to open (their private key). You lock your message using their lock and send it. Now only they can unlock it. But wait—how do they know it’s really *you* who sent it, and not some sneaky imposter? That’s where your signature key comes in. You "sign" the letter using your private signing key. Then, they use your public signing key to verify that the message hasn’t been tampered with and that it really came from you.

This whole process might feel like secret agent stuff, and that’s kind of the point. So, key generation sets up both security (with encryption keys) and authenticity (with signing keys). Without this setup, messages could be stolen, read, or forged. But with the keys in place, you get two powerful guarantees: **only the right person can read your message**, and **they’ll know for sure it came from you**. It builds the foundation for everything the program does: secure, trusted communication.

## Encryption
### _Sealing the Secret Scroll_



## Decryption
### _Breaking the Seal_
