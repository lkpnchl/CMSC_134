Authors: Jean, Jemimah, Pinky, Yzère

## Key Generation
### _The Locksmith’s Workshop_
Before any secret message can be whispered in the shadows, before any code can be cracked or protected, something must happen first: **the forging of the keys**. In this program, key generation is the very first step and probably the most important one—it’s like creating the locks and keys before you send any secret messages. When you run the command: `python main.py generate -o mykeys -b 2048` you’re basically telling the system: “Hey, I need my encryption gear.” What happens next is a quiet but powerful process behind the scenes. The system creates two pairs of keys: one pair for encrypting and decrypting messages, and another for signing and verifying them. Each pair includes a private key (which you guard closely) and a public key (which you can safely share). You’ll see files like `mykeys`, `mykeys.pub`, `mykeys.sig`, and `mykeys.sig.pub` appear in the `keys/` folder—these are your personal security toolkit.

Here’s how it works in simpler terms: you want to send a message, but it’s got to be private. The recipient gives you a lock (their public key) that only they have the key to open (their private key). You lock your message using their lock and send it. Now only they can unlock it. But wait—how do they know it’s really *you* who sent it, and not some sneaky imposter? That’s where your signature key comes in. You use your private signing key to stamp your message, like putting your personal seal on a letter. Then, the receiver uses your public signing key to check if that stamp is legit. If the message has been tampered with or if someone else tries to fake your identity, the signature won’t match—and they’ll know something’s off. This is how the program ensures authenticity.

Under the hood, the key generation part of the code looks like this:

```python
utils.generate_private_key(output, bits)
utils.generate_public_key(output)
output_signature = utils.append_to_path(output, ".sig")
utils.generate_private_key(output_signature, bits)
utils.generate_public_key(output_signature)
```

This chunk is where it all begins—your encryption keys (`mykeys`, `mykeys.pub`) and your signature keys (`mykeys.sig`, `mykeys.sig.pub`) are created here. It's a one-time setup, but everything else in the program depends on it.

If you're curious about what actually happens during key generation, here’s a peek inside the utils.py file. This is where the magic happens:

```python
def generate_private_key(output, bits):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits
    )
    
    with open(output, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
```

This function creates a private RSA key and saves it in a `.pem` format, which is a widely used text encoding for cryptographic keys.

Once the private key is ready, the corresponding public key is extracted like this:

```python
def generate_public_key(private_key_path):
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    
    public_key = private_key.public_key()
    
    output = append_to_path(private_key_path, ".pub")
    with open(output, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
```
This function loads the private key you just made, pulls out the public key from it, and saves that too—also in `.pem` format. The .pub extension helps keep things organized.


So, key generation sets up both security (with encryption keys) and authenticity (with signing keys). Without this setup, messages could be stolen, read, or forged. But with the keys in place, you get two powerful guarantees: **only the right person can read your message**, and **they’ll know for sure it came from you**. It builds the foundation for everything the program does: secure, trusted communication.

## Encryption
### _Sealing the Secret Scroll_



## Decryption
### _Breaking the Seal_
