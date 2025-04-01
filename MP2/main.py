import argparse
import os
import sys
from pathlib import Path
import utils

def main():
    parser = argparse.ArgumentParser(
        description="encryptor - A simple RSA encryption tool",
    )
    
    parser.add_argument('--debug', action='store_true', help='Enable debug prints')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands for different operations')
    
    # Encrypt subcommand
    encrypt_parser = subparsers.add_parser('encrypt', aliases=['enc'], 
                                          help='Encrypt a message')
    encrypt_parser.add_argument('file', nargs='?', type=Path, 
                               help='Specifies the input file containing plaintext')
    encrypt_parser.add_argument('-p', '--public-key', '--public', '--key', '--pkey', '--pk', 
                               dest='public_key', required=True, type=Path,
                               help="The recipient's public RSA key")
    encrypt_parser.add_argument('-s', '--signing-key', '--signature', '--sig', 
                               dest='signing_key', required=True, type=Path,
                               help='Your private key signature')
    encrypt_parser.add_argument('-o', '--output', '--out', 
                               dest='output', type=Path,
                               help='Specify the file path for the output of the encrypted message')

    # Decrypt subcommand
    decrypt_parser = subparsers.add_parser('decrypt', aliases=['dec'], 
                                          help='Decrypt an encrypted message')
    decrypt_parser.add_argument('file', nargs='?', type=Path, 
                               help='Specifies the input file containing ciphertext message')
    decrypt_parser.add_argument('-p', '--private-key', '--private', '--key', '--pkey', '--pk', 
                               dest='private_key', required=True, type=Path,
                               help='Your RSA private key to decrypt the message')
    decrypt_parser.add_argument('-s', '--verifying-key', '--signature', '--sig', 
                               dest='verifying_key', required=True, type=Path,
                               help="The recipient's public key signature")
    decrypt_parser.add_argument('-o', '--output', '--out', 
                               dest='output', type=Path,
                               help='Specify the file path for the output of the decrypted message')
    decrypt_parser.add_argument('-x', '--skip-verification', '--skip', 
                               dest='skip_verification', action='store_true', default=False,
                               help='Option to skip integrity check')
    
    # Generate subcommand
    generate_parser = subparsers.add_parser('generate', aliases=['gen'], 
                                           help='Generate private and public keys')
    generate_parser.add_argument('-o', '--output', '--out', 
                                dest='output', required=True, type=Path,
                                help='Filename')
    generate_parser.add_argument('-b', '--bits', 
                                dest='bits', default='1648', choices=['1024', '1648', '2048', '4096'],
                                help='Bit size')
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return
    
    if args.command in ['encrypt', 'enc']:
        message_file = Path("sender") / args.file
        message = utils.read_input(message_file)
        public_key = Path("keys") / args.public_key
        signature = Path("keys") / args.signing_key
        output = Path("receiver") / args.output 
        
        if args.debug:
            print(f"Message: {message}")
            print(f"Public key: {public_key}")
            print(f"Signature: {signature}")
            print(f"Output: {output}")
        
        try:
            utils.generate_encrypted_message(message.encode(), public_key, signature, output)
        except Exception as err:
            sys.stderr.write(str(err))
    
    elif args.command in ['decrypt', 'dec']:
        receiver_dir = Path("receiver")
        receiver_dir.mkdir(parents=True, exist_ok=True)

        message_file = Path("receiver") / args.file
        message = utils.read_input_raw(message_file)
        private_key = Path("keys") / args.private_key
        signature = Path("keys") / args.verifying_key
        output = receiver_dir / args.output 
        skip_verification = args.skip_verification
        
        if args.debug:
            print(f"Message: {message}")
            print(f"Private key: {private_key}")
            print(f"Signature: {signature}")
            print(f"Output: {output}")
            print(f"Skip verification: {skip_verification}")
        
        try:
            utils.generate_decrypted_message(message, private_key, signature, output, skip_verification)
        except Exception as err:
            sys.stderr.write(str(err))
    
    elif args.command in ['generate', 'gen']:
        key_dir = Path("keys")
        key_dir.mkdir(parents=True, exist_ok=True)

        output = key_dir / args.output 
        
        bits = int(args.bits)
        
        if args.debug:
            print(f"Output: {output}")
            print(f"Bits: {bits}")
        
        print("Generating private and public RSA keys...")
        
        try:
            utils.generate_private_key(output, bits)
            utils.generate_public_key(output)
            print(f"Saved {output}")
            
            print("Generating private and public signature keys...")
            output_signature = utils.append_to_path(output, ".sig")
            utils.generate_private_key(output_signature, bits)
            utils.generate_public_key(output_signature)
            print(f"Saved {output_signature}")
        except Exception as err:
            sys.stderr.write(str(err))

if __name__ == "__main__":
    main()