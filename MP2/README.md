### INSTALL

`pip install cryptography`

### COMMANDS

Display Help: `python main.py`

To Generate Key:
`python main.py generate -o name_of_key -b 2048`

To Encrypt Message:
`python main.py encrypt -p recipient_key.pub -s sender_key.sig file.txt -o encrypted.bin`

To Decrypt Message:
`python main.py decrypt -p recepient_key -s sender_key.sig.pub encrypted.bin -o decrypted.txt`
