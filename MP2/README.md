python main.py generate -o ./keys/name_of_key -b 2048
python main.py encrypt -p recipient_key.pub -s sender_key.sig file.txt -o encrypted.bin
python main.py decrypt -p sender_key -s sender_key.sig.pub encrypted.bin -o decrypted.txt
