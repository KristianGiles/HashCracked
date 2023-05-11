# HashCracked

HashCracked.py is a hash cracking program developed in Python.

This program currently supports 4 different hashing algorithms:
1. MD5
2. SHA1
3. SHA256
4. NTLM

It has the ability to take in either a single hash on the command line, or a text file with hashes in it, one hash to a line.

It then takes in a wordlist file and will attempt to crack the supplied hash(es) and output them to a new file.

This is still in development.

To Do List:
- More Hashing Algorithms
- Threading
- Salting
