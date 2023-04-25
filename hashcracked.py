## Program Name: HashCracked
## Start Date: 25-04-2023
## Author: Kristian Giles
## Description: HashCracked is a program that takes hashes from a file or the command line and attempts to crack them using a supplied word list.
## Version: 1.0

## Libraries
import hashlib
import binascii
import sys
import argparse

## Function to test that all required arguments are present.
def kill_function(arg1, arg2, test):
    if arg1 == test and arg2 == test:
        return 0
    else:
        return 1

## Writing the cracked_passwords list to a text file to output the passwords.
def hashes_to_file(list):
    with open("cracked_passwords.txt", "w") as hash_combo:
        for line in list:
            hash_combo.write(line)
            hash_combo.write("\n")
    
    return hash_combo

## Initialising argument parser.
parser = argparse.ArgumentParser(
    description = "Read in a file or single user input of password(s), either in plaintext or hashed format and try and crack them with a supplied wordlist."
)

## Mutually exclusive arguments.
input_group = parser.add_mutually_exclusive_group()
type_group = parser.add_mutually_exclusive_group()

## Arguments for  input type.
input_group.add_argument("-i", "--input", help = "Single user inputted password")
input_group.add_argument("-t", "--text", help = "File of passwords, including directory, each password on a new line")

## Argument for wordlist.
parser.add_argument("wordlist", help = "The wordlist the program will use to try and crack the passwords")

## Arguments for hash type.
type_group.add_argument("-m", "--md5", help = "This dictates that the inputted string or file are stored as md5 hashes", action = "store_true")
type_group.add_argument("-s1", "--sha1", help = "This dictates that the inputted string or file are stored as sha1 hashes", action = "store_true")
type_group.add_argument("-s2", "--sha256", help = "This dictates that the inputted string or file are stored as sha256 hashes", action = "store_true")
type_group.add_argument("-n", "--ntlm", help = "This dictates that the inputted string or file are stored as ntlm hashes", action = "store_true")

## Reassigning argument parser to variable.
args = parser.parse_args()

## Assigning arguments to variables.
input_status = args.input
text_status = args.text
md5_status = args.md5
sha1_status = args.sha1
sha256_status = args.sha256
ntlm_status = args.ntlm

## Testing to make sure only one input is given, either command line or a text file.
input_group_status = kill_function(input_status, text_status, None)

## Testing to make sure an input is given, either command line or a text file.
if input_group_status == 0:
    print("Missing input parameters.")
    quit(3)

## Opening the wordlist file in read mode.
wordlist = open(args.wordlist, "r", encoding='Latin-1')

## Testing to see if it it is a command line input.
if input_status != None:

    ## MD5 hash checking.
    if md5_status == True:
        for pw in wordlist:
            password = hashlib.md5(pw.encode())
            password = password.hexdigest()
            if password == input_status:
                print("Success! Your Password Is", pw)
                quit(3)

    ## SHA1 hash checking.
    if sha1_status == True:
        for pw in wordlist:
            password = hashlib.sha1(pw.encode())
            password = password.hexdigest()
            if password == input_status:
                print("Success! Your Password Is", pw)
                quit(3)

    ## SHA256 hash checking.
    if sha256_status == True:
        for pw in wordlist:
            password = hashlib.sha256(pw.encode())
            password = password.hexdigest()
            if password == input_status:
                print("Success! Your Password Is", pw)
                quit(3)

    ## NTLM hash checking.
    if ntlm_status == True:
        for pw in wordlist:
            password = hashlib.new('md4', pw.encode())
            password = password.hexdigest()
            if password == input_status:
                print("Success! Your Password Is", pw)
                quit(3)

## Testing to see if it it is a text file input.
if text_status is not None:

        ## Reading the text file into a list.
        with open(text_status, "r") as text:
            hash_list = text.readlines()

## Setting up an empty list to store the cracked passwords.       
cracked_passwords = []

## Setting the length of the list to a variable.
hash_length = len(hash_list)

## Detecting the hash type via the inputted argument and converting the word in the wordlist to said hash type for comparison.
if md5_status == True:
    for pw in wordlist:
        for hash in hash_list:
            hash = hash.strip()
            pw = pw.strip()
            password = hashlib.md5(pw.encode())
            password = password.hexdigest()

            ## Comparing the hash of the item in the wordlist to the hash in the hash list, if they are the same it is saved to our cracked_passwords list. 
            if password == hash:
                result = hash + ":" + pw
                print(result)
                cracked_passwords.append(result)
                hash_length -= 1

                ## Detecting if the hash list is now empty, if it is the cracked_passwords list is written to a file and closes all the files used.
                if hash_length == 0:
                    hash_combo = hashes_to_file(cracked_passwords)
                    wordlist.close()
                    hash_combo.close()
                    text.close()
                    quit(3)

## Detecting the hash type via the inputted argument and converting the word in the wordlist to said hash type for comparison.
if sha1_status == True:
    for pw in wordlist:
        for hash in hash_list:
            hash = hash.strip()
            pw = pw.strip()
            password = hashlib.sha1(pw.encode())
            password = password.hexdigest()

            ## Comparing the hash of the item in the wordlist to the hash in the hash list, if they are the same it is saved to our cracked_passwords list. 
            if password == hash:
                result = hash + ":" + pw
                print(result)
                hash_length -= 1

                ## Detecting if the hash list is now empty, if it is the cracked_passwords list is written to a file and closes all the files used.
                if hash_length == 0:
                    hash_combo = hashes_to_file(cracked_passwords)
                    wordlist.close()
                    hash_combo.close()
                    text.close()
                    quit(3)

## Detecting the hash type via the inputted argument and converting the word in the wordlist to said hash type for comparison.
if sha256_status == True:
    for pw in wordlist:
        for hash in hash_list:
            hash = hash.strip()
            pw = pw.strip()
            password = hashlib.sha256(pw.encode())
            password = password.hexdigest()

            ## Comparing the hash of the item in the wordlist to the hash in the hash list, if they are the same it is saved to our cracked_passwords list.
            if password == hash:
                result = hash + ":" + pw
                print(result)
                cracked_passwords.append(result)
                hash_length -= 1

                ## Detecting if the hash list is now empty, if it is the cracked_passwords list is written to a file and closes all the files used.
                if hash_length == 0:
                    hash_combo = hashes_to_file(cracked_passwords)
                    wordlist.close()
                    hash_combo.close()
                    text.close()
                    quit(3)
                    
## Detecting the hash type via the inputted argument and converting the word in the wordlist to said hash type for comparison.
if ntlm_status == True:
    for pw in wordlist:
        for hash in hash_list:
            hash = hash.strip()
            pw = pw.strip()
            password = hashlib.new('md4', pw.encode())
            password = password.hexdigest()

            ## Comparing the hash of the item in the wordlist to the hash in the hash list, if they are the same it is saved to our cracked_passwords list.
            if password == hash:
                result = hash + ":" + pw
                print(result)
                cracked_passwords.append(result)
                hash_length -= 1

                ## Detecting if the hash list is now empty, if it is the cracked_passwords list is written to a file and closes all the files used.
                if hash_length == 0:
                    hash_combo = hashes_to_file(cracked_passwords)
                    wordlist.close()
                    hash_combo.close()
                    text.close()
                    quit(3)
