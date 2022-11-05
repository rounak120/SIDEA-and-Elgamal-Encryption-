
##    Name:    Rounak Kumar Gupta
##    Roll:    20BCS185

## ---->>> Elgamal <<<---##

# function *elgamal_key_generation()* 
    It takes prime number as input and generates public key (e1,e2,p). primitiveRoot() function generates the primitive root e1 and power() function generates e2.

# function *elgamal_encryption()*
    It takes input public key and encrypts the secret key to generate cypher key pair {C1,C2}.

# function *elgamal_decryption()*  
    It takes encrypted secret key as input and decrypts it using the private key.

 # function *binaryToDecimal()* 
    It takes a binary string as input and converts it into a decimal number.

## ---->>> SIMPLIFED IDEA <<<---- ##

# function *keyGeneration()*
    It take input a {secret key}.
    Each of the 4 complete rounds requires 6 subkeys, and the final transformation requires 4 subkeys; so, the entire process requires 28 subkeys.
    The 32-bit key is split into eight 4-bit subkeys. Then the bits are shifted to
    the left 6 bits using function leftShift(). The resulting 128-bit string is split into eight 4-bit blocks that become the next eight subkeys. The shifting and splitting process is repeated until 28 subkeys are generated.

# function *encodeMessage()*  
    It take input a secret key{message(binary string),sets of keys}
    16 bit message splited in 4 nibbles and convert to integer. Applying the SIDEA to each part 
    which give the 4-bit binary cipher text and get concantinated to form a 16 bit cipher text. 

# function *decryptionKey()*
    It take input a cipher key{cipher key}
    firstly the keyGenration() function genereate the keys for encryption then creating the decryption subkeys according to Simplified decryption algorithm(given in pdf)

# function *decodeMessage()*
    It take input a cipher text{message(binary string),sets of dekeys}
    Applying the similar algorithm as in encodeMessage with the decryption keys and which give us the source code

# function *leftShift()* 
    It shifts the given string cyclically by 6 bits. 


