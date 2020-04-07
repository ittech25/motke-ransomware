```
  __  __       _   _          _____                                                       
 |  \/  |     | | | |        |  __ \                                                      
 | \  / | ___ | |_| | _____  | |__) |__ _ _ __  ___  ___  _ __ _____      ____ _ _ __ ___ 
 | |\/| |/ _ \| __| |/ / _ \ |  _  // _` | '_ \/ __|/ _ \| '_ ` _ \ \ /\ / / _` | '__/ _ \
 | |  | | (_) | |_|   |  __/ | | \ | (_| | | | \__ | (_) | | | | | \ V  V | (_| | | |  __/
 |_|  |_|\___/ \__|_|\_\___| |_|  \_\__,_|_| |_|___/\___/|_| |_| |_|\_/\_/ \__,_|_|  \___|
                                                                                          
                                                                                         
  ```                                                                                     
                                                                                        
## Notes
> This project is purely for learning purposes, and is not meant to be used in any illegal or unethical way.

> This is a POC for encryption only, the script is not cleaning up traces left in memory nor communicating over TOR to ensure anonymity of the attacker.

> As a POC, file is required to be manually ran, as a part of a real situation it could be compiled into an executable / vba script downloading it from an external server.


### Project summery:
This POC was developed from pure curiosity about how ransomware works.

As a POC, it will not scan the entire drives of the machine and encrypt all non-system files, Instead, it will ask for a user to input a folder path, and encrypt all the files under that path (non-recursively).

supported file extenstions are:

docx, exe, txt, png, jpg, avi, bmp, mp4, mp3, mkv

  ### Encryption:
   The malware is encrypting the files using AES-256.
    
   Each key is being encrypted by a client generated RSA public key, while the RSA private key is being encrypted by a pre made RSA public key encoded in the malware.
   
   
  ### Decryption:
   While using the Decryptor, it requests the user for the server's pre made private key, and the encrypted folder location.
   
   while being given those parameters, it will load the private key, decrypt the client RSA private key, and with that decrypt the AES key for each file.
   
   Using this work scheme, the same server private key can be used to decrypt all the data for every person affected by this malware.
   
   This could be prevented by opening a socket over TOR network in order to send a hash used to encrypt the client private key, but it wasnt the purpose of this POC.


Please, DO NOT use this script on important files, or play with encrypted data you wish to restore, as i take no responsibility over loss of data.


## Features:
* Includes a Decrypter.

* Usage of RSA + AES-256.

* Encryption being done in chunks in order to prevet memory overflow and to reduce memory usage.

* Changes Desktop background and creates a text file for instructions.



# summary
I went into this POC with thoughts about how hard it may be to build such a malware.

While not being as big as a real ransomware might be, the important part is being made like a POC should be, and it really shows the threats of how anyone can build such things.
