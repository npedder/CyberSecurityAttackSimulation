from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from time import sleep
from queue import Empty
import os
from datetime import datetime



def attacker_backend (guiToAttacker, attackerToGui, processAtoProcessB, processBtoProcessA):
    senderPublicKeyIntercepted = False
    receiverPublicKeyIntercepted = False
    AESKeyIntercepted = False

    # User's keys for man-in-the-middle-attack
    user_public_key = ''
    receiver_public_pem = ''
    receiver_public_key = ''
    aes_key = ''
    hmac = ''

    # Creating own RSA key for man-in-the-middle attack
    attacker_secret_code = "Unguessable"
    attacker_key = RSA.generate(2048)
    attacker_private_key = attacker_key
    attacker_public_key = attacker_key.publickey()
    attacker_public_pem = attacker_public_key.export_key()


    while True:
        attack_type = ''
        attack_message_body = ''
        attack_message = guiToAttacker.get()

        try:
            attack_type = attack_message.status
            attacker_message_body = attack_message.body
        except:
            print("Attacker message not correct data type")

        match attack_type:
            case 'AvailabilityAttack':
                attack_type = ''
                attacking = True
                print("Availability Attack Start")
                while attacking:
                    message = "Flooding the channels"

                    # Flood channel from process A to process B
                    try:
                        processAtoProcessB.put_nowait(message.encode())
                    except:
                        pass

                    # Flood channel from process B to process A
                    try:
                        processBtoProcessA.put_nowait(message.encode())
                    except:
                        pass

                    # For exit message from gui
                    try:
                        attack_message = guiToAttacker.get_nowait()
                        attack_type = attack_message.status
                    except:
                        pass

                    if attack_type == 'AvailabilityAttack':
                        attack_type = ''
                        attacking = False

                    sleep(0.1)  # Without, will freeze other processes

                print("Availability Attack Complete")


            # Will need to run before users start to decrypt and send AES messages
            case 'ConfidentialityAttack':
                attack_type = ''
                attacking = True
                print("Confidentiality Attack Start")
                while attacking:

                    # Messages from User A ---------------------------------------------------
                    try:
                        message_from_A = processAtoProcessB.get(timeout=0.1)
                        # If User A's public key, we will store it to use later, then send our public key instead
                        if not senderPublicKeyIntercepted and b"-----BEGIN PUBLIC KEY-----" in message_from_A:
                            user_public_pem = message_from_A
                            user_public_key = RSA.import_key(message_from_A)
                            print("Attacker has intercepted User A's Public Key! Sending attacker public key instead.")
                            log_confidentiality_message("A", f"***USER_A_PUBLIC_KEY_INTERCEPTED***" + user_public_pem.decode())
                            senderPublicKeyIntercepted = True

                            processAtoProcessB.put(attacker_public_pem)

                        elif not AESKeyIntercepted and is_rsa_encrypted_message(message_from_A):
                            encrypted_aes_key = message_from_A
                            cipher_rsa = PKCS1_OAEP.new(attacker_private_key)
                            decrypted_keys = cipher_rsa.decrypt(encrypted_aes_key)
                            aes_key = decrypted_keys[:16]
                            hmac_key = decrypted_keys[16:]

                            AESKeyIntercepted = True
                            print("Intercepted RSA-encrypted AES key from User A. Encrypting with our receiver's "
                                  "public key and sending to User B")
                            # log_confidentiality_message("A", f"***AES_KEY_INTERCEPTED***" + encrypted_aes_key.decode())

                            # Encrypt the AES key with the receiver's public key
                            cipher_rsa = PKCS1_OAEP.new(receiver_public_key)
                            reEncrypted_aes_key = cipher_rsa.encrypt(aes_key + hmac_key)

                            processAtoProcessB.put(reEncrypted_aes_key)
                            sleep(5) # So Attacker doesn't eat message before B can get to it
                            print("Attacker successfully intercepting and decrypting communication now!")

                        elif AESKeyIntercepted:
                            # Decrypt message and read
                            tag = message_from_A[:32]
                            nonce = message_from_A[32:40]
                            ciphertext = message_from_A[40:]

                            try:
                                hmac = HMAC.new(hmac_key, digestmod=SHA256)
                                tag = hmac.update(nonce + ciphertext).verify(tag)
                            except ValueError:
                                print("The message was modified!")

                            cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
                            messageA = cipher.decrypt(ciphertext)
                            print("ATTACKER INTERCEPTED AND DECRYPTED MESSAGE FROM USER A: ", messageA.decode())
                            log_confidentiality_message("A", messageA.decode())

                            # # Reencrypt message
                            # cipher = AES.new(aes_key, AES.MODE_CTR)
                            # ciphertext = cipher.encrypt(message_from_A)
                            #
                            # hmac = HMAC.new(hmac_key, digestmod=SHA256)
                            # tag = hmac.update(cipher.nonce + ciphertext).digest()

                            # Send encrypted message
                            # encrypted_data = tag + cipher.nonce + ciphertext
                            processAtoProcessB.put(message_from_A)

                        else:
                            print("ATTACKER INTERCEPTED MESSAGE FROM USER A, but couldn't decrypt: ", message_from_A)
                            log_confidentiality_message("A", message_from_A)
                            processAtoProcessB.put(message_from_A)


                    except Exception as e:
                        if not isinstance(e, Empty):
                            print(f"Error occurred: {e}")
                        pass


                    # Messages from User B --------------------------------------------------------
                    try:
                        message_from_B = processBtoProcessA.get(timeout=0.1)

                        # If User A's public key, we will store it to use later, then send our public key instead
                        if not receiverPublicKeyIntercepted and b"-----BEGIN PUBLIC KEY-----" in message_from_B:
                            receiver_public_pem = message_from_B
                            receiver_public_key = RSA.import_key(message_from_B)
                            print("Attacker has intercepted User B's Public Key! Sending attacker public key instead.")
                            log_confidentiality_message("A", f"***USER_B_PUBLIC_KEY_INTERCEPTED***" + receiver_public_pem.decode())
                            receiverPublicKeyIntercepted = True

                            processBtoProcessA.put(attacker_public_pem)

                        elif AESKeyIntercepted:
                            # Decrypt message and read
                            tag = message_from_B[:32]
                            nonce = message_from_B[32:40]
                            ciphertext = message_from_B[40:]

                            try:
                                hmac = HMAC.new(hmac_key, digestmod=SHA256)
                                tag = hmac.update(nonce + ciphertext).verify(tag)
                            except ValueError:
                                print("The message was modified!")

                            cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
                            messageB = cipher.decrypt(ciphertext)
                            print("ATTACKER INTERCEPTED AND DECRYPTED MESSAGE FROM USER B: ", messageB.decode())
                            log_confidentiality_message("B", messageB.decode())

                            # TODO: Is HMAC right if we just send the message without reenecrypting?
                            # Reencrypt message
                            # cipher = AES.new(aes_key, AES.MODE_CTR)
                            # ciphertext = cipher.encrypt(message_from_B)
                            #
                            # hmac = HMAC.new(hmac_key, digestmod=SHA256)
                            # tag = hmac.update(cipher.nonce + ciphertext).digest()
                            #
                            # # Send encrypted message
                            # encrypted_data = tag + cipher.nonce + ciphertext
                            processBtoProcessA.put(message_from_B)

                        else:
                            print("ATTACKER INTERCEPTED MESSAGE FROM USER B, but couldn't decrypt: ", message_from_B)
                            log_confidentiality_message("B", message_from_B)
                            processBtoProcessA.put(message_from_B)

                    except:
                        pass


                    # For exit message from gui
                    try:
                        attack_message = guiToAttacker.get_nowait()
                        attack_type = attack_message.status
                    except:
                        pass


                    if attack_type == 'ConfidentialityAttack':
                        attack_type = ''
                        attacking = False
                        print("Confidentiality Attack Complete")

                    sleep(0.01)

            # Will need confidentiality attack first to receive necessary keys for impersonation
            case 'IntegrityAttack':
                print("Integrity Attack begin")

                if AESKeyIntercepted:
                    # Attacker will send message with AES encryption

                    cipher = AES.new(aes_key, AES.MODE_CTR)
                    log_integrity_attack_message(attacker_message_body)
                    ciphertext = cipher.encrypt(attacker_message_body.encode())

                    hmac = HMAC.new(hmac_key, digestmod=SHA256)
                    tag = hmac.update(cipher.nonce + ciphertext).digest()



                    # Send encrypted message
                    encrypted_data = tag + cipher.nonce + ciphertext

                    processAtoProcessB.put(encrypted_data)
                    processBtoProcessA.put(encrypted_data)
                else:
                    print("AES key was never intercepted. Restart, run confidentiality attack first to intercept keys")
                    # Sending as plain text
                    processAtoProcessB.put(attacker_message_body.encode())
                    processBtoProcessA.put(attacker_message_body.encode())


            case _:     # Default Case
                print("Invalid attack type")


def log_confidentiality_message(source: str, message: str):
    os.makedirs("attacker_logs", exist_ok=True)  # Ensure directory exists
    log_path = "attacker_logs/confidentiality_attack_message_logs.txt"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write(f"[{timestamp}] From {source}: {message}\n")

def log_integrity_attack_message(message: str):
    os.makedirs("attacker_logs", exist_ok=True)  # Ensure the log directory exists
    log_path = "attacker_logs/integrity_attack_message_logs.txt"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write(f"[{timestamp}] Integrity Attack Sent: {message}\n")


# To check for encrypted AES key
def is_rsa_encrypted_message(data: bytes, key_size_bits=2048) -> bool:
    expected_len = key_size_bits // 8
    return isinstance(data, bytes) and len(data) == expected_len

