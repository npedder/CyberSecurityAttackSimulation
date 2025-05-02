from Crypto.PublicKey import RSA
from time import sleep

def attacker_backend (guiToAttacker, attackerToGui, processAtoProcessB, processBtoProcessA):
    senderPublicKeyIntercepted = False
    receiverPublicKeyIntercepted = False

    # User's keys for man-in-the-middle-attack
    user_public_key = ''
    receiver_public_key = ''

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
                    message = "lol"
                    try:
                        processAtoProcessB.put_nowait(message.encode())
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

                    sleep(0.01)  # Without, will freeze other processes

                print("Availability Attack Complete")


            # Will need to run before users start to decrypt and send AES messages
            case 'ConfidentialityAttack':
                attack_type = ''
                attacking = True
                print("Confidentiality Attack Start")
                while attacking:

                    # Messages from User A
                    try:
                        message_from_A = processAtoProcessB.get(timeout=0.1)
                        print("ATTACKER INTERCEPTED MESSAGE FROM USER A: ", message_from_A)

                        # If User A's public key, we will store it to use later, then send our public key instead
                        if not senderPublicKeyIntercepted and b"-----BEGIN PUBLIC KEY-----" in message_from_A:
                            user_public_key = RSA.import_key(message_from_A)
                            print("Attacker has intercepted User A's Public Key! Sending attacker public key instead.")
                            senderPublicKeyIntercepted = True

                            processAtoProcessB.put(message_from_A)
                        else:
                            processAtoProcessB.put(message_from_A)

                    except Exception as e:
                        pass

                    # Messages from User B
                    try:
                        message_from_B = processBtoProcessA.get(timeout=0.1)
                        print("ATTACKER INTERCEPTED MESSAGE From USER B: ", message_from_B)

                        # If User A's public key, we will store it to use later, then send our public key instead
                        if not receiverPublicKeyIntercepted and b"-----BEGIN PUBLIC KEY-----" in message_from_B:
                            receiver_public_key = RSA.import_key(message_from_B)
                            print("Attacker has intercepted User B's Public Key! Sending attacker public key instead.")
                            receiverPublicKeyIntercepted = True

                            processBtoProcessA.put(message_from_B)
                        else:
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




            case 'IntegrityAttack':
                print("Integrity Attack begin")

            case _:     # Default Case
                print("Invalid attack type")

