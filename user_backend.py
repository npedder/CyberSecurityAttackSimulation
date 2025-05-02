from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import sys
from queue import Queue, Empty
from Crypto.PublicKey import RSA
from time import sleep

def user_backend(name, guiToProcess, processToGui, thisProcessToOtherProcess, otherProcesstoThisProcess, isRSASender=False):

    # Wait for GUI Start message

    start = False
    while not start:
        try:
            start_message = guiToProcess.get()
            if start_message.status == "Start":
                start = True
        except Exception as e:
            print("Start Message not correct format",  e)
            sys.exit(1)



    # Generate the necessary keys
    aes_key = get_random_bytes(16)
    hmac_key = get_random_bytes(16)

    # Sending the AES key over RSA before starting message communication
    if isRSASender:
        secret_code = "Unguessable"
        key = RSA.generate(2048)
        private_key = key
        public_key = key.publickey()
        public_pem = public_key.export_key()

        # Send public key
        print(public_key)
        thisProcessToOtherProcess.put(public_pem)

        # Encrypt the AES key with the receiver's public key
        recipient_pem = get_poll(otherProcesstoThisProcess) # Blocks until receiver's public key is received
        recipient_key = RSA.import_key(recipient_pem)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key + hmac_key)

        # Send encrypted AES key
        thisProcessToOtherProcess.put(encrypted_aes_key)

    else:   # Is RSA Receiver

        # Wait for sender's public key
        sender_public_pem = get_poll(otherProcesstoThisProcess)
        sender_public_key = RSA.import_key(sender_public_pem)

        # Generate own RSA keypair
        receiver_key = RSA.generate(2048)
        receiver_private_key = receiver_key
        receiver_public_key = receiver_key.publickey()
        receiver_public_pem = receiver_public_key.export_key()

        # Send receiver public key back to user
        thisProcessToOtherProcess.put(receiver_public_pem)

        # Receive encrypted AES key
        encrypted_aes_key = get_poll(otherProcesstoThisProcess)

        cipher_rsa = PKCS1_OAEP.new(receiver_private_key)
        decrypted_keys = cipher_rsa.decrypt(encrypted_aes_key)
        aes_key = decrypted_keys[:16]
        hmac_key = decrypted_keys[16:]


    # Receive message input From Gui
    while True:
        try:
            # Try getting data from the GUI
            outgoing_message = guiToProcess.get(timeout=0.1)
            print(name, "Received from GUI:", outgoing_message)

            # AES Encryption
            outgoing_message_data = outgoing_message.body.encode()


            cipher = AES.new(aes_key, AES.MODE_CTR)
            ciphertext = cipher.encrypt(outgoing_message_data)

            hmac = HMAC.new(hmac_key, digestmod=SHA256)
            tag = hmac.update(cipher.nonce + ciphertext).digest()

            # Send encrypted message
            encrypted_data = tag + cipher.nonce + ciphertext
            thisProcessToOtherProcess.put(encrypted_data)

        except Empty:
            pass

        # Receive message from other user
        try:
            # Try getting data from the other process
            incoming_message_data = otherProcesstoThisProcess.get(timeout=0.1)
            print(name, "Received from Other Process:", incoming_message_data)

            tag = incoming_message_data[:32]
            nonce = incoming_message_data[32:40]
            ciphertext = incoming_message_data[40:]

            try:
                hmac = HMAC.new(hmac_key, digestmod=SHA256)
                tag = hmac.update(nonce + ciphertext).verify(tag)
            except ValueError:
                print("The message was modified!")

            cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
            message = cipher.decrypt(ciphertext)
            print("Message:", message.decode())

            processToGui.put(message.decode())
        except Empty:
            sleep(0.5)
            pass

# A queue get function that polls instead of waits. We do this so there is some time for an attacker to intercept messages
def get_poll(queue, poll_rate=0.5):
    message_received = False
    while not message_received:
        try:
            poll_message = queue.get_nowait()
            message_received = True
        except:
            pass

        sleep(poll_rate)

    return poll_message
