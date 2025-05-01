from guis import Guis
from message import Message
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import sys
from DoubleQueue import  DoubleQueue
from queue import Queue, Empty
from threading import Thread

aes_key = get_random_bytes(16)
hmac_key = get_random_bytes(16)




def user_backend(name, guiToProcess, processToGui, thisProcessToOtherProcess, otherProcesstoThisProcess):

    # Receive From Gui
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

        # Receive from other user
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
                sys.exit(1)

            cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
            message = cipher.decrypt(ciphertext)
            print("Message:", message.decode())

            processToGui.put(message.decode())
        except Empty:
            pass


if __name__ == '__main__':
    message = Message('OK', "Default message")
    # guiToProcessAPipleine = DoubleQueue()
    # processAToProcessBPipleine = DoubleQueue()

    # Process A to GUI pipeline
    guiToProcessA = Queue()
    processAtoGui = Queue()

    # Process B to Process A pipeline
    processAtoProcessB = Queue()
    processBtoProcessA = Queue()

    # Process B to GUI pipeline
    processBtoGui = Queue()
    guiToProcessB = Queue()



    processA = Thread(target=user_backend, args=("User A", guiToProcessA, processAtoGui, processAtoProcessB, processBtoProcessA))
    processB = Thread(target=user_backend, args=("User B", guiToProcessB, processBtoGui, processBtoProcessA, processAtoProcessB))
    processA.start()
    processB.start()

    guis = Guis(guiToProcessA,processAtoGui, guiToProcessB, processBtoGui, message)
    guis.run()




