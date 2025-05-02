from guis import Guis
from message import Message
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import sys
from queue import Queue, Empty
from threading import Thread
from Crypto.PublicKey import RSA
from time import sleep

# Thread method for the attacker's backend logic
from attacker_backend import attacker_backend

# Thread method for the user's backend logic
from user_backend import user_backend


if __name__ == '__main__':
    message = Message('OK', "Default message")
    # guiToProcessAPipleine = DoubleQueue()
    # processAToProcessBPipleine = DoubleQueue()

    # Process A to GUI pipeline
    guiToProcessA = Queue()
    processAtoGui = Queue()

    # Process B to Process A pipeline
    processAtoProcessB = Queue(maxsize=100)
    processBtoProcessA = Queue(maxsize=100)

    # Process B to GUI pipeline
    guiToProcessB = Queue()
    processBtoGui = Queue()


    # Attacker To GUI pipeline
    guiToAttacker = Queue()
    attackerToGui = Queue()

    # Attacker Thread
    attacker = Thread(target=attacker_backend,
                      args=(guiToAttacker, attackerToGui, processAtoProcessB, processBtoProcessA))
    attacker.start()

    # Process A will start the RSA transaction, so isRSASender is True
    processA = Thread(target=user_backend,
                      args=("User A", guiToProcessA, processAtoGui, processAtoProcessB, processBtoProcessA, True))
    processB = Thread(target=user_backend,
                      args=("User B", guiToProcessB, processBtoGui, processBtoProcessA, processAtoProcessB))
    processA.start()
    processB.start()


    # User interface for users and attacker
    guis = Guis(guiToProcessA, processAtoGui, guiToProcessB, processBtoGui, guiToAttacker, attackerToGui, message)
    guis.run()




