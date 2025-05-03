from guis import Guis
from message import Message
from queue import Queue
from threading import Thread
import os

# Thread method for the attacker's backend logic
from attacker_backend import attacker_backend

# Thread method for the user's backend logic
from user_backend import user_backend


if __name__ == '__main__':
    # Clear logs
    os.makedirs("attacker_logs", exist_ok=True)
    os.makedirs("user_a_logs", exist_ok=True)
    os.makedirs("user_b_logs", exist_ok=True)
    with open("attacker_logs/confidentiality_attack_message_logs.txt", "w", encoding="utf-8") as log_file:
        log_file.write("=== Confidentiality Attack Log Start ===\n")

    with open("attacker_logs/integrity_attack_message_logs.txt", "w", encoding="utf-8") as log_file:
        log_file.write("=== Integrity Attack Log Start ===\n")

    with open("user_a_logs/traffic.txt", "w", encoding="utf-8") as log_file:
        log_file.write("=== Integrity Attack Log Start ===\n")

    with open("user_b_logs/traffic.txt", "w", encoding="utf-8") as log_file:
        log_file.write("=== Integrity Attack Log Start ===\n")


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




