from queue import Queue

# Class containing 2 queues for bidirectional thread communication
class DoubleQueue:
    def __init__(self):
        self.q1 = Queue()
        self.q2 = Queue()



