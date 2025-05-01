class Message:
    def __init__(self, status, body):
        self.status = status
        self.body = body

    def __str__(self):
        return f'Status: ' + self.status + '\nBody: ' + self.body + '\n'