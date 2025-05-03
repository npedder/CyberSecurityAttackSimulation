import tkinter as tk
from message import Message
from queue import Queue, Empty


class Guis:
    def __init__(self, guiToProcessA, processAtoGui, guiToProcessB, processBtoGui, guiToAttacker, attackerToGui, message_buffer):

        self.toProcessAQueue = guiToProcessA
        self.fromProcessAQueue = processAtoGui
        self.toProcessBQueue = guiToProcessB
        self.fromProcessBQueue = processBtoGui
        self.toAttackerQueue = guiToAttacker
        self.fromAttackerQueue = attackerToGui

        self.message_buffer = message_buffer

        self.root = tk.Tk(className='TK')
        self.root.withdraw()

        self.user_A = self._create_user_window_("A", self.toProcessAQueue, self.fromProcessAQueue)
        self.user_B = self._create_user_window_("B", self.toProcessBQueue, self.fromProcessBQueue)
        self.attacker = self._create_attacker_window_()




    def run(self):
        self.root.mainloop()

    def _create_user_window_(self, username, toProcess, fromProcess):
        def send_text():
            content = entry.get("1.0", tk.END)
            newMessage = Message("OK", content)
            toProcess.put(newMessage)

        def update_message():
            try:
                message_body = fromProcess.get_nowait()
                message.config(text=message_body)

                # Unlock user B's text after OK message
                if username == "B" and message_body == "OK":
                    entry.config(state=tk.NORMAL)
                    button.config(state=tk.NORMAL)

                # === ADDED: Status update logic (based on message content) ===
                if "public key" in message_body.lower():
                    status_label.config(text="Status: Public key received")
                elif "aes" in message_body.lower() or "symmetric key" in message_body.lower():
                    status_label.config(text="Status: Symmetric key exchanged")
                elif "modified" in message_body.lower() or "altered" in message_body.lower():
                    status_label.config(text="Status: Message altered by attacker")
                else:
                    status_label.config(text="Status: Message received")
                # === END ADDED ===

            except Empty:
                pass
            win.after(100, update_message)

        win = tk.Toplevel()
        win.resizable(height=False, width=False)
        win.title("User " + username + ":")

        ui_frame = tk.Frame(win)
        ui_frame.pack(padx=30, pady=30)

        user_label = tk.Label(ui_frame, text="User " + username + ":", foreground="green")
        user_label.pack()

        message = tk.Message(ui_frame, text="Message will appear here", foreground="black", width=300)
        message.pack()

        # === ADDED: Status notifications label ===
        status_label = tk.Label(ui_frame, text="Status: Waiting for message", foreground="blue")
        status_label.pack()
        # === END ADDED ===

        entry = tk.Text(ui_frame, height=10, width=40)
        entry.pack(padx=10, pady=10)

        button = tk.Button(ui_frame, text='Send', command=send_text)
        button.pack()

        # Initially disable User B's input, only user A can type
        if username == "B":
            entry.config(state=tk.DISABLED)
            button.config(state=tk.DISABLED)

        update_message()

        return win

    def _create_attacker_window_(self):
        def send_text():
            content = entry.get("1.0", tk.END)
            newMessage = Message("OK", content)
            self.toAttackerQueue.put(newMessage)

        # Update message from the other process
        def update_message():
            try:
                # Try to fetch a message from the queue
                message_body = self.fromAttackerQueue.get_nowait()  # Non-blocking call
                message.config(text=message_body)  # Update Message widget
            except Empty:
                pass  # No message available, just continue

            # Re-run the update_message function in 100 ms
            win.after(100, update_message)

        # Tell attacker backend to stop/start the availability attack
        def availability_attack():
            newMessage = Message("AvailabilityAttack", '')
            self.toAttackerQueue.put(newMessage)

            # Change button text
            if availability_button.cget('text') == 'Start Availability Attack':
                availability_button.config(text='Stop Availability Attack ')
            else:
                availability_button.config(text='Start Availability Attack')

        def confidentiality_attack():
            newMessage = Message("ConfidentialityAttack", '')
            self.toAttackerQueue.put(newMessage)

            # Change button text
            if confidentiality_button.cget('text') == 'Start Confidentiality Attack':
                confidentiality_button.config(text='Stop Confidentiality Attack ')
            else:
                confidentiality_button.config(text='Start Confidentiality Attack')

        def integrity_attack():
            content = entry.get("1.0", tk.END)
            newMessage = Message("IntegrityAttack", content)
            self.toAttackerQueue.put(newMessage)


        win = tk.Toplevel()
        win.resizable(height=False, width=False)
        win.title("Attacker:")

        user_label = tk.Label(win, text="Attacker:", foreground="red")
        user_label.pack()

        message = tk.Message(win, text="Message will appear here", foreground="grey")
        message.pack()

        entry = tk.Text(win, height=10, width=40)
        entry.pack(padx=10, pady=10)

        # send_button = tk.Button(win, text='Send', command=send_text)
        # send_button.pack()

        confidentiality_button = tk.Button(win, text='Start Confidentiality Attack', command=confidentiality_attack)
        confidentiality_button.pack()

        integrity_button = tk.Button(win, text='Send Message as a User (Impersonation)', command=integrity_attack)
        integrity_button.pack()

        availability_button = tk.Button(win, text='Start Availability Attack', command=availability_attack)
        availability_button.pack()

        # Start checking for new messages
        update_message()

        return win