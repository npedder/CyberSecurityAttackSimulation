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

        self.root = tk.Tk(screenName="user", className='TK')
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

        def start_session():  # Show full UI after start
            start_button.pack_forget()
            ui_frame.pack()
            update_message()

            # Tell backend to start exchange
            newMessage = Message("Start", '')
            toProcess.put(newMessage)

        def update_message():
            try:
                message_body = fromProcess.get_nowait()
                message.config(text=message_body)
            except Empty:
                pass
            win.after(100, update_message)

        win = tk.Toplevel()
        win.resizable(height=False, width=False)
        win.title("User " + username + ":")

        start_button = tk.Button(win, text='Start', command=start_session, height=3, width=20)

        start_button.pack(padx=30, pady=30)

        ui_frame = tk.Frame(win)

        user_label = tk.Label(ui_frame, text="User " + username + ":")
        user_label.pack()

        message = tk.Message(ui_frame, text="Message will appear here", foreground="grey", width=300)
        message.pack()

        entry = tk.Text(ui_frame, height=10, width=40)
        entry.pack(padx=10, pady=10)

        button = tk.Button(ui_frame, text='Send', command=send_text)
        button.pack()



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

        def start_integrity_attack():
            newMessage = Message("IntegrityAttack", '')
            self.toAttackerQueue.put(newMessage)

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

        win = tk.Toplevel()
        win.resizable(height=False, width=False)
        win.title("Attacker:")

        user_label = tk.Label(win, text="Attacker:")
        user_label.pack()

        message = tk.Message(win, text="Message will appear here", foreground="grey")
        message.pack()

        entry = tk.Text(win, height=10, width=40)
        entry.pack(padx=10, pady=10)

        send_button = tk.Button(win, text='Send', command=send_text)
        send_button.pack()

        availability_button = tk.Button(win, text='Start Availability Attack', command=availability_attack)
        availability_button.pack()

        integrity_button = tk.Button(win, text='Start Integrity Attack', command=send_text)
        integrity_button.pack()

        confidentiality_button = tk.Button(win, text='Start Confidentiality Attack', command=confidentiality_attack)
        confidentiality_button.pack()

        # Start checking for new messages
        update_message()

        return win