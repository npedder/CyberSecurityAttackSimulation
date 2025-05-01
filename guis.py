import tkinter as tk
from message import Message
from queue import Queue, Empty


class Guis:
    def __init__(self, guiToProcessA, processAtoGui, guiToProcessB, processBtoGui, message_buffer):

        self.toProcessAQueue = guiToProcessA
        self.fromProcessAQueue = processAtoGui
        self.toProcessBQueue = guiToProcessB
        self.fromProcessBQueue = processBtoGui

        self.message_buffer = message_buffer

        self.root = tk.Tk(screenName="user", className='TK')
        self.root.withdraw()

        self.user_A = self._create_user_window_("A", self.toProcessAQueue, self.fromProcessAQueue)
        self.user_B = self._create_user_window_("B", self.toProcessBQueue, self.fromProcessBQueue)





    def run(self):
        self.root.mainloop()

    def _create_user_window_(self, username, toProcess, fromProcess):
        def send_text():
            content = entry.get("1.0", tk.END)
            newMessage = Message("OK", content)
            toProcess.put(newMessage)

        win = tk.Toplevel()
        win.resizable(height=False, width=False)
        win.title("User " + username + ":")

        user_label = tk.Label(win, text="User " + username + ":")
        user_label.pack()

        message = tk.Message(win, text="Message will appear here", foreground="grey")
        message.pack()

        entry = tk.Text(win, height=10, width=40)
        entry.pack(padx=10, pady=10)

        button = tk.Button(win, text='Send', command=send_text)
        button.pack()

        # Update message from the other process
        def update_message():
            try:
                # Try to fetch a message from the queue
                message_body= fromProcess.get_nowait()  # Non-blocking call
                message.config(text=message_body)  # Update Message widget
            except Empty:
                pass  # No message available, just continue

            # Re-run the update_message function in 100 ms
            win.after(100, update_message)

        # Start checking for new messages
        update_message()

        return win

