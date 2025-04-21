import tkinter as tk

class Guis:
    def __init__(self):

        self.root = tk.Tk(screenName="user", className='TK')
        self.root.withdraw()

        self._create_user_window_("A")
        self._create_user_window_("B")

    def run(self):
        self.root.mainloop()

    def _create_user_window_(self, username):
        win = tk.Toplevel()
        win.resizable(height=False, width=False
                      )
        win.title("User " + username + ":")

        user_label = tk.Label(win, text="User " + username + ":")
        user_label.pack()

        message = tk.Message(win, text="Message will appear here", foreground="grey")
        message.pack()

        entry = tk.Text(win, height=10, width=40)
        entry.pack(padx=10, pady=10)

        button = tk.Button(win, text='Send')
        button.pack()

