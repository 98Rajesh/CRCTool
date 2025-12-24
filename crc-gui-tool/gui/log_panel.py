import tkinter as tk
from tkinter import ttk


class LogPanel(ttk.LabelFrame):
    def __init__(self, parent):
        super().__init__(parent, text="Logs")
        self._build_ui()

    def _build_ui(self):
        self.text = tk.Text(
            self,
            height=8,
            bg="#111",
            fg="#0f0",
            font=("Consolas", 9)
        )
        self.text.pack(fill="both", expand=True)

    def log(self, msg):
        self.text.insert(tk.END, msg + "\n")
        self.text.see(tk.END)
