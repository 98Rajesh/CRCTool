import tkinter as tk
from tkinter import ttk


class OutputPanel(ttk.LabelFrame):
    def __init__(self, parent):
        super().__init__(parent, text="Output")
        self._build_ui()

    def _build_ui(self):
        ttk.Label(self, text="CRC Result:").pack(anchor="w")

        self.result_entry = ttk.Entry(self, font=("Consolas", 12))
        self.result_entry.pack(fill="x", pady=3)

        ttk.Label(self, text="Generated Code:").pack(anchor="w")

        self.code_text = tk.Text(self, height=18, font=("Consolas", 10))
        self.code_text.pack(fill="both", expand=True)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", pady=3)

        ttk.Button(btn_frame, text="Generate C Code").pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Generate Python Code").pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Copy Code").pack(side="right", padx=5)
