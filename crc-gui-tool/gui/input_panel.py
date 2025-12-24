import tkinter as tk
from tkinter import ttk, filedialog


class InputPanel(ttk.LabelFrame):
    def __init__(self, parent):
        super().__init__(parent, text="Input Data")
        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(1, weight=1)

        ttk.Label(self, text="Input Type:").grid(row=0, column=0, sticky="w")
        self.input_type = ttk.Combobox(
            self,
            values=["Binary File", "HEX File (Intel/Motorola)", "Raw Hex", "Raw Binary"],
            state="readonly"
        )
        self.input_type.current(0)
        self.input_type.grid(row=0, column=1, sticky="ew", pady=2)

        ttk.Button(self, text="Browse File", command=self._browse_file)\
            .grid(row=1, column=0, sticky="w")

        self.file_path = ttk.Entry(self)
        self.file_path.grid(row=1, column=1, sticky="ew", pady=2)

        ttk.Label(self, text="Raw Input:").grid(row=2, column=0, sticky="nw")

        self.raw_text = tk.Text(self, height=10)
        self.raw_text.grid(row=2, column=1, sticky="nsew", pady=2)

    def _browse_file(self):
        file = filedialog.askopenfilename()
        if file:
            self.file_path.delete(0, tk.END)
            self.file_path.insert(0, file)
