import tkinter as tk
from tkinter import ttk


class CRCConfigPanel(ttk.LabelFrame):
    def __init__(self, parent):
        super().__init__(parent, text="CRC Configuration")
        self._build_ui()

    def _build_ui(self):
        labels = [
            "Standard", "Width", "Polynomial",
            "Init Value", "XOR Out", "Reflect In", "Reflect Out"
        ]

        for i, label in enumerate(labels):
            ttk.Label(self, text=label + ":").grid(row=i, column=0, sticky="w")

        self.standard = ttk.Combobox(
            self,
            values=["CRC-8", "CRC-16-CCITT", "CRC-32", "CRC-32C", "Custom"],
            state="readonly"
        )
        self.standard.current(2)
        self.standard.grid(row=0, column=1, sticky="ew")

        self.width = ttk.Entry(self)
        self.poly = ttk.Entry(self)
        self.init = ttk.Entry(self)
        self.xorout = ttk.Entry(self)

        self.width.grid(row=1, column=1, sticky="ew")
        self.poly.grid(row=2, column=1, sticky="ew")
        self.init.grid(row=3, column=1, sticky="ew")
        self.xorout.grid(row=4, column=1, sticky="ew")

        self.refin = tk.BooleanVar()
        self.refout = tk.BooleanVar()

        ttk.Checkbutton(self, variable=self.refin).grid(row=5, column=1, sticky="w")
        ttk.Checkbutton(self, variable=self.refout).grid(row=6, column=1, sticky="w")

        ttk.Button(self, text="Calculate CRC").grid(
            row=7, column=0, columnspan=2, pady=5
        )
