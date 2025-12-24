import tkinter as tk
from tkinter import ttk

from gui.input_panel import InputPanel
from gui.crc_config_panel import CRCConfigPanel
from gui.output_panel import OutputPanel
from gui.log_panel import LogPanel


class CRCStudioApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("CRC Studio")
        self.geometry("1100x700")
        self.minsize(1000, 650)

        self._build_ui()

    def _build_ui(self):
        # ---- Main layout ----
        self.columnconfigure(0, weight=3)
        self.columnconfigure(1, weight=2)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=0)

        # Left: Input + CRC config
        left_frame = ttk.Frame(self)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Right: Output + Code gen
        right_frame = ttk.Frame(self)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        # Bottom: Logs
        log_frame = ttk.Frame(self)
        log_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        # Panels
        self.input_panel = InputPanel(left_frame)
        self.input_panel.pack(fill="both", expand=True, pady=5)

        self.crc_config_panel = CRCConfigPanel(left_frame)
        self.crc_config_panel.pack(fill="x", pady=5)

        self.output_panel = OutputPanel(right_frame)
        self.output_panel.pack(fill="both", expand=True, pady=5)

        self.log_panel = LogPanel(log_frame)
        self.log_panel.pack(fill="both", expand=True)
