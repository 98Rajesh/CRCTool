#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog
import os, re

# ============================================================
# CRC PRESETS
# ============================================================
CRC_PRESETS = {
    "CRC-8": dict(width=8, poly=0x07, init=0x00, xorout=0x00, refin=False, refout=False),
    "CRC-16-IBM": dict(width=16, poly=0x8005, init=0x0000, xorout=0x0000, refin=True, refout=True),
    "CRC-16-CCITT": dict(width=16, poly=0x1021, init=0xFFFF, xorout=0x0000, refin=False, refout=False),
    "CRC-32": dict(width=32, poly=0x04C11DB7, init=0xFFFFFFFF, xorout=0xFFFFFFFF, refin=True, refout=True),
    "CRC-32C": dict(width=32, poly=0x1EDC6F41, init=0xFFFFFFFF, xorout=0xFFFFFFFF, refin=True, refout=True),
    "CRC-64-ECMA": dict(width=64, poly=0x42F0E1EBA9EA3693, init=0x0, xorout=0x0, refin=False, refout=False),
    "CRC-64-ISO": dict(width=64, poly=0x1B, init=0xFFFFFFFFFFFFFFFF,
                        xorout=0xFFFFFFFFFFFFFFFF, refin=True, refout=True),
}

# ============================================================
# UTILITIES
# ============================================================
def reflect(v, bits):
    r = 0
    for i in range(bits):
        if v & (1 << i):
            r |= 1 << (bits - 1 - i)
    return r

def c_uint(width):
    if width <= 8: return "uint8_t"
    if width <= 16: return "uint16_t"
    if width <= 32: return "uint32_t"
    return "uint64_t"

# ============================================================
# INPUT PARSERS
# ============================================================
def parse_raw_hex(txt):
    txt = re.sub(r"[^0-9A-Fa-f]", "", txt)
    if len(txt) % 2:
        raise ValueError("Odd-length hex string")
    return bytes.fromhex(txt)

def parse_intel_hex(path):
    data = bytearray()
    with open(path) as f:
        for l in f:
            if l.startswith(":") and int(l[7:9], 16) == 0:
                n = int(l[1:3], 16)
                data.extend(bytes.fromhex(l[9:9+n*2]))
    return data

def parse_srec(path):
    data = bytearray()
    with open(path) as f:
        for l in f:
            if l.startswith("S") and l[1] in "123":
                al = {"1":4,"2":6,"3":8}[l[1]]
                data.extend(bytes.fromhex(l[4+al:-2]))
    return data

# ============================================================
# CRC CORE (REFERENCE)
# ============================================================
def crc_bitwise(data, width, poly, init, xorout, refin, refout):
    mask = (1 << width) - 1
    top = 1 << (width - 1)
    crc = init & mask

    for b in data:
        if refin:
            b = reflect(b, 8)
        crc ^= b << (width - 8)
        for _ in range(8):
            crc = ((crc << 1) ^ poly) if crc & top else (crc << 1)
            crc &= mask

    if refout:
        crc = reflect(crc, width)
    return crc ^ xorout

# ============================================================
# TABLE GENERATION
# ============================================================
def gen_table256(width, poly, refin):
    mask = (1 << width) - 1
    top = 1 << (width - 1)
    table = []

    for i in range(256):
        crc = i if refin else i << (width - 8)
        for _ in range(8):
            if refin:
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
            else:
                crc = (crc << 1) ^ poly if crc & top else crc << 1
        table.append(crc & mask)

    return table

def gen_table16(width, poly):
    mask = (1 << width) - 1
    top = 1 << (width - 1)
    table = []
    for i in range(16):
        crc = i << (width - 4)
        for _ in range(4):
            crc = (crc << 1) ^ poly if crc & top else crc << 1
        table.append(crc & mask)
    return table

# ============================================================
# CODE GENERATION – C & PYTHON
# ============================================================
def gen_c_bitwise(p, streaming=False):
    T = c_uint(p["width"])
    if not streaming:
        return f"""
{T} crc_calc(const uint8_t *data, size_t len)
{{
    {T} crc = 0x{p['init']:X};
    while(len--)
    {{
        crc ^= (*data++) << ({p['width']}-8);
        for(int i=0;i<8;i++)
            crc = (crc & (1ULL<<({p['width']}-1))) ?
                  (crc<<1)^0x{p['poly']:X} : (crc<<1);
    }}
    return crc ^ 0x{p['xorout']:X};
}}
"""
    return f"""
static {T} crc_init(void)
{{
    return 0x{p['init']:X};
}}

static {T} crc_update({T} crc, uint8_t data)
{{
    crc ^= ({T})data << ({p['width']}-8);
    for(int i=0;i<8;i++)
        crc = (crc & (1ULL<<({p['width']}-1))) ?
              (crc<<1)^0x{p['poly']:X} : (crc<<1);
    return crc;
}}

static {T} crc_finalize({T} crc)
{{
    return crc ^ 0x{p['xorout']:X};
}}
"""

def gen_c_bytewise(p, streaming=False):
    T = c_uint(p["width"])
    tbl = gen_table256(p["width"], p["poly"], p["refin"])
    table = ", ".join(hex(x) for x in tbl)

    if not streaming:
        return f"""
static const {T} crc_table[256] = {{ {table} }};

{T} crc_calc(const uint8_t *data, size_t len)
{{
    {T} crc = 0x{p['init']:X};
    while(len--)
        crc = (crc<<8) ^ crc_table[((crc>>({p['width']}-8)) ^ *data++) & 0xFF];
    return crc ^ 0x{p['xorout']:X};
}}
"""
    return f"""
static const {T} crc_table[256] = {{ {table} }};

static {T} crc_update({T} crc, uint8_t data)
{{
    return (crc<<8) ^ crc_table[((crc>>({p['width']}-8)) ^ data) & 0xFF];
}}
"""

def gen_c_minitable(p, streaming=False):
    T = c_uint(p["width"])
    tbl = gen_table16(p["width"], p["poly"])
    body = ", ".join(hex(x) for x in tbl)

    if not streaming:
        return f"""
static const {T} crc_mini[16] = {{ {body} }};

{T} crc_calc(const uint8_t *data, size_t len)
{{
    {T} crc = 0x{p['init']:X};
    while(len--)
    {{
        crc ^= (*data++) << ({p['width']}-8);
        crc = (crc<<4) ^ crc_mini[(crc>>({p['width']}-4)) & 0xF];
        crc = (crc<<4) ^ crc_mini[(crc>>({p['width']}-4)) & 0xF];
    }}
    return crc ^ 0x{p['xorout']:X};
}}
"""
    return f"""
static const {T} crc_mini[16] = {{ {body} }};

static {T} crc_update({T} crc, uint8_t data)
{{
    crc ^= data << ({p['width']}-8);
    crc = (crc<<4) ^ crc_mini[(crc>>({p['width']}-4)) & 0xF];
    crc = (crc<<4) ^ crc_mini[(crc>>({p['width']}-4)) & 0xF];
    return crc;
}}
"""

def gen_py_bitwise(p):
    return f"""
def crc_calc(data):
    crc = 0x{p['init']:X}
    for b in data:
        crc ^= b << ({p['width']}-8)
        for _ in range(8):
            crc = ((crc<<1)^0x{p['poly']:X}) if crc & (1<<({p['width']}-1)) else crc<<1
            crc &= {(1<<p['width'])-1}
    return crc ^ 0x{p['xorout']:X}
"""

def gen_py_bytewise(p):
    tbl = gen_table256(p["width"], p["poly"], p["refin"])
    return f"""
CRC_TABLE = {tbl}

def crc_calc(data):
    crc = 0x{p['init']:X}
    for b in data:
        crc = (crc<<8) ^ CRC_TABLE[((crc>>({p['width']}-8)) ^ b) & 0xFF]
        crc &= {(1<<p['width'])-1}
    return crc ^ 0x{p['xorout']:X}
"""

# ============================================================
# GUI
# ============================================================
class CRCTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Universal CRC Tool – Final")
        self.geometry("1350x820")
        self.data = b""
        self.build_ui()

    def log(self, msg, lvl="INFO"):
        self.logbox.insert(tk.END, f"[{lvl}] {msg}\n")
        self.logbox.see(tk.END)

    def params(self):
        w = int(self.width.get())
        poly = int(self.poly.get(),16)
        init = int(self.init.get(),16)
        xo = int(self.xorout.get(),16)
        if not (8 <= w <= 64):
            raise ValueError("Width must be 8–64")
        return dict(width=w, poly=poly, init=init,
                    xorout=xo, refin=self.refin.get(),
                    refout=self.refout.get())

    def build_ui(self):
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True)

        tab_calc = ttk.Frame(nb)
        tab_code = ttk.Frame(nb)
        nb.add(tab_calc, text="CRC Calculation")
        nb.add(tab_code, text="CRC Code Generation")

        # ---- Calculation Tab ----
        cfg = ttk.LabelFrame(tab_calc, text="CRC Parameters")
        cfg.pack(fill=tk.X, padx=5, pady=5)

        self.preset = ttk.Combobox(cfg, values=list(CRC_PRESETS.keys()))
        self.preset.pack(side=tk.LEFT)
        self.preset.bind("<<ComboboxSelected>>", self.load_preset)

        self.width  = tk.StringVar(value="32")
        self.poly   = tk.StringVar(value="04C11DB7")
        self.init   = tk.StringVar(value="FFFFFFFF")
        self.xorout = tk.StringVar(value="FFFFFFFF")
        self.refin  = tk.BooleanVar(value=True)
        self.refout = tk.BooleanVar(value=True)

        for l,v in [("Width",self.width),("Poly",self.poly),
                    ("Init",self.init),("XorOut",self.xorout)]:
            ttk.Label(cfg,text=l).pack(side=tk.LEFT)
            ttk.Entry(cfg,textvariable=v,width=12).pack(side=tk.LEFT,padx=3)

        ttk.Checkbutton(cfg,text="RefIn",variable=self.refin).pack(side=tk.LEFT)
        ttk.Checkbutton(cfg,text="RefOut",variable=self.refout).pack(side=tk.LEFT)

        inp = ttk.LabelFrame(tab_calc, text="Input")
        inp.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.hex_text = tk.Text(inp, height=6)
        self.hex_text.pack(fill=tk.X)

        ttk.Button(inp,text="Load File",command=self.load_file).pack()
        ttk.Button(inp,text="Calculate CRC",command=self.calc_crc).pack()

        self.out = tk.Text(tab_calc, height=4)
        self.out.pack(fill=tk.X)

        self.logbox = tk.Text(tab_calc)
        self.logbox.pack(fill=tk.BOTH, expand=True)

        # ---- Code Generation Tab ----
        btns = [
            ("C Bitwise", lambda:self.show(gen_c_bitwise, False)),
            ("C Bitwise (Streaming)", lambda:self.show(gen_c_bitwise, True)),
            ("C Bytewise", lambda:self.show(gen_c_bytewise, False)),
            ("C Bytewise (Streaming)", lambda:self.show(gen_c_bytewise, True)),
            ("C Mini-table", lambda:self.show(gen_c_minitable, False)),
            ("C Mini-table (Streaming)", lambda:self.show(gen_c_minitable, True)),
            ("Python Bitwise", lambda:self.show_py(gen_py_bitwise)),
            ("Python Bytewise", lambda:self.show_py(gen_py_bytewise)),
        ]

        for txt,cb in btns:
            ttk.Button(tab_code,text=txt,command=cb).pack(fill=tk.X)

        self.code = tk.Text(tab_code)
        self.code.pack(fill=tk.BOTH, expand=True)

    def load_preset(self, _):
        p = CRC_PRESETS[self.preset.get()]
        self.width.set(str(p["width"]))
        self.poly.set(f"{p['poly']:X}")
        self.init.set(f"{p['init']:X}")
        self.xorout.set(f"{p['xorout']:X}")
        self.refin.set(p["refin"])
        self.refout.set(p["refout"])
        self.log(f"Preset loaded: {self.preset.get()}")

    def load_file(self):
        path = filedialog.askopenfilename()
        if not path: return
        try:
            if path.endswith(".hex"):
                self.data = parse_intel_hex(path)
                t = "Intel HEX"
            elif path.endswith((".srec",".s19")):
                self.data = parse_srec(path)
                t = "Motorola SREC"
            else:
                self.data = open(path,"rb").read()
                t = "Binary"
            self.log(f"Input type: {t}")
            self.log(f"Bytes used: {len(self.data)}")
        except Exception as e:
            self.log(str(e),"ERROR")

    def calc_crc(self):
        try:
            raw = self.hex_text.get("1.0",tk.END).strip()
            if raw:
                self.data = parse_raw_hex(raw)
                self.log("Raw hex input used")
            if not self.data:
                self.log("No input data","WARNING")
                return
            crc = crc_bitwise(self.data, **self.params())
            self.out.delete("1.0",tk.END)
            self.out.insert(tk.END,f"CRC = 0x{crc:X}")
            self.log(f"CRC RESULT: 0x{crc:X}","RESULT")
        except Exception as e:
            self.log(str(e),"ERROR")

    def show(self, fn, streaming):
        try:
            self.code.delete("1.0", tk.END)
            self.code.insert(tk.END, fn(self.params(), streaming))
        except Exception as e:
            self.log(str(e),"ERROR")

    def show_py(self, fn):
        try:
            self.code.delete("1.0", tk.END)
            self.code.insert(tk.END, fn(self.params()))
        except Exception as e:
            self.log(str(e),"ERROR")

# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    CRCTool().mainloop()
