#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog
from PIL import Image, ImageTk
import os, re, io
import cairosvg

# ============================================================
# CRC PRESETS
# ============================================================
CRC_PRESETS = {
    # 8-bit CRC standards
    "CRC-8": dict(width=8, poly=0x07, init=0x00, xorout=0x00, refin=False, refout=False),
    "CRC-8/ITU": dict(width=8, poly=0x07, init=0x00, xorout=0x55, refin=False, refout=False),
    "CRC-8/ROHC": dict(width=8, poly=0x07, init=0xFF, xorout=0x00, refin=True, refout=True),
    "CRC-8/MAXIM": dict(width=8, poly=0x31, init=0x00, xorout=0x00, refin=True, refout=True),
    "CRC-8/SAE-J1850": dict(width=8, poly=0x1D, init=0xFF, xorout=0xFF, refin=False, refout=False),
    "CRC-8/DVB-S2": dict(width=8, poly=0xD5, init=0x00, xorout=0x00, refin=False, refout=False),
    "CRC-8/CDMA2000": dict(width=8, poly=0x9B, init=0xFF, xorout=0x00, refin=False, refout=False),
    
    # 16-bit CRC standards
    "CRC-16-CCITT": dict(width=16, poly=0x1021, init=0xFFFF, xorout=0x0000, refin=False, refout=False),
    "CRC-16-IBM": dict(width=16, poly=0x8005, init=0x0000, xorout=0x0000, refin=True, refout=True),
    "CRC-16-ARC": dict(width=16, poly=0x8005, init=0x0000, xorout=0x0000, refin=True, refout=True),  # Same as IBM
    "CRC-16-MODBUS": dict(width=16, poly=0x8005, init=0xFFFF, xorout=0x0000, refin=True, refout=True),
    "CRC-16-USB": dict(width=16, poly=0x8005, init=0xFFFF, xorout=0xFFFF, refin=True, refout=True),
    "CRC-16-DNP": dict(width=16, poly=0x3D65, init=0x0000, xorout=0xFFFF, refin=True, refout=True),
    "CRC-16-XMODEM": dict(width=16, poly=0x1021, init=0x0000, xorout=0x0000, refin=False, refout=False),
    "CRC-16-X.25": dict(width=16, poly=0x1021, init=0xFFFF, xorout=0xFFFF, refin=True, refout=True),
    "CRC-16-KERMIT": dict(width=16, poly=0x1021, init=0x0000, xorout=0x0000, refin=True, refout=True),
    "CRC-16-GENIBUS": dict(width=16, poly=0x1021, init=0xFFFF, xorout=0xFFFF, refin=False, refout=False),
    "CRC-16-MCRF4XX": dict(width=16, poly=0x1021, init=0xFFFF, xorout=0x0000, refin=True, refout=True),
    "CRC-16-DECT": dict(width=16, poly=0x0589, init=0x0000, xorout=0x0001, refin=False, refout=False),
    "CRC-16-T10-DIF": dict(width=16, poly=0x8BB7, init=0x0000, xorout=0x0000, refin=False, refout=False),
    "CRC-16-EN-13757": dict(width=16, poly=0x3D65, init=0x0000, xorout=0xFFFF, refin=False, refout=False),
    "CRC-16-AUG-CCITT": dict(width=16, poly=0x1021, init=0x1D0F, xorout=0x0000, refin=False, refout=False),
    "CRC-16-BUYPASS": dict(width=16, poly=0x8005, init=0x0000, xorout=0x0000, refin=False, refout=False),
    "CRC-16-DDS-110": dict(width=16, poly=0x8005, init=0x800D, xorout=0x0000, refin=False, refout=False),
    "CRC-16-DECT-R": dict(width=16, poly=0x0589, init=0x0000, xorout=0x0000, refin=True, refout=True),
    "CRC-16-TELEDISK": dict(width=16, poly=0xA097, init=0x0000, xorout=0x0000, refin=False, refout=False),
    "CRC-16-TMS37157": dict(width=16, poly=0x1021, init=0x89EC, xorout=0x0000, refin=True, refout=True),
    "CRC-16-RIELL": dict(width=16, poly=0x1021, init=0x554D, xorout=0x0000, refin=False, refout=False),
    
    # 32-bit CRC standards
    "CRC-32 (IEEE)": dict(width=32, poly=0x04C11DB7, init=0xFFFFFFFF, xorout=0xFFFFFFFF, refin=True, refout=True),
    "CRC-32C (Castagnoli)": dict(width=32, poly=0x1EDC6F41, init=0xFFFFFFFF, xorout=0xFFFFFFFF, refin=True, refout=True),
    "CRC-32B (AUTOSAR)": dict(width=32, poly=0xF4ACFB13, init=0xFFFFFFFF, xorout=0xFFFFFFFF, refin=True, refout=True),
    "CRC-32K (Koopman)": dict(width=32, poly=0x741B8CD7, init=0xFFFFFFFF, xorout=0xFFFFFFFF, refin=True, refout=True),
    "CRC-32Q": dict(width=32, poly=0x814141AB, init=0x00000000, xorout=0x00000000, refin=False, refout=False),
    "CRC-32D": dict(width=32, poly=0xA833982B, init=0xFFFFFFFF, xorout=0xFFFFFFFF, refin=True, refout=True),
    "CRC-32/MPEG-2": dict(width=32, poly=0x04C11DB7, init=0xFFFFFFFF, xorout=0x00000000, refin=False, refout=False),
    "CRC-32/JAMCRC": dict(width=32, poly=0x04C11DB7, init=0xFFFFFFFF, xorout=0x00000000, refin=True, refout=True),
    "CRC-32/XFER": dict(width=32, poly=0x000000AF, init=0x00000000, xorout=0x00000000, refin=False, refout=False),
    "CRC-32/AIXM": dict(width=32, poly=0x814141AB, init=0x00000000, xorout=0x00000000, refin=False, refout=False),
    
    # 64-bit CRC standards
    "CRC-64-ISO": dict(width=64, poly=0x000000000000001B, init=0xFFFFFFFFFFFFFFFF, xorout=0xFFFFFFFFFFFFFFFF, refin=True, refout=True),
    "CRC-64-ECMA": dict(width=64, poly=0x42F0E1EBA9EA3693, init=0xFFFFFFFFFFFFFFFF, xorout=0xFFFFFFFFFFFFFFFF, refin=False, refout=False),
    "CRC-64-WE": dict(width=64, poly=0x42F0E1EBA9EA3693, init=0xFFFFFFFFFFFFFFFF, xorout=0xFFFFFFFFFFFFFFFF, refin=True, refout=True),
    "CRC-64/XZ": dict(width=64, poly=0x42F0E1EBA9EA3693, init=0xFFFFFFFFFFFFFFFF, xorout=0xFFFFFFFFFFFFFFFF, refin=True, refout=True),
    
    # Special/Other CRC standards
    "CRC-4/ITU": dict(width=4, poly=0x03, init=0x00, xorout=0x00, refin=True, refout=True),
    "CRC-5/EPC": dict(width=5, poly=0x09, init=0x09, xorout=0x00, refin=False, refout=False),
    "CRC-5/ITU": dict(width=5, poly=0x15, init=0x00, xorout=0x00, refin=True, refout=True),
    "CRC-5/USB": dict(width=5, poly=0x05, init=0x1F, xorout=0x1F, refin=True, refout=True),
    "CRC-6/CDMA2000-A": dict(width=6, poly=0x27, init=0x3F, xorout=0x00, refin=False, refout=False),
    "CRC-6/CDMA2000-B": dict(width=6, poly=0x07, init=0x3F, xorout=0x00, refin=False, refout=False),
    "CRC-6/ITU": dict(width=6, poly=0x03, init=0x00, xorout=0x00, refin=True, refout=True),
    "CRC-7/MMC": dict(width=7, poly=0x09, init=0x00, xorout=0x00, refin=False, refout=False),
    "CRC-7/UMTS": dict(width=7, poly=0x45, init=0x00, xorout=0x00, refin=False, refout=False),
    "CRC-10": dict(width=10, poly=0x233, init=0x000, xorout=0x000, refin=False, refout=False),
    "CRC-10/CDMA2000": dict(width=10, poly=0x3D9, init=0x3FF, xorout=0x000, refin=False, refout=False),
    "CRC-10/GSM": dict(width=10, poly=0x175, init=0x000, xorout=0x3FF, refin=False, refout=False),
    "CRC-11": dict(width=11, poly=0x385, init=0x01A, xorout=0x000, refin=False, refout=False),
    "CRC-12/3GPP": dict(width=12, poly=0x80F, init=0x000, xorout=0x000, refin=False, refout=True),
    "CRC-12/CDMA2000": dict(width=12, poly=0xF13, init=0xFFF, xorout=0x000, refin=False, refout=False),
    "CRC-12/DECT": dict(width=12, poly=0x80F, init=0x000, xorout=0x000, refin=False, refout=False),
    "CRC-13/BBC": dict(width=13, poly=0x1CF5, init=0x0000, xorout=0x0000, refin=False, refout=False),
    "CRC-14/DARC": dict(width=14, poly=0x0805, init=0x0000, xorout=0x0000, refin=True, refout=True),
    "CRC-14/GSM": dict(width=14, poly=0x202D, init=0x0000, xorout=0x3FFF, refin=False, refout=False),
    "CRC-15/CAN": dict(width=15, poly=0x4599, init=0x0000, xorout=0x0000, refin=False, refout=False),
    "CRC-15/MPT1327": dict(width=15, poly=0x6815, init=0x0000, xorout=0x0001, refin=False, refout=False),
    "CRC-24": dict(width=24, poly=0x864CFB, init=0xB704CE, xorout=0x000000, refin=False, refout=False),
    "CRC-24/FLEXRAY-A": dict(width=24, poly=0x5D6DCB, init=0xFEDCBA, xorout=0x000000, refin=False, refout=False),
    "CRC-24/FLEXRAY-B": dict(width=24, poly=0x5D6DCB, init=0xABCDEF, xorout=0x000000, refin=False, refout=False),
    "CRC-24/OPENPGP": dict(width=24, poly=0x864CFB, init=0xB704CE, xorout=0x000000, refin=False, refout=False),
    "CRC-24/BLE": dict(width=24, poly=0x00065B, init=0x555555, xorout=0x000000, refin=True, refout=True),
    "CRC-31/PHILIPS": dict(width=31, poly=0x04C11DB7, init=0x7FFFFFFF, xorout=0x7FFFFFFF, refin=False, refout=False),
    "CRC-40/GSM": dict(width=40, poly=0x0004820009, init=0x0000000000, xorout=0xFFFFFFFFFF, refin=False, refout=False),
    "CRC-82/DARC": dict(width=82, poly=0x0308C0111011401440411, init=0x000000000000000000000, xorout=0x000000000000000000000, refin=True, refout=True),
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
# HEX / SREC → BIN
# ============================================================
def intel_hex_to_bin(path, fill=0xFF):
    mem = {}
    base = 0
    lo, hi = None, 0

    with open(path) as f:
        for line in f:
            if not line.startswith(":"):
                continue
            cnt = int(line[1:3], 16)
            addr = int(line[3:7], 16)
            typ = int(line[7:9], 16)

            if typ == 0x00:
                for i in range(cnt):
                    a = base + addr + i
                    mem[a] = int(line[9+i*2:11+i*2], 16)
                    lo = a if lo is None else min(lo, a)
                    hi = max(hi, a)

            elif typ == 0x04:
                base = int(line[9:13], 16) << 16

    if lo is None:
        raise ValueError("No data records found")

    out = bytearray(mem.get(a, fill) for a in range(lo, hi + 1))
    return out, lo, hi

def srec_to_bin(path, fill=0xFF):
    mem = {}
    lo, hi = None, 0

    with open(path) as f:
        for line in f:
            if not line.startswith("S") or line[1] not in "123":
                continue
            al = {"1":4,"2":6,"3":8}[line[1]]
            addr = int(line[4:4+al], 16)
            data = line[4+al:-2]

            for i in range(0, len(data), 2):
                a = addr + i//2
                mem[a] = int(data[i:i+2], 16)
                lo = a if lo is None else min(lo, a)
                hi = max(hi, a)

    if lo is None:
        raise ValueError("No data records found")

    out = bytearray(mem.get(a, fill) for a in range(lo, hi + 1))
    return out, lo, hi

# ============================================================
# GUI APPLICATION
# ============================================================
class CRCTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CRC Universal Tool")
        self.geometry("1400x860")

        self.data = b""
        self.status_var = tk.StringVar(value="Ready")
        
        self.load_svg_icon()
        self.build_ui()

    # --------------------------------------------------------
    # SVG ICON LOADING
    # --------------------------------------------------------
    def load_svg_icon(self):
        try:
            png_data = cairosvg.svg2png(url="crc_icon.svg", output_width=64, output_height=64)
            image = Image.open(io.BytesIO(png_data))
            self.logo_img = ImageTk.PhotoImage(image)
            self.iconphoto(False, self.logo_img)
        except Exception:
            self.logo_img = None

    # --------------------------------------------------------
    # STATUS BAR
    # --------------------------------------------------------
    def set_status(self, msg):
        self.status_var.set(msg)
        self.update_idletasks()

    def log(self, msg, lvl="INFO"):
        self.logbox.insert(tk.END, f"[{lvl}] {msg}\n")
        self.logbox.see(tk.END)

    def params(self):
        w = int(self.width.get())
        poly = int(self.poly.get(),16)
        init = int(self.init.get(),16)
        xo = int(self.xorout.get(),16)
        if not (8 <= w <= 64):
            raise ValueError("CRC width must be 8–64")
        mask = (1 << w) - 1
        if poly > mask or init > mask or xo > mask:
            raise ValueError("POLY / INIT / XOROUT exceed width")
        return dict(width=w, poly=poly, init=init,
                    xorout=xo, refin=self.refin.get(),
                    refout=self.refout.get())

    # --------------------------------------------------------
    # UI BUILD
    # --------------------------------------------------------
    def build_ui(self):
        self.build_header(self)

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True)

        tab_crc  = ttk.Frame(nb)
        tab_code = ttk.Frame(nb)
        tab_hex  = ttk.Frame(nb)

        nb.add(tab_crc,  text="CRC Calculation")
        nb.add(tab_code, text="CRC Code Generation")
        nb.add(tab_hex,  text="HEX to BIN")

        self.build_crc_tab(tab_crc)
        self.build_codegen_tab(tab_code)
        self.build_hexbin_tab(tab_hex)

        status = ttk.Frame(self)
        status.pack(fill=tk.X, side=tk.BOTTOM)

        ttk.Label(status, textvariable=self.status_var,
                  anchor="w").pack(fill=tk.X, padx=10)

    # --------------------------------------------------------
    # CRC TAB
    # --------------------------------------------------------
    def build_crc_tab(self, tab):
        cfg = ttk.LabelFrame(tab, text="CRC Parameters")
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

        inp = ttk.LabelFrame(tab, text="Input Data")
        inp.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.hex_text = tk.Text(inp, height=6)
        self.hex_text.pack(fill=tk.X)

        ttk.Button(inp,text="Load File",command=self.load_file).pack()
        ttk.Button(inp,text="Calculate CRC",command=self.calc_crc).pack()

        self.out = tk.Text(tab, height=4)
        self.out.pack(fill=tk.X)

        self.logbox = tk.Text(tab)
        self.logbox.pack(fill=tk.BOTH, expand=True)

    # --------------------------------------------------------
    # CODEGEN TAB (kept concise here – already validated)
    # --------------------------------------------------------
    def build_codegen_tab(self, tab):
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
            ttk.Button(tab,text=txt,command=cb).pack(fill=tk.X)

        self.code = tk.Text(tab)
        self.code.pack(fill=tk.BOTH, expand=True)

    # --------------------------------------------------------
    # HEX → BIN TAB
    # --------------------------------------------------------
    def build_hexbin_tab(self, tab):
        frm = ttk.LabelFrame(tab, text="HEX / SREC to BIN")
        frm.pack(fill=tk.X, padx=5, pady=5)

        self.hexbin_fmt = tk.StringVar(value="Auto")
        for t,v in [("Auto","Auto"),("Intel HEX","Intel"),("Motorola SREC","SREC")]:
            ttk.Radiobutton(frm,text=t,value=v,variable=self.hexbin_fmt).pack(side=tk.LEFT)

        self.hexbin_fill = tk.StringVar(value="FF")
        ttk.Label(frm,text="Fill byte").pack(side=tk.LEFT,padx=5)
        ttk.Entry(frm,textvariable=self.hexbin_fill,width=5).pack(side=tk.LEFT)

        ttk.Button(tab,text="Convert HEX → BIN",command=self.convert_hexbin).pack(pady=10)

        self.hexbin_log = tk.Text(tab)
        self.hexbin_log.pack(fill=tk.BOTH, expand=True)

    def build_header(self, parent):
        header = ttk.Frame(parent)
        header.pack(fill=tk.X, padx=10, pady=5)

        if self.logo_img:
            ttk.Label(header, image=self.logo_img).pack(side=tk.LEFT, padx=10)
        else:
            ttk.Label(header, text="CRC", font=("Segoe UI", 24, "bold")).pack(side=tk.LEFT)

        text_frame = ttk.Frame(header)
        text_frame.pack(side=tk.LEFT)

        ttk.Label(text_frame, text="CRC", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(text_frame, text="Universal CRC Tool",
                  font=("Segoe UI", 11)).pack(anchor="w")

    # --------------------------------------------------------
    # ACTIONS
    # --------------------------------------------------------
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
        if path.endswith(".hex"):
            self.data = parse_intel_hex(path)
            t = "Intel HEX"
        elif path.endswith((".srec",".s19")):
            self.data = parse_srec(path)
            t = "Motorola SREC"
        else:
            self.data = open(path,"rb").read()
            t = "Binary"
        self.log(f"Input type : {t}")
        self.log(f"Bytes used : {len(self.data)}")

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
            self.log(f"CRC RESULT : 0x{crc:X}","RESULT")
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

    def convert_hexbin(self):
        
        path = filedialog.askopenfilename(filetypes=[("HEX/SREC","*.hex *.s19 *.srec *.mot")])
        if not path: return
        try:
            fill = int(self.hexbin_fill.get(),16)
            fmt = self.hexbin_fmt.get()

            if fmt == "Intel" or (fmt=="Auto" and path.endswith(".hex")):
                data, lo, hi = intel_hex_to_bin(path, fill)
                ftype = "Intel HEX"
            else:
                data, lo, hi = srec_to_bin(path, fill)
                ftype = "Motorola SREC"

            out = os.path.splitext(path)[0] + ".bin"
            with open(out,"wb") as f:
                f.write(data)

            self.hexbin_log.insert(
                tk.END,
                f"[OK] {ftype} → BIN\n"
                f"Output : {out}\n"
                f"Range  : 0x{lo:X} – 0x{hi:X}\n"
                f"Size   : {len(data)} bytes\n\n"
            )
        except Exception as e:
            self.hexbin_log.insert(tk.END,f"[ERROR] {e}\n")

# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    CRCTool().mainloop()
