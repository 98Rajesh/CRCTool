# CRC Utility GUI Tool – Specification

## 1. Overview
The CRC Utility GUI Tool is a desktop application written in Python using Tkinter.
It allows users to calculate CRC values for binary and text-based firmware files
commonly used in embedded systems and OTA workflows.

---

## 2. Supported Platforms
- Windows 10 / 11 (Primary)
- Linux (Optional)
- macOS (Optional)

---

## 3. GUI (Tkinter) – Feature-Complete Desktop Tool
+--------------------------------------------------+
|  Logo | CRC-Studio                               |
+--------------------------------------------------+
| Input Type | CRC Config | Calculate | Generate   |
+--------------------------------------------------+
| Input Viewer / File Selector                     |
|                                                  |
|  (BIN / HEX / SREC / RAW / TEXT)                  |
+--------------------------------------------------+
| CRC Result                                       |
|  CRC Value: 0xXXXXXXXX                           |
|  Width / Poly / Init / XOR / RefIn / RefOut      |
+--------------------------------------------------+
| Generated Code (C / Python) [Copy]               |
+--------------------------------------------------+
| Log Window (INFO / WARN / ERROR)                 |
+--------------------------------------------------+

---

## 4. Supported Input Formats
🔹 Auto-detection engine
🔹 User override option
🔹 Option: Include / Exclude address & metadata (important for FOTA)

| Type                  | Details                        |
| --------------------- | ------------------------------ |
| **Binary (.bin)**     | Raw firmware / images          |
| **Intel HEX**         | Full support for type 00/01/04 |
| **Motorola S-Record** | S1/S2/S3                       |
| **Raw File**          | Any file → byte stream         |
| **Hex String**        | `01 FF A0 5C`                  |
| **Binary String**     | `10101010...`                  |
| **ASCII / Text**      | Encoded as bytes               |


---

## 5. CRC Configuration (Standard + Custom)
- CRC-8
- CRC-16-IBM
- CRC-16-CCITT
- CRC-16-MODBUS
- CRC-32 (IEEE)
- CRC-32C (Castagnoli)
- CRC-64-ECMA

---

## 6. User-Defined CRC (Editable fields)
- Width (1–64)
- Polynomial
- Init value
- XOR out
- Reflect in/out
- Direct / Non-direct mode
- Final masking

---

## 7. Supported Algorithms
- Bitwise (no table)
- Table-driven (256-entry)
- Mini-table (16-entry)
- Streaming CRC (chunked update)
- File-offset-aware CRC (bootloader-safe)

---

## 8. Code Generator (Major Differentiator 🔥)
- C Code
    ✔ Table-based
    ✔ No-table (bitwise)
    ✔ Mini-table (16-entry)
    ✔ Streaming API
    ✔ Embedded-safe (no malloc)
- Python Code
    ✔ File-based
    ✔ Buffer-based
    ✔ Streaming

---

## 9. Logo (Created Programmatically or Asset)
- Concept:
    Circular arrow (data flow)
    Polynomial wave
    Binary bits
    Text: CRC-Studio
- Colors:
    Blue (data)
    Green (verification)
    Dark gray (embedded feel)
(We can auto-generate a PNG using PIL if you want.)

---

## 10. Advanced Features (Strongly Recommended 🚀)
- CRC Validation Mode
    Input expected CRC
    Tool highlights PASS / FAIL
    Ideal for bootloaders & OTA
- Offset / Range CRC
    CRC over [0x08020000 – 0x0807FFFF]
    Critical for STM32 bootloaders
- Endianness Control
    Byte / Word / DWord ordering
- Multi-CRC Compare
    Compute CRC-32 vs CRC-32C side-by-side
- Test Vector Generator
    Auto-generate known-answer tests
    Exports CSV / JSON
- CLI Version
    crc-studio --file fw.bin --crc CRC32C
- Plugin System (Future)
    Add new checksum (Adler, Fletcher, CMAC)

---

## 11. Packaging & Distribution
- Windows EXE (PyInstaller)
- Portable ZIP
- Versioned releases
- .crcproj project save/load

---

## 10. Target Users
- Embedded firmware engineers
- Automotive FOTA developers
- Validation & QA teams

---

## 12. Future Enhancements
- Custom CRC parameter editor
- Batch processing
- SHA-256 / CMAC support
- Qt GUI migration
