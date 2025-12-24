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

## 3. Supported Input Formats
| Format | Description |
|------|------------|
| BIN | Raw binary firmware |
| HEX | Intel HEX (data records only) |
| TXT | ASCII text |

---

## 4. Supported CRC Algorithms
- CRC-8
- CRC-16-IBM
- CRC-16-CCITT
- CRC-16-MODBUS
- CRC-32 (IEEE)
- CRC-32C (Castagnoli)
- CRC-64-ECMA

---

## 5. Functional Requirements
### FR-1 File Selection
User shall be able to browse and select input files.

### FR-2 CRC Selection
User shall be able to select CRC algorithm from dropdown.

### FR-3 CRC Calculation
Tool shall calculate CRC on:
- Raw binary bytes (BIN)
- Extracted data bytes only (HEX)
- ASCII bytes (TXT)

### FR-4 Result Display
Tool shall display:
- Selected file path
- Number of bytes processed
- Calculated CRC value (HEX)

### FR-5 Code Generation
Tool shall generate portable C source code for the selected CRC.

---

## 6. Non-Functional Requirements
- Deterministic CRC output
- No external runtime dependencies
- GUI responsiveness during file parsing
- Embedded-friendly CRC algorithms

---

## 7. Error Handling
- Invalid file type → error dialog
- Empty file → warning
- Corrupted HEX → ignore non-data records

---

## 8. Security Considerations
- Read-only file access
- No network connectivity
- No external code execution

---

## 9. Target Users
- Embedded firmware engineers
- Automotive FOTA developers
- Validation & QA teams

---

## 10. Future Enhancements
- Custom CRC parameter editor
- Batch processing
- SHA-256 / CMAC support
- Qt GUI migration
