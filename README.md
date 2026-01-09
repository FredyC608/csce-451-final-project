# Malware Analysis: WannaCry Encryptor (CSCE 451)

**Final Project for CSCE 451: Software Reverse Engineering (Fall 2025)**
**Grade:** 285/300

This repository contains a formal analysis of the WannaCry ransomware "Encryptor" payload. The goal was to reverse engineer the sample to understand its persistence mechanisms, encryption strategy, and network behavior without relying on external reports.

## 📂 Contents
* `final-project-wannacry.pdf`: The full analysis report.
* `[Malware Sample Hash/Name]`: (Note: Handle live malware with caution).

## 🔧 Tools Used
* **Ghidra** (Static Analysis, Disassembly)
* **x32dbg** (Dynamic Debugging)
* **Wireshark** (Network Traffic Analysis)
* **ProcMon** (Behavioral Analysis)
* **CFF Explorer** (PE Header Analysis)
* **InetSim** (Network Simulation)

## 📝 Retrospective & Future Improvements
While the project was successful and met the course requirements, the following areas were identified for improvement to meet professional standards:

### 1. Static vs. Dynamic Analysis Consistency
* **Critique:** My initial static analysis (using CFF Explorer) concluded the sample was "unpacked" because the PE headers were standard. However, dynamic analysis later revealed the malware acts as a **Stage 1 Loader**, utilizing `VirtualAlloc` to unpack a secondary payload (the ransomware GUI) at runtime.
* **Correction:** Future analysis should statically analyze the entry point stub to identify these loader characteristics immediately, rather than having contradictory findings between the static and dynamic phases.

### 2. Depth of Disassembly
* **Critique:** I successfully fully disassembled one key function (`InitializeRansomware`) as required. However, for the rest of the binary, I relied on function imports and behavioral analysis to infer context.
* **Correction:** To provide a comprehensive analysis, I should extend the deep disassembly process to all critical functions. This involves fully reversing the logic of the payload injection and file traversal routines, rather than inferring their purpose solely from API calls and runtime behavior.

### 3. Deep Packet & Protocol Analysis
* **Critique:** The network analysis identified suspicious connections (Port 9001, `dns.msftncsi.com`) but relied on external OSINT to identify the protocol as TOR.
* **Correction:** A more robust analysis would involve inspecting the packet headers and payloads at the byte level. Even if the connection failed, analyzing the TCP handshake or the specific structure of the initial beacon would allow for confirming the protocol manually, rather than inferring it solely from the destination port.

### 4. Cryptographic Specificity
* **Critique:** The analysis identified the use of `CryptImportKey` but did not verify the specific algorithm IDs at runtime.
* **Correction:** I should set breakpoints on the crypto API calls in x32dbg to inspect the registers. This would confirm exactly which algorithm (RSA vs. AES) and key bit-length were being requested, rather than relying on string references.

### 5. Automated Remediation
* **Critique:** The paper proposed manual cleanup steps (regedit, deleting files).
* **Correction:** A robust solution would include a **Python** or **PowerShell script** to automate the termination of malicious processes (`taskse.exe`, `taskdl.exe`), wipe the `HKCU/.../Run` persistence keys, and remove dropped binaries.
