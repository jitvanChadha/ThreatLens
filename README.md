# ThreatLens 🔍🛡️

> **Local-First SLM Security Analyzer with RAG Knowledge Base & Context7 Integration**

ThreatLens is an intelligent, privacy-preserving application security testing studio powered by a local Small Language Model (**Qwen 2.5 Coder 7B**) running via Ollama. It analyzes source code for Common Weakness Enumerations (CWEs), flags vulnerabilities with pinpoint accuracy, explains risk mechanisms, and provides one-click actionable remediation code—without transmitting sensitive proprietary code to external third-party cloud APIs.

---

## Key Features

- **Local & Privacy-Preserving**: Operates entirely on-premises using Ollama (`qwen2.5-coder:7b`). Source code never leaves your local workstation or private cloud boundary.
- **Hybrid Multi-Engine Detection**:
  - **Local SLM Engine**: High-fidelity semantic comprehension of complex data-flow and taint patterns.
  - **Deterministic Safety Net**: High-precision regex pattern scanner operating in parallel to catch baseline signatures and eliminate false negatives.
  - **Deterministic False Positive Filter**: AST & semantic filter that eliminates false alarms on safe practices (e.g., parameterized SQL queries, result fetching, already implemented remediations).
- **RAG Knowledge Base**: Persistent ChromaDB vector database pre-seeded with CWE taxonomies, reference attack payloads, and security remediation patterns. Automatically vectorizes and indexes ingested codebases.
- **Context7 Integration**: Dynamic enrichment of analyzer prompts with security guidelines and documentation for third-party libraries.
- **Interactive Security Studio (UI)**:
  - **Security Check**: Monaco code editor with live syntax highlighting, line annotations, sequential retro terminal typewriter findings stream, and one-click fix application.
  - **Security Debugger & Trace Simulator**: Interactive taint-analysis engine visualizing payload execution from entry points to dangerous sinks.
  - **Batch File Ingestion**: Upload individual files, directories, or compressed `.zip` archives for automated security audits and RAG indexation.
  - **Hardened Code Writer**: Production-ready code generator templates with built-in defenses against command injection, SQL injection, path traversal, and weak hashing.
  - **Live Diagnostics**: Real-time status monitoring of Ollama model availability, memory footprint, vector store corpus statistics, and backend connectivity.

---

## Supported CWE Classes

ThreatLens currently detects and remediates 10 core vulnerability classes:

| CWE ID | Vulnerability Class | Primary Risk Vector |
| :--- | :--- | :--- |
| **CWE-78** | OS Command Injection | Shell invocation via unsanitized strings (`os.system`, `subprocess.call(shell=True)`) |
| **CWE-798** | Hardcoded Credentials | Embedded secrets, API keys, passwords, private keys, and tokens |
| **CWE-89** | SQL Injection | Raw SQL string interpolation / formatting without parameterization |
| **CWE-79** | Cross-Site Scripting (XSS) | Direct injection of untrusted parameters into rendered HTML output |
| **CWE-22** | Path Traversal | File path concatenation allowing unauthorized directory escaping (`../`) |
| **CWE-502** | Insecure Deserialization | Arbitrary code execution via untrusted object unpickling (`pickle.loads`) |
| **CWE-918** | Server-Side Request Forgery (SSRF) | Server requests to arbitrary / internal endpoints and cloud metadata services |
| **CWE-327** | Broken / Risky Cryptography | Outdated or collision-prone cryptographic primitives (e.g., MD5, SHA1) |
| **CWE-330** | Insecure Randomness | Cryptographically weak pseudorandom generators (`random` vs. `secrets`) |
| **CWE-20** | Improper Input Validation | Missing boundary, type, or range verification on sensitive parameters |

---

## System Architecture

```
                      ┌────────────────────────────────────────┐
                      │        ThreatLens Studio (React)        │
                      │   Monaco Editor • Terminal Findings    │
                      └───────────────────┬────────────────────┘
                                          │ HTTP / JSON
                                          ▼
                      ┌────────────────────────────────────────┐
                      │          FastAPI Backend Engine        │
                      │         (REST API : Port 8000)         │
                      └────┬──────────────┬──────────────┬─────┘
                           │              │              │
                           ▼              ▼              ▼
                    ┌────────────┐ ┌────────────┐ ┌────────────┐
                    │ Determin-  │ │ ChromaDB   │ │ Context7   │
                    │ istic      │ │ Vector RAG │ │ Library    │
                    │ Scanner    │ │ Storage    │ │ Docs API   │
                    └────────────┘ └────────────┘ └────────────┘
                           │              │              │
                           └──────────────┼──────────────┘
                                          │ Augmented Prompt
                                          ▼
                           ┌───────────────────────────┐
                           │      Local Ollama SLM     │
                           │   (qwen2.5-coder:7b)      │
                           └──────────────┬────────────┘
                                          │ Raw JSON Stream
                                          ▼
                           ┌───────────────────────────┐
                           │   False Positive Filter   │
                           │  (AST & Semantic Verifier)│
                           └──────────────┬────────────┘
                                          │ Clean Verified Output
                                          ▼
                                 Returned to UI
```

---

## Prerequisites

1. **Python**: 3.10 or higher
2. **Node.js**: v18 or higher (with `npm`)
3. **Ollama**: Installed from [ollama.com](https://ollama.com)

---

## Quick Start Guide

### 1. Launch Ollama & Model

Open a terminal to download and start the local model:

```bash
# Pull and start the specialized code model
ollama pull qwen2.5-coder:7b
ollama run qwen2.5-coder:7b
```

*(Ollama listens locally on `http://127.0.0.1:11434`)*

---

### 2. Start the Backend API

Open a new terminal window and initialize the FastAPI service:

```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Windows (CMD):
.\.venv\Scripts\activate.bat
# Linux / macOS:
source .venv/bin/activate

# Install required dependencies
pip install -r requirements.txt

# Start FastAPI server with live reload
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

The backend documentation will be accessible at:
- Swagger UI: `http://127.0.0.1:8000/docs`
- Health Check: `http://127.0.0.1:8000/health`

---

### 3. Start the Frontend Studio

Open a third terminal window to start the Vite developer server:

```bash
cd frontend

# Install Node dependencies
npm install

# Start Vite dev server
npm run dev
```

Open your browser and navigate to:
```
http://localhost:5173
```

---

## Project Structure

```
ThreatLens/
├── backend/
│   ├── domain/
│   │   ├── ingestion/             # Multi-file, directory & archive scanners
│   │   └── knowledge_base/        # ChromaDB embeddings, retriever, and corpus
│   ├── context7_client.py         # Context7 security guidelines client
│   ├── false_positive_filter.py   # AST & semantic false-positive filter
│   ├── main.py                    # FastAPI server entry point & endpoints
│   ├── ollama_client.py           # Local Ollama communication client
│   ├── prompt.py                  # Few-shot prompt builder with RAG injection
│   ├── regex_scanner.py           # High-precision deterministic regex checks
│   ├── requirements.txt           # Python dependency specifications
│   └── schema.py                  # Pydantic schema validation models
├── frontend/
│   ├── public/                    # Static assets & icons
│   ├── src/
│   │   ├── assets/                # Visual media, logos, and textures
│   │   ├── components/            # UI components (FindingCard, Navigation, Modals)
│   │   │   └── views/             # Views (DebuggerView, IngestCodeView, CodeWriterView)
│   │   ├── utils/                 # Hooks, sample code snippets, and typewriter logic
│   │   ├── App.jsx                # Core application layout & state coordinator
│   │   └── index.css              # Custom styling & retro terminal theme tokens
│   └── package.json               # Frontend dependencies & scripts
├── run_guide.txt                  # Concise command-line reference cheatsheet
├── .gitignore                     # Git exclusion rules
└── README.md                      # Comprehensive project documentation
```

---

