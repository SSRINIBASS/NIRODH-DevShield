# DevShield

> **Open-Source DevSecOps Platform**
> Every developer should be able to run a complete DevSecOps security scan with a single command.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)

---

## 🛡 What is DevShield?

DevShield is a **free, privacy-first DevSecOps platform** delivered as a single Go binary with a terminal UI. It unifies best-in-class open-source security scanners behind one binary, one config file, and one unified report.

**Think of it as `golangci-lint` for full-stack security.**

### Key Features

- 🔍 **Secret Scanning** — Gitleaks (Go library, full git history)
- 🧪 **SAST** — Semgrep (coming soon)
- 📦 **SCA** — OSV-Scanner, govulncheck (coming soon)
- 🏗 **IaC Scanning** — Trivy, KICS (coming soon)
- 📋 **SBOM** — Syft, Grype (coming soon)
- 📊 **Unified Reports** — SARIF 2.1.0, HTML, JSON
- 🖥 **Terminal UI** — Bubbletea-based live progress
- 🔒 **Privacy-first** — No telemetry, no cloud uploads, fully offline capable

---

## 🚀 Quick Start

```bash
# Build from source
go build -o devshield ./cmd/devshield

# Run a scan
./devshield scan .

# Generate config
./devshield init

# Check versions
./devshield version
```

---

## 📁 Project Structure

```
devshield/
├── cmd/devshield/          # CLI entry point
├── internal/
│   ├── cli/               # Cobra commands
│   ├── tui/               # Bubbletea TUI
│   ├── scanner/           # Scanner interface + registry
│   ├── adapters/
│   │   └── gitleaks/      # Go lib adapter
│   ├── report/            # SARIF + HTML + JSON writers
│   ├── config/            # Viper config engine
│   ├── detect/            # Context detector
│   └── suppress/          # Finding suppression engine
├── pkg/
│   └── schema/            # Public types (Finding, ScanContext)
└── .devshield.yaml        # Self-scan config
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

**DevShield** — Security scanning for everyone. 🛡
