<div align="center">
    <p align="center">
        <a href="https://learn.microsoft.com/windows/win32/debug/pe-format">
        <details>
           <summary>PE FILE MAP</summary>
          <img width="100%" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/Portable_Executable_32_bit_Structure.svg" />
        </details>
        </a>
    </p>

```mermaid
mindmap
  root((PE Feature Representations))

    Header-Based
      DOS Header
      PE Header
      COFF Header
      Optional Header
      Data Directories

    Section-Based
      Section Names
      Section Entropy
      Section Size
      Section Permissions
      Section Alignment
      Entry Point Section

    Import-Export Features
      Import Table
      Export Table
      Imported DLLs
      Imported APIs
      Delayed Imports
      Forwarded Exports

    String-Based
      ASCII Strings
      Unicode Strings
      URLs
      IP Addresses
      Registry Keys
      File Paths

    Opcode-Based
      Opcodes
      Mnemonics
      Instruction Frequency
      N-Grams
      Control Transfer Instructions

    Graph-Based
      Control Flow Graph
      Call Graph
      API Call Graph
      Dependency Graph
      AST

    Behavioral Features
      Process Creation
      File Operations
      Registry Operations
      Network Activity
      Memory Operations

    Sequence-Based
      Byte Sequence
      Instruction Sequence
      API Sequence
      Entropy Sequence
      Opcode N-Grams

    Image-Based
      Grayscale Image
      RGB Image
      Texture Features
      CNN Embeddings

    Relationship-Based
      File Reputation
      File-to-File Relation
      File-to-Host Relation
      Process Trees
      Campaign Clusters

    Security Metadata
      Authenticode Signature
      Certificate Information
      Packer Detection
      Compiler Information
      PDB Path

    ATTACK-Based
      Tactics
      Techniques
      Procedures
      Technique Frequency
      Technique Graph
```

# **[PE](https://youtube.com/playlist?list=PL9V4Zu3RroiU7nAvkoC3rN8Y6EQ_17X22&si=c5aU7aJbb4GHg8m-) Static Toolkit** | _Portable Executable (PE) Analysing Toolkit_
</div>

[![made-with-python](http://forthebadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
[![built-with-science](https://forthebadge.com/images/badges/built-with-science.svg)](https://cyberthreatdefence.com/)
[![open-source](https://forthebadge.com/images/badges/open-source.svg)](https://gitHub.com/cybersecurity-dev/)
<p align="center">
    <a href="https://github.com/cybersecurity-dev/"><img height="25" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/github.svg" alt="GitHub"></a>
    &nbsp;
    <a href="https://www.youtube.com/@CyberThreatDefense"><img height="25" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/youtube.svg" alt="YouTube"></a>
    &nbsp;
    <a href="https://cyberthreatdefence.com/my_awesome_lists"><img height="20" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/blog.svg" alt="My Awesome Lists"></a>
    <img src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/bar.gif">
</p>

```text
Windows Artifacts
│
├── Portable Executable (PE)
│   │
│   ├── EXE
│   │   ├── GUI Applications
│   │   ├── Console Applications
│   │   └── Services
│   │
│   ├── DLL
│   │   ├── Shared Libraries
│   │   ├── COM Libraries
│   │   └── API Providers
│   │
│   ├── SYS
│   │   ├── Kernel Drivers
│   │   ├── File System Drivers
│   │   └── Network Drivers
│   │
│   ├── OCX
│   │   └── ActiveX Controls
│   │
│   ├── CPL
│   │   └── Control Panel Extensions
│   │
│   ├── SCR
│   │   └── Screensavers
│   │
│   ├── COM Server
│   │   ├── In-Process COM (DLL)
│   │   └── Out-of-Process COM (EXE)
│   │
│   └── EFI
│       └── UEFI Modules
│
├── Installation Artifacts
│   │
│   ├── MSI
│   ├── CAB
│   └── Setup EXE
│
├── Script-Based Executables
│   │
│   ├── BAT
│   ├── CMD
│   ├── PS1
│   ├── VBS
│   ├── JS/JSE
│   ├── HTA
│   └── WSF
│
├── Configuration Artifacts
│   │
│   ├── REG
│   ├── INF
│   └── XML
│
└── Indirect Execution
    │
    ├── LNK
    ├── Scheduled Tasks
    ├── Services
    └── WMI
````

## 📖 Contents
- [My Awesome Lists](#my-awesome-lists)
- [Contributing](#contributing)
- [Contributors](#contributors)

<details>
 
 <summary>Install required tools on Linux</summary>
 
 ### For Ubuntu 18.04, 20.04, 22.04
 
 ```bash
 sudo apt-get update
 ```
 </details>
 
 
 <details>
 
 <summary>Install required python libs</summary>
 
 ### pip install
 ```bash
python -m venv w_pe
source w_pe/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
 ```
 
 ### conda install
 ```bash
 conda config --add channels conda-forge
 conda install --file requirements_conda.txt
 python3 setup.py install
 ```
 
 </details>


##

### My Awesome Lists
You can access the my awesome lists [here](https://cyberthreatdefence.com/my_awesome_lists)

### Contributing
[Contributions of any kind welcome, just follow the guidelines](contributing.md)!

### Contributors
[Thanks goes to these contributors](https://github.com/cybersecurity-dev/PE-Static-Toolkit/graphs/contributors)!

### License
[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0)

[🔼 Back to top](#pe-static-toolkit--portable-executable-pe-analysing-toolkit)
