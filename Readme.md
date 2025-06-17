# **Events Generation System**

## **Overview**
The **Events Generation System** automates AWS EC2 instance management and configuration for:
- DNS Tasks
- Firewall Tasks
- Web Tasks
- ZTNA-Clientless Tasks
- ZTNA-Clientbased Tasks

It uses `boto3`, `paramiko`, and `winrm` for AWS and remote operations, supporting both key-based and password-based authentication for Windows and Linux.

---

## **Quick Start**
1. **Clone the repository and install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Configure AWS CLI:**
   ```bash
   aws configure
   ```
3. **Generate AWS session before running the script:**
   ```bash
   sl aws session generate --role-name engineer --account-id 07XXXXXXXX --profile default
   ```
   Replace `07XXXXXXXX` with your AWS account ID.
5. **Start the app:**
   ```bash
   streamlit run app.py
   ```

---

## **Prerequisites**

### AWS Access and Permissions
- You must have appropriate IAM permissions to:
  - Access the AWS Management Console
  - Create and delete EC2 instances
  - Manage VPCs, Subnets, Security Groups, and Key Pairs

### Networking Configuration
- Identify or create the following networking components:
  - **VPC ID** (e.g., vpc-xxxxxxxx):
    - Go to the VPC Dashboard in the AWS Console
    - Navigate to "Your VPCs" to find or create a VPC
  - **Subnet ID** (e.g., subnet-xxxxxxxx):
    - In the VPC Dashboard, select "Subnets"
    - Use or create a subnet associated with your VPC
  - **Security Group ID** (e.g., sg-xxxxxxxx):
    - Open the EC2 Dashboard > Security Groups
    - Use or create a group with the appropriate inbound/outbound rules

### Key Pair Setup
- To enable secure SSH or RDP access to EC2 instances:
  - Open the EC2 Dashboard > Network & Security > Key Pairs
  - Click "Create Key Pair"
  - Provide a name and choose file format (.pem for Linux/macOS, .ppk for Windows)
  - Download and store the private key file securely

### Local Environment Requirements
- **Python 3.8 or higher** (check with `python --version`)
- **Remote Desktop Application (Windows App)** for accessing Windows EC2 instances via RDP
  - Install from the Microsoft Store or [download here](https://apps.microsoft.com/store/detail/remote-desktop/9WZDNCRFJ3PS)
---

## **Task-Specific Workflows**

- **DNS Tasks:** Configure DNS on Windows via WinRM (create/reuse instance, set DNS, run diagnostics).
- **Firewall Tasks:** Set up IPsec/StrongSwan on Ubuntu and manage Windows routes/gateway for secure tunneling.
- **Web Tasks:** Configure Windows for SWG traffic (proxy, PAC file, Firefox install, proxy config, connectivity test).
- **ZTNA-Clientless Tasks:** Set up Nginx with HTTPS on Linux for ZTNA private resource (create/reuse, install, configure, test).
- **ZTNA-Clientbased Tasks:** Automate Cisco ZTNA modules on Windows (create/reuse, SSH server, file transfer, install modules, replace hosts, copy certs, verify).

---

## **Troubleshooting**
- **AWS errors:** Check your credentials/session and `Config.json`.
- **Streamlit errors:** Ensure all dependencies are installed and Python version is compatible.
---


## **Project Structure (Updated)**

```plaintext
.
├── app.py                  # Entry point for managing EC2 instances and executing tasks
├── utils.py                # Shared utility functions (e.g., file operations, AWS helpers)
├── Config.json             # Configuration for instance types and tasks
├── Instance.json           # Tracks created/reused instance details
├── ipsec_details.json      # IPsec configuration details
├── requirements.txt        # Python dependencies
├── sl_auth.py              # AWS session/auth helper (if used)
├── src/
│   ├── utils.py
│   ├── DNS/
│   │   └── Tasks.py
│   ├── Firewall/
│   │   └── Tasks.py
│   ├── Web/
│   │   └── Tasks.py
│   ├── workflows/
│   │   ├── dns_workflow.py
│   │   ├── firewall_workflow.py
│   │   ├── web_workflow.py
│   │   ├── ztna_clientbased_workflow.py
│   │   └── ztna_clientless_workflow.py
│   ├── ZTNAClientbased/
│   │   ├── Tasks.py
│   │   └── files/
│   │       ├── secure_access_signing_nonprod.p7b
│   │       ├── zta-staging.txt
│   │       └── ztaEnroll_saml_commercial_int_stage.json
│   ├── ZTNAClientless/
│   │   └── Tasks.py
└── README.md               # Documentation
```
