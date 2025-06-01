# **Events Generation System**

## **Overview**
The **Events Generation System** is a comprehensive project designed to automate the management and configuration of EC2 instances for specific tasks, including:
- **DNS Tasks**
- **Firewall Tasks**
- **Web Tasks**
- **ZTNA-Clientless Tasks**
- **ZTNA-Clientbased Tasks**

The project integrates AWS EC2 instance management, file transfers, and task-specific workflows using libraries like `boto3`, `paramiko`, and `winrm`. It also supports both **key-based authentication** and **password-based authentication** for Windows and Linux instances.

---

## **Project Structure**
The project is divided into modular components for each task:

```plaintext
.
├── main.py                  # Entry point for managing EC2 instances and executing tasks
├── utils.py                 # Shared utility functions \(e.g., file operations, AWS helpers\)
├── Config.json              # Configuration for instance types and tasks
├── Instance.json            # Tracks created/reused instance details
├── DNS/
│   └── Tasks.py             # Centralized DNS task logic
├── Firewall/
│   └── Tasks.py             # Centralized Firewall task logic
├── Web/
│   └── Tasks.py             # Centralized Web task logic
├── ZTNAClientless/
│   └── Tasks.py             # Centralized ZTNA-Clientless task logic
├── ZTNAClientbased/
│   └── Tasks.py             # Centralized ZTNA-Clientbased task logic
├── files/
│   ├── zta-staging.txt      # Hosts file for ZTNA-Clientbased tasks
│   ├── secure_access_signing_nonprod.p7b # Certificate for ZTNA-Clientbased tasks
│   ├── ztaEnroll_saml_commercial_int_stage.json # Enrollment file for ZTNA-Clientbased tasks
└── README.md                # Documentation

---

## **Task-Specific Workflows**:

#### **DNS Tasks**
- Configures DNS-specific tasks on Windows instances using WinRM.
- **Steps**:
  1. **Create/Reuse a Windows Instance**:
      - Launch or reuse a new Windows EC2 instance or reuse an existing one.
  2. **Perform DNS-Specific Configuration**:
      - Configure DNS-related settings on the instance using PowerShell commands over WinRM.
      - Examples include setting primary/secondary DNS servers or running DNS diagnostic tools.

---

#### **Firewall Tasks**
- Configures IPsec and StrongSwan on Ubuntu instances and manages routes on Windows instances for secure tunneling.
- **Steps**:
  1. **Create/Reuse Ubuntu and Windows Instances**:
      - Launch or reuse an Ubuntu instance for StrongSwan configuration.
      - Launch or reuse a Windows instance for route and gateway management.
  2. **Configure StrongSwan and IPsec on Ubuntu**:
      - Enable IP forwarding on the Ubuntu instance.
      - Install StrongSwan and configure IPsec with required parameters (e.g., left and right subnets, PSK).
      - Restart IPsec services and bring up the tunnel.
  3. **Manage Routes on Windows**:
      - Disable Firewall to allow strongswan to interact with windows
      - Add persistent routes to connect to the Ubuntu StrongSwan instance.
      - Optionally update the default gateway on the Windows instance.
      - Delete specific default routes if required to avoid conflicts.

---

#### **Web Tasks**
- Configures a Windows instance by enabling proxy settings to enable SWG Traffic.
- **Steps**:
  1. **Create/Reuse a Windows Instance**:
      - Launch or reuse a Windows EC2 instance for the web server.
  2. **Set System Proxy**:
      - Update the system proxy settings to use a PAC file specified in `Config.json`.
  3. **Install Mozilla Firefox**:
      - Download and install the latest version of Mozilla Firefox on the Linux instance.
  4. **Enable Manual Proxy Configuration in Firefox**:
      - Configure Firefox to use the proxy URL from `Config.json`.
      - Enable manual proxy configuration for HTTP and HTTPS traffic.
  5. **Launch and Verify Firefox**:
      - Launch Mozilla Firefox and verify that it uses the configured proxy settings.
      - Test internet connectivity and close Firefox.

---

#### **ZTNA-Clientless Tasks**
- Automates the setup of Nginx with HTTPS on a Linux instance for Private resource of clientless Zero Trust Network Access (ZTNA).
- **Steps**:
  1. **Create/Reuse a Linux Instance**:
      - Launch a new Linux instance or reuse an existing one.
  2. **Install Nginx**:
      - Install the Nginx web server on the instance.
  3. **Configure HTTPS**:
      - Generate a self-signed SSL certificate.
      - Update the Nginx configuration to enable both HTTP and HTTPS.
  4. **Restart Nginx**:
      - Restart the Nginx service to apply the configuration changes.
  5. **Test HTTPS Access**:
      - Verify that the instance serves content over HTTPS using the self-signed certificate.

---

#### **ZTNA-Clientbased Tasks**
- Automates the setup and configuration of Cisco ZTNA modules on a Windows instance.
- **Steps**:
  1. **Create/Reuse a Windows Instance**:
      - Launch a new Windows instance or reuse an existing one.
      - Fetch instance details, including Public IP and Administrator password.
  2. **Set Up SSH Server on Windows**:
      - Install and configure OpenSSH Server on the Windows instance.
      - Enable SSH traffic in the Windows Firewall.
  3. **Transfer Required Files**:
      - Copy the Cisco Secure Client ZIP file to the Windows instance using Paramiko SFTP.
  4. **Unzip and Process Files**:
      - Unzip the Cisco Secure Client package on the Windows instance.
      - Locate and execute the required module installers (e.g., Core VPN, DART, ZTA).
  5. **Install ZTNA Modules**:
      - Install ZTNA modules (Core VPN, DART, ZTA) using the appropriate installers from the Cisco Secure Client package.
  6. **Replace Hosts File**:
      - Modify the system `hosts` file with custom entries (e.g., staging servers) using the provided OrgID.
  7. **Copy Additional Configuration Files**:
      - Copy certificates and enrollment files to the relevant directories on the Windows instance.
  8. **Verify Configuration**:
      - Check internet connectivity, verify module installations, and ensure the instance is ready for ZTNA use.

---

## **Prerequisites**
Before running the project, ensure the following tools, libraries, and configurations are set up.

### **Tools**
1. **AWS Session Generation (Using `sl` Command)**:
   - Before running the script, ensure you have generated an AWS session.
   - Use the following command to generate the session:
     ```bash
     sl aws session generate --role-name engineer --account-id 07XXXXXXXX --profile default
     ```
   - Replace `07XXXXXXXX` with your **AWS account ID**.
   - This command will generate a temporary AWS session for the specified account.

2. **AWS CLI**:
   - Install and configure AWS CLI with access to your AWS account:
     ```bash
     aws configure
     ```

3. **Python 3.8+**:
   - Install Python 3.8 or newer.
   - Install required libraries using `pip`:
     ```bash
     pip install boto3 paramiko winrm cryptography
     ```

4. **AWS EC2 Key Pair**:
   - Ensure you have the correct `.pem` file for your AWS key pair.

---

