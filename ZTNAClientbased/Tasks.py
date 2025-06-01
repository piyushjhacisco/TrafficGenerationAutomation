import boto3
import json
import time
import winrm
import logging
import base64
import os
import subprocess
import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Paths for additional files
ZIP_FILE = "ZTNAClientbased/cisco-secure-client.zip"
HOSTS_FILE = "ZTNAClientbased/files/zta-staging.txt"
CERT_FILE = "ZTNAClientbased/files/secure_access_signing_nonprod.p7b"
ENROLLMENT_FILE = "ZTNAClientbased/files/ztaEnroll_saml_commercial_int_stage.json"

# Remote directories
REMOTE_ZIP_PATH = r"C:\Users\Administrator\Downloads\cisco-secure-client.zip"
REMOTE_UNZIP_DIR = r"C:\Users\Administrator\Downloads\cisco-secure-client"
REMOTE_CACERTS_DIR = r"C:\ProgramData\Cisco\Cisco Secure Client\ZTA\cacerts"
REMOTE_ENROLLMENT_DIR = r"C:\ProgramData\Cisco\Cisco Secure Client\ZTA\enrollment_choices"

def create_winrm_session(public_ip, username, password):
    return winrm.Session(f'http://{public_ip}:5985/wsman', auth=(username, password))


def find_installer(session, remote_path, keyword):
    try:
        # PowerShell command to search for the installer
        search_command = f"""
        Get-ChildItem -Path '{remote_path}' -Recurse -Include *.msi, *.exe |
        Where-Object {{ $_.Name -match '{keyword}' }} |
        Select-Object -ExpandProperty FullName
        """
        logging.info(f"Searching for installer with keyword '{keyword}' in '{remote_path}'...")
        result = session.run_ps(search_command)

        if result.status_code != 0:
            logging.error(f"Failed to search for installer with keyword '{keyword}': {result.std_err.decode().strip()}")
            return ""

        installer_path = result.std_out.decode().strip()
        if not installer_path:
            logging.warning(f"No installer found for keyword '{keyword}'.")
        return installer_path
    except Exception as e:
        logging.error(f"An error occurred during installer search: {str(e)}")
        return ""


def install_msi(session, installer_path, log_file):
    try:
        # PowerShell command to execute the MSI installer silently
        install_command = f"""
        Start-Process -FilePath '{installer_path}' -ArgumentList '/norestart', '/passive', '/lvx*', '{log_file}' -Wait
        """
        logging.info(f"Installing MSI '{installer_path}'...")
        result = session.run_ps(install_command)

        if result.status_code != 0:
            logging.error(f"Failed to install MSI '{installer_path}': {result.std_err.decode().strip()}")
            return False

        logging.info(f"MSI '{installer_path}' installed successfully. Logs saved to '{log_file}'.")
        return True
    except Exception as e:
        logging.error(f"An error occurred during MSI installation: {str(e)}")
        return False

def install_modules_ssh(public_ip, username, private_key_file, remote_unzip_dir, module_keywords):

    try:
        for keyword in module_keywords:
            # PowerShell command to search for installer files in the unzipped directory
            search_command = f"""
            powershell Get-ChildItem -Path '{remote_unzip_dir}' -Recurse -Include '*.exe', '*.msi' |
            Where-Object {{ $_.Name -match '{keyword}' }} | Select-Object -ExpandProperty FullName
            """

            # Execute the search command using SSH
            command = [
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-i", private_key_file,
                f"{username}@{public_ip}",
                search_command
            ]
            logging.info(f"Searching for installer with keyword '{keyword}'...")
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if result.returncode != 0:
                logging.error(f"Failed to search for installer with keyword '{keyword}': {result.stderr.decode().strip()}")
                return False

            # Get the installer path from the output
            installer_path = result.stdout.decode().strip()
            if not installer_path:
                logging.warning(f"No installer found for keyword '{keyword}'. Skipping...")
                continue

            logging.info(f"Installer found for '{keyword}': {installer_path}")

            # PowerShell command to execute the installer silently
            install_command = f"powershell Start-Process -FilePath '{installer_path}' -ArgumentList '/quiet /norestart' -Wait"

            # Execute the install command using SSH
            command = [
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-i", private_key_file,
                f"{username}@{public_ip}",
                install_command
            ]
            logging.info(f"Installing module '{keyword}'...")
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if result.returncode != 0:
                logging.error(f"Failed to install module '{keyword}': {result.stderr.decode().strip()}")
                return False

            logging.info(f"Module '{keyword}' installed successfully.")

        return True
    except Exception as e:
        logging.error(f"An error occurred during module installation: {str(e)}")
        return False



def transfer_file_with_paramiko(password, local_file, remote_user, remote_ip, remote_path):
    """
    Transfer a file to the remote instance using Paramiko SFTP.
    :param password: Password for the remote user.
    :param local_file: Path to the local file to transfer.
    :param remote_user: Username for the remote instance.
    :param remote_ip: Public IP of the remote instance.
    :param remote_path: Destination path on the remote instance.
    """
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the remote instance
        logging.info(f"Connecting to {remote_ip} as {remote_user}...")
        ssh.connect(hostname=remote_ip, username=remote_user, password=password)

        # Create an SFTP client
        sftp = ssh.open_sftp()
        logging.info(f"Transferring {local_file} to {remote_path} using SFTP...")
        sftp.put(local_file, remote_path)
        logging.info("File transferred successfully using SFTP.")

        # Close the SFTP connection
        sftp.close()
        ssh.close()
        return True

    except Exception as e:
        logging.error(f"An error occurred during file transfer: {str(e)}")
        return False


def setup_ssh_server(public_ip, username, password):
    """
    Set up an SSH server on the Windows EC2 instance using pywinrm.

    Args:
        public_ip (str): The public IP address of the Windows EC2 instance.
        username (str): The username for WinRM authentication.
        password (str): The password for WinRM authentication.

    Returns:
        bool: True if the SSH server is successfully set up, False otherwise.
    """
    session = winrm.Session(f"http://{public_ip}:5985/wsman", auth=(username, password))

    try:
        # Install the OpenSSH server feature
        logging.info("Installing OpenSSH Server on the Windows EC2 instance...")
        install_ssh_command = "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
        result = session.run_ps(install_ssh_command)
        if result.status_code != 0:
            logging.error(f"Failed to install OpenSSH Server: {result.std_err.decode().strip()}")
            return False

        # Start the SSH service
        logging.info("Starting the OpenSSH Server service...")
        start_ssh_command = "Start-Service sshd"
        result = session.run_ps(start_ssh_command)
        if result.status_code != 0:
            logging.error(f"Failed to start OpenSSH Server: {result.std_err.decode().strip()}")
            return False

        # Set the SSH service to start automatically on boot
        logging.info("Configuring SSH service to start automatically...")
        set_ssh_autostart_command = "Set-Service -Name sshd -StartupType Automatic"
        result = session.run_ps(set_ssh_autostart_command)
        if result.status_code != 0:
            logging.error(f"Failed to configure SSH service autostart: {result.std_err.decode().strip()}")
            return False

        # Allow SSH traffic through the Windows Firewall
        logging.info("Allowing SSH traffic through the Windows Firewall...")
        firewall_command = """
        New-NetFirewallRule -Name "SSH" -DisplayName "OpenSSH Server (TCP-In)" -Protocol TCP -LocalPort 22 -Action Allow -Direction Inbound
        """
        result = session.run_ps(firewall_command)
        if result.status_code != 0:
            logging.error(f"Failed to configure the Windows Firewall for SSH: {result.std_err.decode().strip()}")
            return False

        logging.info("OpenSSH Server installed, started, and configured successfully.")
        logging.info("Password-based authentication remains enabled.")
        return True

    except Exception as e:
        logging.error(f"An error occurred while setting up the SSH server: {str(e)}")
        return False
    

def unzip_file_ssh(public_ip, username, private_key_file, remote_zip_path, remote_unzip_dir):
   
    try:
        # PowerShell command to unzip the file
        unzip_command = f"powershell Expand-Archive -Path '{remote_zip_path}' -DestinationPath '{remote_unzip_dir}' -Force"

        # Execute the command using SSH
        command = [
            "ssh",
            "-i", private_key_file,
            f"{username}@{public_ip}",
            unzip_command
        ]
        logging.info(f"Executing unzip command on {public_ip}...")
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode != 0:
            logging.error(f"Failed to unzip file: {result.stderr.decode().strip()}")
            return False

        logging.info("Unzipped successfully.")
        return True
    except Exception as e:
        logging.error(f"An error occurred during unzipping: {str(e)}")
        return False
    
def replace_hosts_file(public_ip, username, password, org_id, local_hosts_file, remote_hosts_path):
   
    try:
        # Step 1: Read and modify the local hosts file
        logging.info("Modifying the local hosts file...")
        with open(local_hosts_file, "r") as file:
            content = file.read()

        # Replace <orgID> with the provided org_id
        modified_content = content.replace("<orgID>", org_id)

        # Escape double quotes and construct the here-string
        escaped_content = modified_content.replace('"', '`"')
        here_string = f'@"\n{escaped_content}\n"@'

        # Step 2: Establish a WinRM session
        logging.info("Establishing WinRM session...")
        session = winrm.Session(f'http://{public_ip}:5985/wsman', auth=(username, password))

        # Step 3: Upload the modified content to the remote hosts file
        logging.info(f"Uploading the modified hosts file to {remote_hosts_path} on {public_ip}...")
        upload_command = f"""
        $content = {here_string}
        Set-Content -Path '{remote_hosts_path}' -Value $content -Force
        """
        result = session.run_ps(upload_command)

        if result.status_code != 0:
            logging.error(f"Failed to upload the hosts file: {result.std_err.decode().strip()}")
            return False

        logging.info("Hosts file modified and uploaded successfully.")
        return True
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return False

import paramiko
import os
import logging

def copy_additional_files_paramiko(public_ip, username, private_key_file, cert_file, enrollment_file, remote_cacerts_dir, remote_enrollment_dir):

    try:
        # Create an SSH client and connect to the instance
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logging.info(f"Connecting to {public_ip} as {username}...")
        ssh.connect(hostname=public_ip, username=username, key_filename=private_key_file, timeout=30)
        logging.info("SSH connection established successfully.")

        # Create an SFTP client
        sftp = ssh.open_sftp()

        # Copy the certificate file
        cert_remote_path = os.path.join(remote_cacerts_dir, "secure_access_signing_nonprod.p7b").replace("\\", "/")
        logging.info(f"Copying certificate file to {cert_remote_path}...")
        sftp.put(cert_file, cert_remote_path)
        logging.info("Certificate file copied successfully.")

        # Copy the enrollment file
        enrollment_remote_path = os.path.join(remote_enrollment_dir, "ztaEnroll_saml_commercial_int_stage.json").replace("\\", "/")
        logging.info(f"Copying enrollment file to {enrollment_remote_path}...")
        sftp.put(enrollment_file, enrollment_remote_path)
        logging.info("Enrollment file copied successfully.")

        # Close the SFTP and SSH connections
        sftp.close()
        ssh.close()
        logging.info("Additional files copied successfully.")
        return True

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return False
    except paramiko.SSHException as e:
        logging.error(f"SSH connection error: {e}")
        return False
    except Exception as e:
        logging.error(f"An error occurred while copying additional files: {e}")
        return False
    
# ----------------------------- Centralized Function -----------------------------

def execute_ztna_clientbased_tasks(public_ip, username, password, key_file, org_id, config):
    """
    Centralized function to execute ZTNA-Clientbased tasks.
    Orchestrates module installation, SSH setup, file transfers, and configuration.
    """
    logging.info(f"Starting ZTNA-Clientbased tasks on instance with Public IP: {public_ip}...")

    # Step 1: Set up SSH server
    logging.info("Setting up SSH server...")
    if not setup_ssh_server(public_ip, username, password):
        logging.error("Failed to set up SSH server. Exiting...")
        return

    # Step 2: Transfer ZIP file
    logging.info("Transferring ZIP file...")
    if not transfer_file_with_paramiko(password, ZIP_FILE, username, public_ip, REMOTE_ZIP_PATH):
        logging.error("Failed to transfer ZIP file. Exiting...")
        return

    # Step 3: Unzip the ZIP file
    logging.info("Unzipping file...")
    if not unzip_file_ssh(public_ip, username, key_file, REMOTE_ZIP_PATH, REMOTE_UNZIP_DIR):
        logging.error("Failed to unzip file. Exiting...")
        return

    # Step 4: Process modules
    session = create_winrm_session(public_ip, username, password)
    modules = [
        {"name": "Core VPN", "keyword": "core-vpn", "log_file": "C:/Users/Administrator/core-install.log"},
        {"name": "DART", "keyword": "dart", "log_file": "C:/Users/Administrator/dart-install.log"},
        {"name": "ZTA", "keyword": "zta", "log_file": "C:/Users/Administrator/zta-install.log"},
    ]

    for module in modules:
        logging.info(f"Processing module: {module['name']}")
        installer_path = find_installer(session, REMOTE_UNZIP_DIR, module["keyword"])
        if not installer_path:
            logging.warning(f"Skipping module '{module['name']}' as no installer was found.")
            continue
        if not install_msi(session, installer_path, module["log_file"]):
            logging.error(f"Failed to install module '{module['name']}'. Exiting...")
            return

    # Step 5: Replace hosts file
    logging.info("Replacing hosts file...")
    if not replace_hosts_file(public_ip, username, password, org_id, HOSTS_FILE, "C:\\Windows\\System32\\drivers\\etc\\hosts"):
        logging.error("Failed to replace hosts file. Exiting...")
        return

    # Step 6: Copy additional files
    logging.info("Copying additional files...")
    if not copy_additional_files_paramiko(public_ip, username, key_file, CERT_FILE, ENROLLMENT_FILE, REMOTE_CACERTS_DIR, REMOTE_ENROLLMENT_DIR):
        logging.error("Failed to copy additional files. Exiting...")
        return

    logging.info("ZTNA-Clientbased tasks completed successfully.")