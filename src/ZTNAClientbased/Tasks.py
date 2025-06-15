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
from src.utils import ssh_connect_with_retry, sftp_transfer, retry_command, install_with_retries

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Paths for additional files
ZIP_FILE = "src/ZTNAClientbased/cisco-secure-client.zip"
HOSTS_FILE = "src/ZTNAClientbased/files/zta-staging.txt"
CERT_FILE = "src/ZTNAClientbased/files/secure_access_signing_nonprod.p7b"
ENROLLMENT_FILE = "src/ZTNAClientbased/files/ztaEnroll_saml_commercial_int_stage.json"

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
            installer_path = ssh_connect_with_retry(public_ip, username, private_key_file, search_command)
            if not installer_path:
                logging.warning(f"No installer found for keyword '{keyword}'. Skipping...")
                continue

            logging.info(f"Installer found for '{keyword}': {installer_path}")

            # PowerShell command to execute the installer silently
            install_command = f"powershell Start-Process -FilePath '{installer_path}' -ArgumentList '/quiet /norestart' -Wait"

            # Execute the install command using SSH
            result = ssh_connect_with_retry(public_ip, username, private_key_file, install_command)
            if not result:
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
    

def unzip_file_ssh(public_ip, username, password, remote_zip_path, remote_unzip_dir):
    """
    Unzip a file on the remote Windows instance using Paramiko SSH with password authentication.
    Uses the exact same authentication and connection logic as transfer_file_with_paramiko.
    """
    import time
    max_retries = 5
    for attempt in range(max_retries):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.info(f"Connecting to {public_ip} as {username} for unzip... (attempt {attempt+1})")
            ssh.connect(hostname=public_ip, username=username, password=password, allow_agent=False, look_for_keys=False, timeout=20)
            logging.info("SSH connection established successfully.")
            unzip_command = f"powershell Expand-Archive -Path '{remote_zip_path}' -DestinationPath '{remote_unzip_dir}' -Force"
            logging.info(f"Executing unzip command on {public_ip}...")
            stdin, stdout, stderr = ssh.exec_command(unzip_command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                logging.info("Unzipped successfully.")
                ssh.close()
                return True
            else:
                err = stderr.read().decode().strip()
                logging.error(f"Failed to unzip file: {err}")
                ssh.close()
                return False
        except paramiko.ssh_exception.SSHException as e:
            if "Error reading SSH protocol banner" in str(e) and attempt < max_retries - 1:
                logging.warning(f"SSH banner error, retrying in 5 seconds... ({attempt+1}/{max_retries})")
                time.sleep(5)
                continue
            logging.error(f"SSH connection error: {e}")
            return False
        except Exception as e:
            logging.error(f"An error occurred during unzipping: {e}")
            return False
    logging.error("Failed to connect after multiple retries.")
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

def copy_additional_files_paramiko(public_ip, username, password, cert_file, enrollment_file, remote_cacerts_dir, remote_enrollment_dir):
    """
    Copy additional files to the remote Windows instance using Paramiko SFTP with password authentication.
    Uses the exact same authentication and connection logic as transfer_file_with_paramiko.
    """
    import time
    max_retries = 5
    for attempt in range(max_retries):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.info(f"Connecting to {public_ip} as {username}... (attempt {attempt+1})")
            ssh.connect(hostname=public_ip, username=username, password=password, allow_agent=False, look_for_keys=False, timeout=20)
            logging.info("SSH connection established successfully.")
            sftp = ssh.open_sftp()
            cert_remote_path = os.path.join(remote_cacerts_dir, "secure_access_signing_nonprod.p7b").replace("\\", "/")
            logging.info(f"Copying certificate file to {cert_remote_path}...")
            sftp.put(cert_file, cert_remote_path)
            logging.info("Certificate file copied successfully.")
            enrollment_remote_path = os.path.join(remote_enrollment_dir, "ztaEnroll_saml_commercial_int_stage.json").replace("\\", "/")
            logging.info(f"Copying enrollment file to {enrollment_remote_path}...")
            sftp.put(enrollment_file, enrollment_remote_path)
            logging.info("Enrollment file copied successfully.")
            sftp.close()
            ssh.close()
            logging.info("Additional files copied successfully.")
            return True
        except paramiko.ssh_exception.SSHException as e:
            if "Error reading SSH protocol banner" in str(e) and attempt < max_retries - 1:
                logging.warning(f"SSH banner error, retrying in 5 seconds... ({attempt+1}/{max_retries})")
                time.sleep(5)
                continue
            logging.error(f"SSH connection error: {e}")
            return False
        except FileNotFoundError as e:
            logging.error(f"File not found: {e}")
            return False
        except Exception as e:
            logging.error(f"An error occurred while copying additional files: {e}")
            return False
    logging.error("Failed to connect after multiple retries.")
    return False
