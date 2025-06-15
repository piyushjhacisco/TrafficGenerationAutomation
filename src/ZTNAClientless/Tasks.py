import boto3
import json
import os
import time
import paramiko
import logging
from src.utils import ssh_connect_with_retry

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Constants
INSTANCE_INIT_WAIT = 180  # Wait time for instance initialization (in seconds)
INSTANCE_JSON_FILE = "Instance.json"  # File to store instance details

# Variables for SSL and Nginx configuration
html_directory = "/var/www/html"
ssl_cert_directory = "/etc/ssl/certs"
ssl_cert_key_directory = "/etc/ssl/private"
self_signed_cert_name = "self-signed.crt"
self_signed_key_name = "self-signed.key"

def connect_to_instance(public_ip, username, key_file):
    """Connect to the instance using Paramiko (with retry)."""
    return ssh_connect_with_retry(public_ip, username, key_file=key_file)

def install_nginx(public_ip, username, key_file):
    """Install Nginx on the instance."""
    logging.info("Installing Nginx...")
    ssh = connect_to_instance(public_ip, username, key_file)
    if ssh:
        try:
            commands = [
                "sudo apt-get update -y",
                "sudo apt-get install nginx -y"
            ]
            for command in commands:
                stdin, stdout, stderr = ssh.exec_command(command)
                stdout_output = stdout.read().decode().strip()
                stderr_output = stderr.read().decode().strip()
                if stderr_output:
                    logging.warning(f"Error executing: {command}. Error: {stderr_output}")
                else:
                    logging.info(f"Command succeeded: {command}")
        finally:
            ssh.close()
            logging.info("Disconnected from the instance after installing Nginx.")


def configure_ssl(public_ip, username, key_file):
    """Configure a self-signed SSL certificate on the instance."""
    logging.info("Configuring self-signed SSL certificate...")
    ssh = connect_to_instance(public_ip, username, key_file)
    if ssh:
        try:
            commands = [
                f"sudo openssl genrsa -out {ssl_cert_key_directory}/{self_signed_key_name} 4096",
                f"sudo openssl req -new -key {ssl_cert_key_directory}/{self_signed_key_name} "
                f"-out /tmp/self_signed.csr -subj '/CN=example.com/O=MyOrg'",
                f"sudo openssl x509 -req -days 365 -in /tmp/self_signed.csr "
                f"-signkey {ssl_cert_key_directory}/{self_signed_key_name} "
                f"-out {ssl_cert_directory}/{self_signed_cert_name}"
            ]
            for command in commands:
                stdin, stdout, stderr = ssh.exec_command(command)
                stderr_output = stderr.read().decode().strip()
                if stderr_output:
                    logging.warning(f"Error executing: {command}. Error: {stderr_output}")
                else:
                    logging.info(f"Command succeeded: {command}")
        finally:
            ssh.close()
            logging.info("Disconnected from the instance after configuring SSL.")


def restart_nginx(public_ip, username, key_file):
    """Restart the Nginx service."""
    logging.info("Restarting Nginx service...")
    ssh = connect_to_instance(public_ip, username, key_file)
    if ssh:
        try:
            command = "sudo systemctl restart nginx"
            stdin, stdout, stderr = ssh.exec_command(command)
            stderr_output = stderr.read().decode().strip()
            if stderr_output:
                logging.warning(f"Error restarting Nginx: {stderr_output}")
            else:
                logging.info("Nginx service restarted successfully.")
        finally:
            ssh.close()
            logging.info("Disconnected from the instance after restarting Nginx.")

def configure_nginx_https(public_ip, username, key_file):
    """Configure Nginx for HTTPS."""
    logging.info("Configuring Nginx for HTTPS...")
    ssh = connect_to_instance(public_ip, username, key_file)
    if ssh:
        try:
            # Update Nginx configuration
            commands = [
                f"sudo bash -c 'cat > /etc/nginx/sites-enabled/default' <<EOF\n"
                f"server {{\n"
                f"    listen 80 default_server;\n"
                f"    listen [::]:80 default_server;\n"
                f"    root /var/www/html;\n"
                f"    index index.html index.htm index.nginx-debian.html;\n"
                f"    server_name _;\n"
                f"    location / {{\n"
                f"        try_files \\$uri \\$uri/ =404;\n"
                f"    }}\n"
                f"}}\n\n"
                f"server {{\n"
                f"    listen 443 ssl default_server;\n"
                f"    listen [::]:443 ssl default_server;\n"
                f"    server_name _;\n"
                f"    ssl_certificate /etc/ssl/certs/{self_signed_cert_name};\n"
                f"    ssl_certificate_key /etc/ssl/private/{self_signed_key_name};\n"
                f"    root /var/www/html;\n"
                f"    index index.html index.htm index.nginx-debian.html;\n"
                f"    location / {{\n"
                f"        try_files \\$uri \\$uri/ =404;\n"
                f"    }}\n"
                f"}}\nEOF"
            ]

            for command in commands:
                stdin, stdout, stderr = ssh.exec_command(command)
                stderr_output = stderr.read().decode().strip()
                if stderr_output:
                    logging.warning(f"Error updating Nginx configuration: {stderr_output}")
                else:
                    logging.info("Nginx configuration updated successfully.")
        finally:
            ssh.close()
            logging.info("Disconnected from the instance after configuring Nginx.")

def execute_ztna_clientless_tasks(public_ip, username, key_file):
    """
    Centralized function to execute ZTNA-Clientless tasks.
    Orchestrates the installation and configuration of Nginx and HTTPS.
    """
    logging.info(f"Starting ZTNA-Clientless tasks on instance with Public IP: {public_ip}...")

    try:
        #time.sleep(180)  # Wait for the instance to be fully initialized
        # Step 1: Install Nginx
        install_nginx(public_ip, username, key_file)

        # Step 2: Configure SSL
        configure_ssl(public_ip, username, key_file)

        # Step 3: Configure Nginx for HTTPS
        configure_nginx_https(public_ip, username, key_file)

        # Step 4: Restart Nginx
        restart_nginx(public_ip, username, key_file)

        logging.info("ZTNA-Clientless tasks completed successfully.")
    except Exception as e:
        logging.error(f"An error occurred during ZTNA-Clientless tasks: {e}")

def fetch_cert_and_key(public_ip, username, key_file, crt_path, key_path):
    """
    Fetch the certificate and key files from the remote instance using SSH/SFTP.
    If permission is denied, attempt to chmod the files and retry once.
    Returns (crt_data, key_data, error_message)
    """
    import paramiko
    def try_fetch(ssh):
        sftp = ssh.open_sftp()
        try:
            with sftp.open(crt_path, 'rb') as f:
                crt_data = f.read()
            with sftp.open(key_path, 'rb') as f:
                key_data = f.read()
            return crt_data, key_data, None
        finally:
            sftp.close()
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key = paramiko.RSAKey.from_private_key_file(key_file)
        ssh.connect(hostname=public_ip, username=username, pkey=private_key, timeout=10)
        try:
            # First try
            try:
                return try_fetch(ssh)
            except Exception as e:
                if "Permission denied" in str(e):
                    # Try to chmod and retry
                    try:
                        ssh.exec_command(f"sudo chmod 644 {crt_path}")
                        ssh.exec_command(f"sudo chmod 644 {key_path}")
                        return try_fetch(ssh)
                    except Exception as e2:
                        return None, None, f"Permission denied and chmod failed: {e2}"
                else:
                    return None, None, str(e)
        finally:
            ssh.close()
    except Exception as e:
        return None, None, str(e)