import json
import winrm
import logging
import boto3
import os
from src.utils import check_internet_connectivity

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def load_instance_details(instance_id=None):
    """
    Load instance details from Instance.json. If instance_id is provided, return details of that instance.
    Otherwise, return all instances.
    """
    try:
        with open("Instance.json", "r") as file:
            instances = json.load(file)

            # If instance_id is provided, return the specific instance
            if instance_id:
                for instance in instances:
                    if instance["InstanceId"] == instance_id:
                        return instance
                logging.error(f"Instance ID {instance_id} not found in Instance.json.")
                return None

            # If no instance_id is provided, return all instances
            return instances
    except FileNotFoundError:
        logging.warning("Instance.json file not found. Returning an empty list.")
        return []  # Return an empty list if file is missing
    except json.JSONDecodeError:
        logging.error("Instance.json contains invalid JSON. Returning an empty list.")
        return []  # Return an empty list if JSON is invalid

def configure_dns(host, username, password, primary_dns, alternate_dns):
    """
    Apply the DNS details (Primary and Alternate) to the specified Windows instance.
    """
    try:
        logging.info(f"Changing DNS server to Primary: {primary_dns}, Alternate: {alternate_dns} on Windows instance...")

        # Create a WinRM session
        session = winrm.Session(f'http://{host}:5985/wsman', auth=(username, password), transport='basic', server_cert_validation='ignore')

        # PowerShell command to change both Primary and Alternate DNS servers
        command = f'''
        Get-NetAdapter | Where-Object {{ $_.Status -eq "Up" }} | ForEach-Object {{
            Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses @("{primary_dns}", "{alternate_dns}")
        }}
        '''
        logging.info(f"Running PowerShell command: {command.strip()}")  # Log the command for debugging
        result = session.run_ps(command)
        logging.info(result.std_out.decode())
        if result.std_err:
            logging.warning(f"Error: {result.std_err.decode()}")

        logging.info("DNS server has been updated successfully.")
    except winrm.exceptions.InvalidCredentialsError:
        logging.error("Invalid credentials. Please verify the username and password.")
    except winrm.exceptions.WinRMTransportError:
        logging.error("WinRM transport error. Ensure WinRM is enabled and configured on the instance.")
    except Exception as e:
        logging.error(f"An error occurred while changing the DNS server: {e}")

def execute_dns_tasks(instance_id, public_ip, instances, instance_file):
    """
    Entry point for DNS-specific tasks. This function orchestrates all DNS tasks.
    """
    logging.info(f"Starting DNS tasks for instance {instance_id} with Public IP {public_ip}...")

    # Retrieve the instance details (e.g., password)
    instance_details = load_instance_details(instance_id)
    if not instance_details:
        logging.error(f"Instance {instance_id} not found in Instance.json. Aborting DNS tasks.")
        return

    username = instance_details.get("Username", "Administrator")
    password = instance_details.get("Password")
    if not password:
        logging.error(f"No password found for instance {instance_id}. Aborting DNS tasks.")
        return

    # Step 1: Check internet connectivity
    check_internet_connectivity(public_ip, username, password)
    
    # Step 2: Configure DNS settings
    configure_dns(public_ip, username, password)

    logging.info(f"DNS tasks for instance {instance_id} completed successfully.")