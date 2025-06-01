import json
import winrm
import logging
import boto3
import tkinter as tk
from tkinter import messagebox
import os

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

def check_internet_connectivity(host, username, password):
    """
    Logs in to the Windows instance via WinRM and checks internet connectivity by pinging 8.8.8.8.
    """
    try:
        logging.info(f"Connecting to Windows instance at {host} via WinRM...")

        # Create a WinRM session
        session = winrm.Session(f'http://{host}:5985/wsman', auth=(username, password), transport='basic', server_cert_validation='ignore')

        # Ping 8.8.8.8 to check internet connectivity
        logging.info("Pinging 8.8.8.8 to check internet connectivity...")
        result = session.run_cmd('ping -n 4 8.8.8.8')
        logging.info(result.std_out.decode())
        if result.std_err:
            logging.warning(f"Error: {result.std_err.decode()}")

        logging.info("Internet connectivity check completed successfully.")
    except winrm.exceptions.InvalidCredentialsError:
        logging.error("Invalid credentials. Please verify the username and password.")
    except winrm.exceptions.WinRMTransportError:
        logging.error("WinRM transport error. Ensure WinRM is enabled and configured on the instance.")
    except Exception as e:
        logging.error(f"An error occurred while checking internet connectivity: {e}")

def configure_dns(host, username, password):
    """
    Central function to prompt the user for DNS details, apply them to a Windows instance.
    """
    def prompt_for_dns_details():
        """
        Open a modal dialog to ask the user for Primary and Alternate DNS Server details.
        Returns a dictionary with the DNS details.
        """
        dns_details = {}

        def submit_details():
            """Collect user inputs, validate them, and save the DNS details."""
            primary_dns = primary_dns_entry.get().strip()
            alternate_dns = alternate_dns_entry.get().strip()

            # Validate user inputs
            if not primary_dns or not alternate_dns:
                messagebox.showerror("Input Error", "Both Primary and Alternate DNS fields are required!")
                return

            # Update DNS details
            dns_details["PrimaryDNS"] = primary_dns
            dns_details["AlternateDNS"] = alternate_dns

            # Log the DNS details (for debugging)
            logging.info(f"DNS Details Entered: Primary: {primary_dns}, Alternate: {alternate_dns}")

            # Close the modal and terminate the main loop
            messagebox.showinfo("Success", "DNS details submitted successfully!")
            modal.grab_release()  # Release modal functionality
            modal.destroy()
            root.destroy()  # Explicitly destroy the root window to stop mainloop()

        # Create a modal dialog
        root = tk.Tk()
        root.withdraw()  # Hide the main application window

        modal = tk.Toplevel(root)
        modal.title("Enter DNS Server Details")
        modal.geometry("400x250")
        modal.configure(bg="#f0f4f8")  # Light gray-blue background
        modal.resizable(False, False)
        modal.grab_set()  # Make the modal window modal (disable interaction with other windows)

        # Add form labels and input fields
        tk.Label(modal, text="Enter DNS Server Details", font=("Arial", 14, "bold"), bg="#f0f4f8").pack(pady=10)

        tk.Label(modal, text="Primary DNS Server:", font=("Arial", 12), bg="#f0f4f8").pack(anchor="w", padx=20)
        primary_dns_entry = tk.Entry(modal, width=40, font=("Arial", 12), highlightthickness=1, highlightbackground="#cccccc")
        primary_dns_entry.pack(pady=5, padx=20)

        tk.Label(modal, text="Alternate DNS Server:", font=("Arial", 12), bg="#f0f4f8").pack(anchor="w", padx=20)
        alternate_dns_entry = tk.Entry(modal, width=40, font=("Arial", 12), highlightthickness=1, highlightbackground="#cccccc")
        alternate_dns_entry.pack(pady=5, padx=20)

        # Add a submit button
        submit_button = tk.Button(
            modal,
            text="Submit",
            command=submit_details,
            width=15,
            font=("Arial", 12, "bold"),
            bg="#007BFF",
            fg="white",
            activebackground="#0056b3",
            activeforeground="white"
        )
        submit_button.pack(pady=20)

        # Run the modal dialog
        root.mainloop()

        return dns_details

    def apply_dns_details(primary_dns, alternate_dns):
        """
        Apply the DNS details (Primary and Alternate) to the specified Windows instance.
        """
        try:
            logging.info(f"Changing DNS server to Primary: {primary_dns}, Alternate: {alternate_dns} on Windows instance...")

            # Create a WinRM session
            session = winrm.Session(f'http://{host}:5985/wsman', auth=(username, password), transport='basic', server_cert_validation='ignore')

            # PowerShell command to change both Primary and Alternate DNS servers
            command = f"""
            Get-NetAdapter | Where-Object {{ $_.Status -eq "Up" }} | ForEach-Object {{
                Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses @("{primary_dns}", "{alternate_dns}")
            }}
            """
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

    # Step 1: Prompt the user for DNS details
    dns_details = prompt_for_dns_details()
    primary_dns = dns_details.get("PrimaryDNS")
    alternate_dns = dns_details.get("AlternateDNS")

    # Step 2: Apply the DNS configuration to the Windows instance
    apply_dns_details(primary_dns, alternate_dns)

    # Log success
    logging.info("DNS details updated successfully.")

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