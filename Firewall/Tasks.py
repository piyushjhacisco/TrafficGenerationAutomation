import paramiko
import json
import os
import shlex
import logging
import time
import textwrap
import tkinter as tk
from tkinter import messagebox
import winrm
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")



#---------------------------------------------------------UBUNTU TASKS-----------------------------------------------------------------
def execute_with_fallback(ssh, command, retries=3, delay=10, username=None, hostname=None, key_file=None):
    """
    Execute a command with retries using paramiko, and fall back to system's native ssh command if it fails.
    """
    attempt = 0
    while attempt < retries:
        try:
            logging.info(f"Attempt {attempt + 1} of {retries}: Executing command: {command} using paramiko")
            output = execute_command(ssh, command)  # Use the existing paramiko command execution function
            logging.info(f"Command succeeded: {command}")
            return output  # Return the command output
        except Exception as e:
            logging.error(f"Attempt {attempt + 1} failed for command: {command}. Error: {e}")
            attempt += 1
            if attempt < retries:
                logging.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logging.warning("All paramiko retries failed. Falling back to native SSH.")
    
    # Fallback to native SSH
    if username and hostname and key_file:
        try:
            logging.info(f"Executing command: {command} using native SSH")
            ssh_command = f"ssh -i {key_file} {username}@{hostname} '{command}'"
            result = subprocess.run(ssh_command, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                logging.info(f"Command succeeded: {command}")
                return result.stdout.strip()  # Return the command output
            else:
                raise Exception(f"Native SSH command failed: {result.stderr.strip()}")
        except Exception as e:
            raise Exception(f"Both paramiko and native SSH failed for command: {command}. Error: {e}")
    else:
        raise Exception("Fallback to native SSH failed due to missing credentials.")

def enable_ip_forwarding(public_ip, username, key_file):
    """SSH into the instance and enable IP forwarding."""
    ssh = None
    try:
        logging.info(f"Connecting to the instance at {public_ip} to enable IP forwarding...")
        
        # Ensure the key file exists
        if not os.path.exists(key_file):
            logging.error(f"Error: Key file {key_file} not found.")
            return

        # Create an SSH client and connect
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key = paramiko.RSAKey.from_private_key_file(key_file)
        ssh.connect(hostname=public_ip, username=username, pkey=private_key, timeout=80)
        logging.info("SSH connection established successfully.")

        # Execute the command to enable IP forwarding
        execute_with_fallback(
            ssh, 
            "sudo sysctl -w net.ipv4.ip_forward=1", 
            retries=3, 
            delay=10, 
            username=username, 
            hostname=public_ip, 
            key_file=key_file
        )
        logging.info("IP forwarding enabled successfully.")

    except Exception as e:
        logging.error(f"Failed to enable IP forwarding: {e}")
        raise
    finally:
        if ssh:
            ssh.close()
def install_strongswan(public_ip, username, key_file):
    """SSH into the instance and install StrongSwan."""
    ssh = None
    try:
        logging.info(f"Connecting to the instance at {public_ip} to install StrongSwan...")
        
        # Ensure the key file exists
        if not os.path.exists(key_file):
            logging.error(f"Error: Key file {key_file} not found.")
            return

        # Create an SSH client and connect
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key = paramiko.RSAKey.from_private_key_file(key_file)
        ssh.connect(hostname=public_ip, username=username, pkey=private_key, timeout=80)
        logging.info("SSH connection established successfully.")

        # Install StrongSwan
        execute_with_fallback(
            ssh, 
            "sudo apt-get clean && sudo DEBIAN_FRONTEND=noninteractive apt-get update -y && sudo DEBIAN_FRONTEND=noninteractive apt-get install strongswan -y",
            retries=3, 
            delay=10, 
            username=username, 
            hostname=public_ip, 
            key_file=key_file
        )
        logging.info("StrongSwan installation completed successfully.")

        # Validate the installation
        is_installed = execute_with_fallback(
            ssh, 
            "dpkg -l | grep -qw strongswan && echo 'installed' || echo 'not_installed'", 
            retries=3, 
            delay=10, 
            username=username, 
            hostname=public_ip, 
            key_file=key_file
        )
        if "installed" in is_installed:
            logging.info("StrongSwan installation verified successfully.")
        else:
            raise Exception("StrongSwan installation validation failed.")

    except Exception as e:
        logging.error(f"Failed to install StrongSwan: {e}")
        raise
    finally:
        if ssh:
            ssh.close()
def update_ipsec_config(public_ip, username, key_file, ipsec_details):
    """SSH into the instance, back up, and update IPsec configuration files."""
    ssh = None
    try:
        logging.info(f"Connecting to the instance at {public_ip} to update IPsec configuration...")
        
        # Ensure the key file exists
        if not os.path.exists(key_file):
            logging.error(f"Error: Key file {key_file} not found.")
            return

        # Create an SSH client and connect
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key = paramiko.RSAKey.from_private_key_file(key_file)
        ssh.connect(hostname=public_ip, username=username, pkey=private_key, timeout=80)
        logging.info("SSH connection established successfully.")

        # Back up and update /etc/ipsec.conf
        backup_remote_file(ssh, "/etc/ipsec.conf")
        ipsec_conf = textwrap.dedent(f"""
        conn passthrough-ssh
            left = 127.0.0.1,171.68.244.0/24
            leftsubnet = %dynamic[tcp/22]
            rightsubnet = 0.0.0.0/0
            type = passthrough
            auto = route

        conn b2i
            keyingtries=1
            keyexchange=ikev2
            dpdaction=restart
            dpddelay=30s
            dpdtimeout=150s
            reauth=no
            fragmentation=yes
            forceencaps=yes
            mobike=no
            type=tunnel
            left=%any    
            leftid={ipsec_details['leftid']}
            leftauth=psk
            leftsubnet={ipsec_details['leftsubnet']}
            right={ipsec_details['right']}
            rightauth=psk
            rightsubnet=0.0.0.0/0
            closeaction=restart
            auto=add
        """)
        write_remote_file(ssh, "/etc/ipsec.conf", ipsec_conf)
        logging.info("Updated /etc/ipsec.conf successfully.")

        # Back up and update /etc/ipsec.secrets
        backup_remote_file(ssh, "/etc/ipsec.secrets")
        ipsec_secrets = f"{ipsec_details['leftid']} : PSK {ipsec_details['psk']}"
        write_remote_file(ssh, "/etc/ipsec.secrets", ipsec_secrets)
        logging.info("Updated /etc/ipsec.secrets successfully.")

    except Exception as e:
        logging.error(f"Failed to update IPsec configuration: {e}")
        raise
    finally:
        if ssh:
            ssh.close()

def restart_ipsec_and_tunnel(public_ip, username, key_file):
    """SSH into the instance, restart IPsec service, and bring up the tunnel."""
    ssh = None
    try:
        logging.info(f"Connecting to the instance at {public_ip} to restart IPsec and bring up the tunnel...")

        # Ensure the key file exists
        if not os.path.exists(key_file):
            logging.error(f"Error: Key file {key_file} not found.")
            return

        # Create an SSH client and connect
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key = paramiko.RSAKey.from_private_key_file(key_file)
        ssh.connect(hostname=public_ip, username=username, pkey=private_key, timeout=80)
        logging.info("SSH connection established successfully.")

        # Restart IPsec
        logging.info("Restarting IPsec service...")
        retry_command(ssh, "sudo ipsec restart", retries=3, delay=20)
        logging.info("IPsec service restarted successfully.")

        # Bring up the tunnel
        logging.info("Bringing up the IPsec tunnel (b2i)...")
        tunnel_logs = execute_with_fallback(
            ssh,
            "sudo ipsec up b2i",
            retries=3,
            delay=10,
            username=username,
            hostname=public_ip,
            key_file=key_file
        )

        # Check if "successfully" is found in the logs
        if "successfully" in tunnel_logs.lower():
            logging.info("Tunnel brought up successfully: 'successfully' found in logs.")
        else:
            raise Exception("Tunnel setup failed: 'successfully' not found in logs. Please check the IPsec configuration.")

    except Exception as e:
        logging.error(f"Failed to restart IPsec and bring up the tunnel: {e}")
        raise
    finally:
        if ssh:
            ssh.close()

def prompt_user_for_recovery(failed_steps):
    """
    Prompt the user to choose a step to retry from the failed steps.
    If the user selects Exit (0), return None to continue execution.
    :param failed_steps: List of failed steps (commands or descriptions)
    :return: The selected step to retry, or None if the user chooses to exit.
    """
    logging.info("\n--- Recovery Menu ---")
    logging.info("The following steps have failed:")
    for idx, step in enumerate(failed_steps, start=1):
        logging.info(f"{idx}. {step}")
    logging.info("0. Exit (skip retries and continue execution)")

    while True:
        try:
            choice = int(input("\nEnter the number of the step you want to retry (or 0 to skip retries and continue): "))
            if choice == 0:
                logging.info("Skipping retries and continuing with the next tasks.")
                return None  # Exit recovery mode but continue execution
            elif 1 <= choice <= len(failed_steps):
                return failed_steps[choice - 1]
            else:
                logging.error("Invalid choice. Please try again.")
        except ValueError:
            logging.error("Invalid input. Please enter a number.")

import tkinter as tk
from tkinter import messagebox
import json
import logging

def ask_for_ipsec_details():
    """Open a modal dialog to ask the user for IPsec details and return them."""
    # Load the Windows private IP from Instance.json
    try:
        with open("Instance.json", "r") as file:
            instances = json.load(file)
            # Find the Windows instance
            windows_instance = next((i for i in instances if i.get("Username") == "Administrator"), None)
            if not windows_instance:
                print("Error: Windows instance not found in Instance.json.")
                exit(1)
            windows_private_ip = windows_instance.get("PrivateIpAddress")
            if not windows_private_ip:
                print("Error: Windows private IP address is missing in Instance.json.")
                exit(1)
    except FileNotFoundError:
        print("Error: Instance.json file not found.")
        exit(1)
    except json.JSONDecodeError:
        print("Error: Instance.json contains invalid JSON.")
        exit(1)

    # Initialize variables to store user input
    ipsec_details = {}

    def submit_details():
        """Collect user inputs, validate them, and save the details."""
        leftid = leftid_entry.get().strip()
        right = right_entry.get().strip()
        psk = psk_entry.get().strip()

        # Validate user inputs
        if not leftid or not right or not psk:
            messagebox.showerror("Input Error", "All fields are required!")
            return

        # Save IPsec details to a JSON file
        ipsec_details.update({
            "leftid": leftid,
            "leftsubnet": windows_private_ip,  # Automatically set to the Windows private IP
            "right": right,
            "psk": psk
        })
        with open("ipsec_details.json", "w") as file:
            json.dump(ipsec_details, file, indent=4)
        logging.info("IPsec details saved to 'ipsec_details.json'.")

        # Close the modal
        messagebox.showinfo("Success", "IPsec details submitted successfully!")
        modal.grab_release()  # Release modal functionality
        modal.destroy()
        root.quit()  # Stop the tkinter mainloop

    # Create a parent window (main application)
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    # Create a modal dialog (child window)
    modal = tk.Toplevel(root)
    modal.title("Enter IPsec Configuration Details")
    modal.geometry("400x300")
    modal.resizable(False, False)
    modal.grab_set()  # Make the window modal (disable interaction with other windows)

    # Add form labels and input fields
    tk.Label(modal, text="Enter IPsec Configuration", font=("Arial", 14)).pack(pady=10)

    tk.Label(modal, text="Left ID (e.g., TestTraffic@domain.com):").pack(anchor="w", padx=10)
    leftid_entry = tk.Entry(modal, width=50)
    leftid_entry.pack(pady=5, padx=10)

    tk.Label(modal, text="Right Address (e.g., 54.71.129.174):").pack(anchor="w", padx=10)
    right_entry = tk.Entry(modal, width=50)
    right_entry.pack(pady=5, padx=10)

    tk.Label(modal, text="PSK (Pre-Shared Key):").pack(anchor="w", padx=10)
    psk_entry = tk.Entry(modal, width=50, show="*")  # Mask the PSK field for security
    psk_entry.pack(pady=5, padx=10)

    # Add a submit button
    submit_button = tk.Button(modal, text="Submit", command=submit_details, width=15)
    submit_button.pack(pady=20)

    # Run the modal dialog
    root.mainloop()  # Start the tkinter mainloop

    # Return IPsec details after the modal is closed
    return ipsec_details


def ssh_and_configure_ipsec(public_ip, username, key_file, ipsec_details):
    """
    SSH into the instance, enable IP forwarding, install StrongSwan, configure IPsec, 
    and restart the service. Handles retry mechanism and calls task-specific functions.
    """
    failed_steps = []  # Track failed steps for recovery

    try:
        logging.info(f"Starting IPsec configuration on the instance at {public_ip}...")

        # Step 1: Enable IP forwarding
        try:
            enable_ip_forwarding(public_ip, username, key_file)
        except Exception as e:
            logging.error(f"Step failed: Enable IP forwarding. Error: {e}")
            failed_steps.append("Enable IP forwarding")

        # Step 2: Install StrongSwan
        try:
            install_strongswan(public_ip, username, key_file)
        except Exception as e:
            logging.error(f"Step failed: Install StrongSwan. Error: {e}")
            failed_steps.append("Install StrongSwan")

        # Step 3: Update IPsec Configuration
        try:
            update_ipsec_config(public_ip, username, key_file, ipsec_details)
        except Exception as e:
            logging.error(f"Step failed: Update IPsec Configuration. Error: {e}")
            failed_steps.append("Update IPsec Configuration")

        # Step 4: Restart IPsec and Bring Up the Tunnel
        try:
            restart_ipsec_and_tunnel(public_ip, username, key_file)
        except Exception as e:
            logging.error(f"Step failed: Restart IPsec and bring up the tunnel. Error: {e}")
            failed_steps.append("Restart IPsec and bring up the tunnel")

        # Handle any failed steps
        if failed_steps:
            failed_step = prompt_user_for_recovery(failed_steps)
            logging.info(f"Retrying step: {failed_step}")

            # Retry the failed step based on user input
            if failed_step == "Enable IP forwarding":
                enable_ip_forwarding(public_ip, username, key_file)
            elif failed_step == "Install StrongSwan":
                install_strongswan(public_ip, username, key_file)
            elif failed_step == "Update IPsec Configuration":
                update_ipsec_config(public_ip, username, key_file, ipsec_details)
            elif failed_step == "Restart IPsec and bring up the tunnel":
                restart_ipsec_and_tunnel(public_ip, username, key_file)

        logging.info("IPsec configuration and tunnel setup completed successfully.")

    except Exception as e:
        logging.error(f"An error occurred during IPsec configuration: {e}")
        raise
            
def retry_command(ssh, command, retries=3, delay=10):
    """
    Execute a command with retries in case of failure.
    :param ssh: SSH client
    :param command: Command to execute
    :param retries: Number of retry attempts
    :param delay: Delay (in seconds) between retries
    """
    attempt = 0
    while attempt < retries:
        try:
            logging.info(f"Attempt {attempt + 1} of {retries}: Executing command: {command}")
            execute_command(ssh, command)
            logging.info(f"Command succeeded: {command}")
            return  # Exit the function if the command succeeds
        except Exception as e:
            logging.error(f"Attempt {attempt + 1} failed for command: {command}. Error: {e}")
            attempt += 1
            if attempt < retries:
                logging.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logging.error(f"All retry attempts failed for command: {command}")
                raise

def execute_command(ssh, command):
    """Execute a shell command on the remote instance."""
    stdin, stdout, stderr = ssh.exec_command(command)
    stdout_output = stdout.read().decode().strip()
    stderr_output = stderr.read().decode().strip()

    # Log all stdout output
    if stdout_output:
        logging.info(f"STDOUT: {stdout_output}")

    # Handle expected messages in stderr
    if stderr_output:
        # Define expected informational messages
        expected_messages = [
            "Stopping strongSwan IPsec...",
            "Starting strongSwan",
            "Connection established successfully",
        ]

        if any(msg in stderr_output for msg in expected_messages):
            # Log expected stderr as informational
            logging.info(f"Expected STDERR: {stderr_output}")
        else:
            # Raise an exception for unexpected stderr output
            raise Exception(f"Command failed: {command}\nError: {stderr_output}")

    # Return stdout output for further use
    return stdout_output


def write_remote_file(ssh, remote_path, content):
    """Write content to a remote file via SFTP and move it with root privileges."""
    temp_path = f"/tmp/{os.path.basename(remote_path)}"  # Temporary file location
    sftp = ssh.open_sftp()
    try:
        # Write the content to the temporary file
        with sftp.file(temp_path, "w") as remote_file:
            remote_file.write(content)
        logging.info(f"Written temporary file at {temp_path}.")

        # Move the file to the destination with sudo
        execute_command(ssh, f"sudo mv {temp_path} {remote_path}")
        logging.info(f"Updated {remote_path} successfully.")
    except Exception as e:
        logging.error(f"Failed to update {remote_path}: {e}")
        raise
    finally:
        sftp.close()


def backup_remote_file(ssh, remote_path):
    """Backup a remote file by copying it to a .bak file."""
    backup_path = f"{remote_path}.bak"
    try:
        execute_command(ssh, f"sudo cp {remote_path} {backup_path}")
        logging.info(f"Backup created: {backup_path}")
    except Exception as e:
        logging.warning(f"Could not create backup for {remote_path}: {e}")


def install_with_retries(ssh, command, retries=3, delay=10):
    """
    Execute a command with retries in case of failure.
    :param ssh: SSH client
    :param command: Command to execute
    :param retries: Number of retry attempts
    :param delay: Delay (in seconds) between retries
    """
    attempt = 0
    while attempt < retries:
        try:
            logging.info(f"Attempt {attempt + 1} of {retries}: Installing StrongSwan...")
            execute_command(ssh, command)
            logging.info("StrongSwan installed successfully.")
            return  # Exit the function if the command succeeds
        except Exception as e:
            logging.error(f"Attempt {attempt + 1} failed: {e}")
            attempt += 1
            if attempt < retries:
                logging.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logging.error("All retry attempts failed. StrongSwan installation failed.")
                raise


#---------------------------------------------------------WINDOWS TASKS-----------------------------------------------------------------

def delete_specific_default_route(host, username, password, route_to_delete):
    """
    Deletes a specific default route (0.0.0.0/0) with a specific NextHop (e.g., 172.31.16.1).
    """
    if not route_to_delete:
        logging.error("NextHop for route to delete is missing. Cannot proceed.")
        return

    try:
        logging.info(f"Deleting default route with NextHop {route_to_delete} on Windows instance at {host}...")

        # Create a WinRM session
        session = winrm.Session(f'http://{host}:5985/wsman', auth=(username, password), transport='basic', server_cert_validation='ignore')

        # PowerShell script to delete the specific default route
        powershell_script = f"""
        # Define the NextHop of the route to delete
        $routeToDelete = "{route_to_delete}"

        # Get all default routes (0.0.0.0/0)
        $defaultRoutes = Get-NetRoute | Where-Object {{ $_.DestinationPrefix -eq "0.0.0.0/0" }}

        # Log all default routes
        Write-Host "Current Default Routes:"
        $defaultRoutes | ForEach-Object {{ Write-Host "NextHop: $($_.NextHop), InterfaceIndex: $($_.InterfaceIndex)" }}

        # Find the route to delete based on NextHop
        $route = $defaultRoutes | Where-Object {{ $_.NextHop -eq $routeToDelete }}

        if ($route) {{
            Write-Host "Deleting default route with NextHop: $routeToDelete and InterfaceIndex: $($route.InterfaceIndex)..."

            # Delete the route using Remove-NetRoute
            try {{
                Remove-NetRoute -InterfaceIndex $route.InterfaceIndex -NextHop $route.NextHop -DestinationPrefix "0.0.0.0/0" -Confirm:$false
                Write-Host "Route deleted successfully."
            }} catch {{
                Write-Host "Failed to delete route. Error: $_"
            }}
        }} else {{
            Write-Host "No matching default route found for NextHop: $routeToDelete."
        }}

        # Log remaining default routes
        Write-Host "Remaining Default Routes:"
        Get-NetRoute | Where-Object {{ $_.DestinationPrefix -eq "0.0.0.0/0" }} | ForEach-Object {{ Write-Host "NextHop: $($_.NextHop), InterfaceIndex: $($_.InterfaceIndex)" }}
        """

        # Execute the PowerShell script
        result = session.run_ps(powershell_script)

        # Log the output
        logging.info(result.std_out.decode())
        if result.std_err:
            logging.warning(f"Error: {result.std_err.decode()}")

        logging.info(f"Default route with NextHop {route_to_delete} deleted successfully.")
    except winrm.exceptions.InvalidCredentialsError:
        logging.error("Invalid credentials. Please verify the username and password.")
    except winrm.exceptions.WinRMTransportError:
        logging.error("WinRM transport error. Ensure WinRM is enabled and configured on the instance.")
    except Exception as e:
        logging.error(f"An error occurred while deleting the default route: {e}")


def add_routes_and_maybe_change_gateway(host, username, password, new_gateway):
    """
    Adds persistent routes and optionally changes the default gateway on a Windows instance.
    """
    if not new_gateway:
        logging.error("New default gateway is missing. Cannot proceed.")
        return

    try:
        logging.info(f"Adding persistent routes on Windows instance at {host}...")

        # Create a WinRM session
        session = winrm.Session(f'http://{host}:5985/wsman', auth=(username, password), transport='basic', server_cert_validation='ignore')

        # PowerShell script to add persistent routes
        powershell_script_routes = """
        # Define variables
        $route1Dest = "171.68.244.0"
        $route1Mask = "255.255.255.0"
        $route2Dest = "72.163.220.0"
        $route2Mask = "255.255.255.0"
        $nextHop = "172.31.16.1"
        $metric = 1

        # Add the first persistent route
        Write-Host "Adding persistent route: $route1Dest $route1Mask $nextHop metric $metric"
        route -p add $route1Dest mask $route1Mask $nextHop metric $metric

        # Add the second persistent route
        Write-Host "Adding persistent route: $route2Dest $route2Mask $nextHop metric $metric"
        route -p add $route2Dest mask $route2Mask $nextHop metric $metric

        # Verify that the routes were added
        Write-Host "Verifying routes..."
        route print | findstr $route1Dest
        route print | findstr $route2Dest
        """

        # Execute the PowerShell script to add routes
        result_routes = session.run_ps(powershell_script_routes)

        # Log the output for route addition
        logging.info(result_routes.std_out.decode())
        if result_routes.std_err:
            logging.warning(f"Error: {result_routes.std_err.decode()}")

        logging.info("Persistent routes added successfully.")

        # Ask the user if they want to change the default gateway
        change_gateway = input("Do you want to change the default gateway? (yes/no): ").strip().lower()

        if change_gateway == "yes":
            # PowerShell script to delete the old default route and add the new default gateway
            powershell_script_gateway = f"""
            # Define the new default gateway
            $newGateway = "{new_gateway}"

            # Get the current network adapter with an IPv4 address
            $adapter = Get-NetAdapter | Where-Object {{ $_.Status -eq "Up" }}
            $interfaceIndex = $adapter.ifIndex

            # Get the current default gateway
            $currentGateway = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{ $_.DefaultGateway -ne $null }} | Select-Object -ExpandProperty DefaultGateway

            Write-Host "Current Default Gateway: $currentGateway"

            # Delete the old default route if it exists
            if ($currentGateway) {{
                Write-Host "Removing existing default gateway: $currentGateway..."
                Remove-NetRoute -InterfaceIndex $interfaceIndex -NextHop $currentGateway -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
            }}

            # Add the new default gateway
            Write-Host "Adding new default gateway: $newGateway..."
            New-NetRoute -InterfaceIndex $interfaceIndex -DestinationPrefix "0.0.0.0/0" -NextHop $newGateway

            # Test connectivity with the new default gateway
            Write-Host "Testing connectivity with the new default gateway..."
            Test-Connection -ComputerName "8.8.8.8" -Count 4

            # Log the result of the connectivity test
            if ($?) {{
                Write-Host "Connectivity test successful. Default gateway updated to: $newGateway"
            }} else {{
                Write-Host "Connectivity test failed. The new default gateway may not be reachable."
            }}
            """

            # Execute the PowerShell script to change the default gateway
            result_gateway = session.run_ps(powershell_script_gateway)

            # Log the output for gateway change
            logging.info(result_gateway.std_out.decode())
            if result_gateway.std_err:
                logging.warning(f"Error: {result_gateway.std_err.decode()}")

            logging.info("Default gateway change process completed successfully.")
        else:
            logging.info("User chose not to change the default gateway. Exiting.")

    except winrm.exceptions.InvalidCredentialsError:
        logging.error("Invalid credentials. Please verify the username and password.")
    except winrm.exceptions.WinRMTransportError:
        logging.error("WinRM transport error. Ensure WinRM is enabled and configured on the instance.")
    except Exception as e:
        logging.error(f"An error occurred while adding routes or changing the default gateway: {e}")

def load_config(file_path, instance_type):
    """
    Load configuration from Config.json for the specified instance type (e.g., 'windows' or 'linux').
    """
    try:
        with open(file_path, 'r') as file:
            configs = json.load(file)
            # Find the configuration for the specified instance type
            for config in configs:
                if config["type"].lower() == instance_type.lower():
                    return config
            print(f"Error: Configuration for instance type '{instance_type}' not found.")
            return None
    except FileNotFoundError:
        print(f"Error: Configuration file '{file_path}' not found.")
        exit(1)
    except json.JSONDecodeError:
        print(f"Error: Configuration file '{file_path}' contains invalid JSON.")
        exit(1)
# ----------------------------- Centralized Execution -----------------------------

def execute_firewall_tasks(windows_instance_details, ubuntu_instance_details, instance_file):
    """
    Centralized function to execute Firewall tasks.
    :param windows_instance_details: Details of the Windows instance.
    :param ubuntu_instance_details: Details of the Ubuntu instance.
    :param instance_file: Path to the Instance.json file.
    """
    logging.info("Starting Firewall tasks...")

    ubuntu_config = load_config("Config.json", "linux")
    print(ubuntu_config)

    # Ubuntu Tasks
    try:
        logging.info("Starting Ubuntu tasks...")
        
        ipsec_details = ask_for_ipsec_details()
        print("public ip address of linux",ubuntu_instance_details["PublicIpAddress"],ubuntu_instance_details["Username"],ubuntu_config["key_file"])
        ssh_and_configure_ipsec(
            ubuntu_instance_details["PublicIpAddress"],
            ubuntu_instance_details["Username"],
            ubuntu_config["key_file"],
            ipsec_details
        )
        logging.info("Ubuntu tasks completed successfully.")
    except Exception as e:
        logging.error(f"An error occurred during Ubuntu tasks: {e}")
        return

    # Windows Tasks
    try:
        logging.info("Starting Windows tasks...")
        password = windows_instance_details["Password"]
        add_routes_and_maybe_change_gateway(
            windows_instance_details["PublicIpAddress"],
            windows_instance_details["Username"],
            password,
            ubuntu_instance_details["PrivateIpAddress"]
        )
        delete_specific_default_route(
            windows_instance_details["PublicIpAddress"],
            windows_instance_details["Username"],
            password,
            "172.31.16.1"  # Example NextHop
        )
        logging.info("Windows tasks completed successfully.")
    except Exception as e:
        logging.error(f"An error occurred during Windows tasks: {e}")
        return

    logging.info("Firewall tasks completed successfully.")


