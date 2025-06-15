import paramiko
import json
import os
import logging
import time
import textwrap
import winrm
import subprocess
import tkinter as tk
from tkinter import messagebox

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
        # Custom retry logic to treat expected strongSwan messages as info, not error
        attempt = 0
        while attempt < 3:
            try:
                stdin, stdout, stderr = ssh.exec_command("sudo ipsec restart")
                stdout_output = stdout.read().decode().strip()
                stderr_output = stderr.read().decode().strip()
                expected_msgs = [
                    "Stopping strongSwan IPsec...",
                    "Starting strongSwan"
                ]
                if stderr_output:
                    if all(msg in stderr_output for msg in expected_msgs):
                        logging.info(f"Expected IPsec restart output: {stderr_output}")
                        break
                    elif any(msg in stderr_output for msg in expected_msgs):
                        logging.info(f"Expected IPsec restart output: {stderr_output}")
                        break
                    else:
                        raise Exception(stderr_output)
                logging.info(f"IPsec restart output: {stdout_output}")
                break
            except Exception as e:
                logging.error(f"Attempt {attempt + 1} failed for command: sudo ipsec restart. Error: {e}")
                attempt += 1
                if attempt < 3:
                    logging.info(f"Retrying in 20 seconds...")
                    time.sleep(20)
                else:
                    logging.error(f"All retry attempts failed for command: sudo ipsec restart")
                    raise
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
    Returns a summary log and raises on failure.
    """
    logs = []
    failed_steps = []  # Track failed steps for recovery
    try:
        logs.append(f"Starting IPsec configuration on the instance at {public_ip}...")
        # Step 1: Enable IP forwarding
        try:
            enable_ip_forwarding(public_ip, username, key_file)
            logs.append("IP forwarding enabled successfully.")
        except Exception as e:
            logs.append(f"Step failed: Enable IP forwarding. Error: {e}")
            failed_steps.append("Enable IP forwarding")
        # Step 2: Install StrongSwan
        try:
            install_strongswan(public_ip, username, key_file)
            logs.append("StrongSwan installed successfully.")
        except Exception as e:
            logs.append(f"Step failed: Install StrongSwan. Error: {e}")
            failed_steps.append("Install StrongSwan")
        # Step 3: Update IPsec Configuration
        try:
            update_ipsec_config(public_ip, username, key_file, ipsec_details)
            logs.append("IPsec configuration files updated successfully.")
        except Exception as e:
            logs.append(f"Step failed: Update IPsec Configuration. Error: {e}")
            failed_steps.append("Update IPsec Configuration")
        # Step 4: Restart IPsec and Bring Up the Tunnel
        try:
            restart_ipsec_and_tunnel(public_ip, username, key_file)
            logs.append("IPsec service restarted and tunnel brought up successfully.")
        except Exception as e:
            logs.append(f"Step failed: Restart IPsec and bring up the tunnel. Error: {e}")
            failed_steps.append("Restart IPsec and bring up the tunnel")
        # Handle any failed steps (no Tkinter, just raise for UI to catch)
        if failed_steps:
            logs.append(f"Failed steps: {failed_steps}. Please check logs and retry as needed.")
            raise Exception("; ".join(logs))
        logs.append("IPsec configuration and tunnel setup completed successfully.")
        return "\n".join(logs)
    except Exception as e:
        logs.append(f"An error occurred during IPsec configuration: {e}")
        raise Exception("\n".join(logs))
            


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


# --- WINDOWS TASKS ---
def change_default_gateway_winrm(win_instance, linux_instance):
    """
    Change the default gateway on a Windows instance via WinRM:
    - Detect current default gateway
    - Add two persistent routes with the old gateway
    - Add new default gateway (Linux private IP)
    - Test connectivity
    - Remove old default gateway(s) if ping is successful
    Returns logs (list of strings)
    """
    import socket
    logs = []
    session = winrm.Session(
        f'http://{win_instance["PublicIpAddress"]}:5985/wsman',
        auth=(win_instance["Username"], win_instance["Password"]),
        transport='basic',
        server_cert_validation='ignore',
        read_timeout_sec=20,
        operation_timeout_sec=10
    )
    # Detect current default gateway before change
    detect_gateway_script = '''
    $gw = (Get-NetRoute | Where-Object DestinationPrefix -eq "0.0.0.0/0" | Where-Object NextHop -ne "0.0.0.0" | Select-Object -First 1).NextHop
    Write-Output $gw
    '''
    result_detect = session.run_ps(detect_gateway_script)
    old_gw = result_detect.std_out.decode().strip()
    logs.append(f"Detected old default gateway: {old_gw}")
    print(f"Detected old default gateway: {old_gw}")

    # 1. Add two persistent routes with the old gateway
    add_routes_script = f'''
    $route1Dest = "171.68.244.0"
    $route1Mask = "255.255.255.0"
    $route2Dest = "72.163.220.0"
    $route2Mask = "255.255.255.0"
    $nextHop = "{old_gw}"
    $metric = 1
    Write-Host "Adding persistent route: $route1Dest $route1Mask $nextHop metric $metric"
    route -p add $route1Dest mask $route1Mask $nextHop metric $metric
    Write-Host "Adding persistent route: $route2Dest $route2Mask $nextHop metric $metric"
    route -p add $route2Dest mask $route2Mask $nextHop metric $metric
    Write-Host "Verifying routes..."
    route print | findstr $route1Dest
    route print | findstr $route2Dest
    '''
    result_routes = session.run_ps(add_routes_script)
    routes_out = result_routes.std_out.decode()
    routes_err = result_routes.std_err.decode() if result_routes.std_err else ""
    logs.append(routes_out)
    print(routes_out)
    if routes_err:
        logs.append(f"Error: {routes_err}")
        print(f"Error: {routes_err}")

    # 2. Add new default gateway (Linux private IP)
    powershell_script_gateway = f'''
    $newGateway = "{linux_instance["PrivateIpAddress"]}"
    $adapter = Get-NetAdapter | Where-Object {{ $_.Status -eq "Up" }}
    $interfaceIndex = $adapter.ifIndex
    $currentGateway = "{old_gw}"
    Write-Host "Current Default Gateway: $currentGateway"
    Write-Host "Adding new default gateway: $newGateway..."
    New-NetRoute -InterfaceIndex $interfaceIndex -DestinationPrefix "0.0.0.0/0" -NextHop $newGateway
    Write-Host "Testing connectivity with the new default gateway (before deleting old)..."
    $pingResult = Test-Connection -ComputerName "8.8.8.8" -Count 4 -ErrorAction SilentlyContinue
    if ($pingResult) {{
        Write-Host "Ping successful. Proceeding to remove old default gateway(s)."
        # Remove from both PersistentStore and ActiveStore
        $stores = @("PersistentStore", "ActiveStore")
        foreach ($store in $stores) {{
            $oldRoutes = Get-NetRoute -PolicyStore $store | Where-Object {{ $_.DestinationPrefix -eq "0.0.0.0/0" -and $_.NextHop -eq $currentGateway }}
            foreach ($route in $oldRoutes) {{
                Write-Host "Removing default gateway: $($route.NextHop) on InterfaceIndex: $($route.InterfaceIndex) from $store ..."
                try {{
                    Remove-NetRoute -InterfaceIndex $route.InterfaceIndex -NextHop $route.NextHop -DestinationPrefix "0.0.0.0/0" -PolicyStore $store -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Host "Route removed from $store."
                }} catch {{
                    Write-Host "Failed to remove route from $store. Error: $_"
                }}
            }}
        }}
        # Fallback: try route delete (legacy)
        $legacy = (route print | Select-String $currentGateway)
        if ($legacy) {{
            Write-Host "Attempting legacy route delete for $currentGateway ..."
            route delete 0.0.0.0 $currentGateway
        }}
        # Verify removal
        $remaining = Get-NetRoute | Where-Object {{ $_.DestinationPrefix -eq "0.0.0.0/0" -and $_.NextHop -eq $currentGateway }}
        if ($remaining) {{
            Write-Host "WARNING: Old default gateway(s) still present after attempted removal!"
            $remaining | Format-Table -AutoSize | Out-String | Write-Host
        }} else {{
            Write-Host "Old default gateway(s) fully removed."
        }}
    }} else {{
        Write-Host "Ping failed after adding new default gateway. Old default gateway(s) will NOT be removed."
    }}
    '''
    try:
        result_gateway = session.run_ps(powershell_script_gateway)
        gateway_out = result_gateway.std_out.decode()
        gateway_err = result_gateway.std_err.decode() if result_gateway.std_err else ""
        logs.append(gateway_out)
        print(gateway_out)
        if gateway_err:
            logs.append(f"Error: {gateway_err}")
            print(f"Error: {gateway_err}")
    except (winrm.exceptions.WinRMTransportError, socket.timeout) as e:
        logs.append("WinRM connection lost after gateway change. This is expected if the new gateway breaks public connectivity.")
        print("WinRM connection lost after gateway change. This is expected if the new gateway breaks public connectivity.")
    return logs, old_gw



