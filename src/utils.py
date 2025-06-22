import boto3
import json
import logging
import time
import winrm
import os
import streamlit as st
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64
import paramiko

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

CONFIG_FILE_PATH = "Config.json"
INSTANCE_JSON_FILE = "Instance.json"

def load_config():
    if os.path.exists(CONFIG_FILE_PATH):
        with open(CONFIG_FILE_PATH, "r") as file:
            return json.load(file)
    else:
        return []

def load_instance_file():
    try:
        with open(INSTANCE_JSON_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

def save_instance_file(instances):
    with open(INSTANCE_JSON_FILE, "w") as file:
        json.dump(instances, file, indent=4)

def handle_instance_reuse_or_creation(config, task_name, instance_file):
    instances = load_instance_file()
    reuse_choice = st.radio(f"Do you want to reuse an existing instance for {task_name}?", ["Yes", "No"])
    if reuse_choice == "Yes":
        if not instances:
            st.warning("No existing instances found. A new instance will be created.")
        else:
            instance_id = st.text_input("Enter the Instance ID to reuse:")
            if instance_id:
                instance = next((i for i in instances if i["InstanceId"] == instance_id), None)
                if instance:
                    st.json(instance)
                    return instance
                else:
                    st.warning("Instance ID not found in Instance.json. Please check and try again.")
    else:
        st.write("Creating a new instance...")
        new_instance = {
            "InstanceId": "i-1234567890abcdef0",
            "PublicIpAddress": "54.123.45.67",
            "PrivateIpAddress": "192.168.1.1",
            "InstanceType": "t3.medium",
        }
        instances.append(new_instance)
        save_instance_file(instances)
        st.success("New instance created successfully!")
        st.json(new_instance)
        return new_instance

def load_config(file_path):
    """Load configuration from JSON file."""
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Error loading configuration: {e}")
        return []

def save_instance_details(file_path, instances):
    """Save instance details to JSON."""
    try:
        with open(file_path, "w") as file:
            json.dump(instances, file, indent=4)
        logging.info("Instance details saved successfully.")
    except Exception as e:
        logging.error(f"Failed to save instance details: {e}")

def load_instance_details(file_path):
    """Load instance details from JSON."""
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        logging.warning(f"Instance details file '{file_path}' is missing or invalid.")
        return []

def create_instance(config):
    """Create an EC2 instance and return its ID, public IP, and private IP."""
    ec2 = boto3.client("ec2", region_name=config["aws_region"])
    try:
        # Prepare user_data for Windows instances to configure WinRM
        user_data = ""
        if "windows" in config.get("type", "").lower():
            user_data = get_winrm_bootstrap_script()
        
        # Launch the instance
        launch_params = {
            "ImageId": config["ami_id"],
            "InstanceType": config["instance_type"],
            "KeyName": config["key_name"],
            "SecurityGroupIds": [config["security_group_id"]],
            "SubnetId": config["subnet_id"],
            "MinCount": 1,
            "MaxCount": 1,
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": config["instance_name"]}]}
            ]
        }
        
        # Add user_data for Windows instances
        # Add user_data for Windows instances (as plain string, NOT base64-encoded)
        if user_data:
            launch_params["UserData"] = user_data
        
        instance = ec2.run_instances(**launch_params)

        # Extract the instance ID
        instance_id = instance["Instances"][0]["InstanceId"]
        logging.info(f"Instance created: {instance_id}. Waiting for it to enter the 'running' state...")

        # Wait for the instance to be in 'running' state
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])

        # Refresh the instance details to fetch the public and private IPs
        logging.info(f"Fetching public and private IPs for instance {instance_id}...")
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance_details = response["Reservations"][0]["Instances"][0]

        public_ip = instance_details.get("PublicIpAddress", "N/A")
        private_ip = instance_details.get("PrivateIpAddress", "N/A")

        logging.info(f"Instance is now running: {instance_id} with Public IP: {public_ip} and Private IP: {private_ip}")
        
        # For Windows instances, log that WinRM configuration is in progress
        if user_data:
            logging.info("Windows instance created with WinRM bootstrap script. WinRM will be configured automatically during instance initialization.")
        
        return instance_id, public_ip, private_ip
    except Exception as e:
        logging.error(f"Failed to create instance: {e}")
        return None, None, None

def get_windows_password(ec2, instance_id, key_file, max_retries=10, retry_interval=30, initial_wait=None):
    """Retrieve and decrypt the Windows Administrator password. If initial_wait is set, sleep before polling."""
    try:
        if initial_wait:
            logging.info(f"Waiting for the instance to boot and generate the password for {initial_wait}s...")
            time.sleep(initial_wait)
        for attempt in range(max_retries):
            logging.info(f"Attempt {attempt + 1}/{max_retries}: Retrieving Windows password...")
            response = ec2.get_password_data(InstanceId=instance_id)
            encrypted_password = response.get("PasswordData", "")

            if encrypted_password:
                logging.info("Password data is now available. Decrypting...")
                with open(key_file, "rb") as key_file_data:
                    private_key = serialization.load_pem_private_key(
                        key_file_data.read(),
                        password=None,
                        backend=default_backend()
                    )
                decrypted_password = private_key.decrypt(
                    base64.b64decode(encrypted_password),
                    padding.PKCS1v15()
                )
                return decrypted_password.decode("utf-8")
            logging.info(f"Password not yet available. Retrying in {retry_interval} seconds...")
            time.sleep(retry_interval)

        logging.error("Failed to retrieve Windows password after multiple attempts.")
        return None

    except Exception as e:
        logging.error(f"An error occurred while decrypting the Windows password: {e}")
        return None

def disable_source_destination_check(instance_id):
    """Disable Source/Destination Check for an EC2 instance."""
    ec2 = boto3.client("ec2")
    try:
        logging.info(f"Disabling Source/Destination Check for instance {instance_id}...")
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            SourceDestCheck={"Value": False}
        )
        logging.info("Source/Destination Check disabled successfully.")
    except Exception as e:
        logging.error(f"Failed to disable Source/Destination Check: {e}")

def terminate_instances(instance_file):
    """Terminate all instances listed in Instance.json."""
    ec2 = boto3.client("ec2")
    instances = load_instance_details(instance_file)

    if not instances:
        logging.info("No instances found to terminate.")
        return

    for instance in instances:
        instance_id = instance["InstanceId"]
        logging.info(f"Terminating instance: {instance_id}...")

        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
            waiter = ec2.get_waiter("instance_terminated")
            waiter.wait(InstanceIds=[instance_id])
            logging.info(f"Instance {instance_id} terminated successfully.")
        except Exception as e:
            logging.error(f"An error occurred while terminating instance {instance_id}: {e}")

    # Clear the instance details from Instance.json after termination
    save_instance_details(instance_file, [])
    logging.info("All instances have been terminated and Instance.json has been cleared.")

def check_internet_connectivity(host, username, password):
    """
    Logs in to the Windows instance via WinRM and checks internet connectivity by pinging 8.8.8.8.
    Returns (success, output):
        success (bool): True if connectivity is confirmed, False otherwise.
        output (str): The combined stdout and stderr from the ping command.
    """
    try:
        logging.info(f"Connecting to Windows instance at {host} via WinRM...")
        session = winrm.Session(f'http://{host}:5985/wsman', auth=(username, password), transport='basic', server_cert_validation='ignore')
        logging.info("Pinging 8.8.8.8 to check internet connectivity...")
        result = session.run_cmd('ping -n 4 8.8.8.8')
        std_out = result.std_out.decode() if result.std_out else ''
        std_err = result.std_err.decode() if result.std_err else ''
        output = std_out + ("\n" + std_err if std_err else "")
        logging.info(std_out)
        if std_err:
            logging.warning(f"Error: {std_err}")
        # Check for success patterns in the output
        success_patterns = [
            "Reply from", "bytes from", "Received = 4", "0% packet loss", "Minimum ="
        ]
        success = any(pattern in output for pattern in success_patterns)
        logging.info(f"Internet connectivity check completed. Success: {success}")
        return success, output
    except winrm.exceptions.InvalidCredentialsError:
        logging.error("Invalid credentials. Please verify the username and password.")
        return False, "Invalid credentials. Please verify the username and password."
    except winrm.exceptions.WinRMTransportError:
        logging.error("WinRM transport error. Ensure WinRM is enabled and configured on the instance.")
        return False, "WinRM transport error. Ensure WinRM is enabled and configured on the instance."
    except Exception as e:
        logging.error(f"An error occurred while checking internet connectivity: {e}")
        return False, f"An error occurred: {e}"

def get_instance_details_from_aws(instance_id, aws_region, key_file=None):
    """
    Fetch instance details from AWS based on the instance ID provided by the user.
    If key_file is provided, attempts to retrieve the Windows password as well.
    """
    ec2 = boto3.client("ec2", region_name=aws_region)
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        public_ip = instance.get('PublicIpAddress', 'N/A')
        private_ip = instance.get('PrivateIpAddress', 'N/A')
        instance_type = instance['InstanceType']
        instance_details = {
            "InstanceId": instance_id,
            "PublicIpAddress": public_ip,
            "PrivateIpAddress": private_ip,
            "InstanceType": instance_type
        }
        if key_file:
            password = get_windows_password(ec2, instance_id, key_file)
            if password:
                instance_details["Password"] = password
                instance_details["Username"] = "Administrator"
        return instance_details
    except Exception as e:
        logging.error(f"Failed to fetch details for instance {instance_id}: {e}")
        return None

def ssh_connect_with_retry(hostname, username, key_file=None, password=None, retries=3, delay=10):
    """
    Connect to a host using paramiko with retries. Supports key or password auth.
    Returns an SSHClient or None.
    """
    for attempt in range(retries):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if password:
                ssh.connect(hostname=hostname, username=username, password=password, timeout=20)
            else:
                pkey = paramiko.RSAKey.from_private_key_file(key_file)
                ssh.connect(hostname=hostname, username=username, pkey=pkey, timeout=20)
            return ssh
        except Exception as e:
            logging.warning(f"SSH connection failed (attempt {attempt+1}/{retries}): {e}")
            time.sleep(delay)
    logging.error(f"Failed to connect to {hostname} after {retries} attempts.")
    return None

def sftp_transfer(ssh, local_file, remote_path):
    """Transfer a file using SFTP via an existing SSHClient."""
    try:
        sftp = ssh.open_sftp()
        sftp.put(local_file, remote_path)
        sftp.close()
        return True
    except Exception as e:
        logging.error(f"SFTP transfer failed: {e}")
        return False

def retry_command(ssh, command, retries=3, delay=10):
    """
    Execute a command with retries in case of failure.
    """
    attempt = 0
    while attempt < retries:
        try:
            logging.info(f"Attempt {attempt + 1} of {retries}: Executing command: {command}")
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout_output = stdout.read().decode().strip()
            stderr_output = stderr.read().decode().strip()
            if stderr_output:
                raise Exception(stderr_output)
            return stdout_output
        except Exception as e:
            logging.error(f"Attempt {attempt + 1} failed for command: {command}. Error: {e}")
            attempt += 1
            if attempt < retries:
                logging.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logging.error(f"All retry attempts failed for command: {command}")
                raise

def install_with_retries(ssh, command, retries=3, delay=10):
    """
    Execute a command with retries in case of failure (for installs).
    """
    return retry_command(ssh, command, retries, delay)

def show_disable_firewall_and_enable_winrm(public_ip):
    action_logs = f"""
--- ACTION REQUIRED ---
Please RDP into the Windows instance with Public IP: {public_ip}
1. Disable the Windows Firewall:
   - Open Control Panel > System and Security > Windows Defender Firewall.
   - Click 'Turn Windows Defender Firewall on or off' and select 'Turn off' for all options.
2. Enable WinRM:
   - Open a command prompt on the instance and run:
     winrm quickconfig
     winrm set winrm/config/service/auth @{{Basic="true"}}
     winrm set winrm/config/service @{{AllowUnencrypted="true"}}
"""
    st.code(action_logs, language="text")
    st.info("After completing the above steps, click below.")

def get_winrm_bootstrap_script():
    """
    Returns a PowerShell script for EC2 user_data that uses the official Ansible ConfigureRemotingForAnsible.ps1 script
    to enable WinRM, set up basic auth, and allow unencrypted connections (best practice for Ansible/pywinrm automation).
    """
    return '''<powershell>
# Download and run Microsoft's ConfigureRemotingForAnsible.ps1 script
$url = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
$file = "$env:temp\\ConfigureRemotingForAnsible.ps1"

# Download the script
(New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file)

# Run the script to configure WinRM
powershell.exe -ExecutionPolicy ByPass -File $file

# Additional configuration for pywinrm (basic auth, allow unencrypted)
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/client/auth '@{Basic="true"}'
winrm set winrm/config/client '@{AllowUnencrypted="true"}'

# Create HTTP listener (if not present)
winrm create winrm/config/listener?Address=*+Transport=HTTP

# Open WinRM ports in Windows Firewall
New-NetFirewallRule -DisplayName "WinRM HTTP" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow

# Restart WinRM service
Restart-Service WinRM

Write-Output "WinRM fully configured for Ansible/pywinrm automation."
</powershell>'''

def test_winrm_connection(public_ip, username, password, max_retries=3, retry_delay=10):
    """
    Test WinRM connection to a properly configured Windows instance.
    Only checks HTTP (port 5985). If successful, disables the Windows firewall.
    """
    port = 5985
    protocol = "http"
    for attempt in range(max_retries):
        try:
            logging.info(f"Attempt {attempt + 1}/{max_retries}: Testing WinRM connection to {public_ip}:{port} ({protocol})")
            endpoint = f'{protocol}://{public_ip}:{port}/wsman'
            session = winrm.Session(endpoint, 
                                    auth=(username, password), 
                                    transport='basic',
                                    server_cert_validation='ignore')
            result = session.run_cmd('echo "WinRM connection successful"')
            if result.status_code == 0:
                output = result.std_out.decode('utf-8').strip()
                logging.info(f"WinRM connection successful on {protocol.upper()} port {port}")
                # Disable firewall if connection is successful
                try:
                    session.run_cmd('netsh advfirewall set allprofiles state off')
                    logging.info("Windows firewall disabled via WinRM after successful connectivity test.")
                except Exception as e:
                    logging.warning(f"Failed to disable firewall: {e}")
                return True, f"Connected successfully via {protocol.upper()} on port {port}: {output}"
            else:
                error_msg = result.std_err.decode('utf-8') if result.std_err else "Unknown error"
                logging.warning(f"Command failed on {protocol}:{port}: {error_msg}")
        except Exception as e:
            logging.warning(f"Connection attempt {attempt + 1} failed on {protocol}:{port}: {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
    return False, "Failed to establish WinRM connection on HTTP port 5985"

def diagnose_winrm_issues(public_ip, username, password, instance_id=None, aws_region=None):
    """
    Comprehensive diagnostic function to help troubleshoot WinRM connection issues.
    """
    diagnosis = []
    
    # Test 1: Basic network connectivity
    diagnosis.append("=== WinRM Connection Diagnosis ===")
    
    try:
        import socket
        # Test if port 5985 is reachable
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((public_ip, 5985))
        if result == 0:
            diagnosis.append("✅ Port 5985 (WinRM HTTP) is reachable")
        else:
            diagnosis.append("❌ Port 5985 (WinRM HTTP) is NOT reachable")
        sock.close()
        
        # Test if port 5986 is reachable
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((public_ip, 5986))
        if result == 0:
            diagnosis.append("✅ Port 5986 (WinRM HTTPS) is reachable")
        else:
            diagnosis.append("❌ Port 5986 (WinRM HTTPS) is NOT reachable")
        sock.close()
        
    except Exception as e:
        diagnosis.append(f"❌ Network connectivity test failed: {e}")
    
    # Test 2: Try WinRM connection with detailed error reporting
    try:
        session = winrm.Session(f'http://{public_ip}:5985/wsman', 
                              auth=(username, password), 
                              transport='basic',
                              server_cert_validation='ignore')
        result = session.run_cmd('echo "test"')
        
        if result.status_code == 0:
            diagnosis.append("✅ WinRM HTTP connection successful")
        else:
            diagnosis.append(f"❌ WinRM HTTP connection failed with status: {result.status_code}")
            if result.std_err:
                diagnosis.append(f"   Error: {result.std_err.decode('utf-8')}")
                
    except winrm.exceptions.InvalidCredentialsError:
        diagnosis.append("❌ WinRM authentication failed - invalid credentials")
    except winrm.exceptions.WinRMTransportError as e:
        diagnosis.append(f"❌ WinRM transport error: {e}")
    except Exception as e:
        diagnosis.append(f"❌ WinRM connection failed: {e}")
    
    return "\n".join(diagnosis)

def wait_for_winrm_ready(public_ip, username, password, max_wait_minutes=10):
    """
    Intelligently wait for WinRM to become ready after Windows instance creation.
    This combines password availability check with WinRM readiness check.
    """
    import time
    
    max_attempts = max_wait_minutes * 2  # Check every 30 seconds
    
    for attempt in range(max_attempts):
        try:
            # Test basic WinRM connection
            success, message = test_winrm_connection(public_ip, username, password, max_retries=1, retry_delay=5)
            
            if success:
                return True, f"WinRM ready after {attempt * 30} seconds: {message}"
            
            logging.info(f"WinRM not ready yet (attempt {attempt + 1}/{max_attempts}). Waiting 30 seconds...")
            time.sleep(30)
            
        except Exception as e:
            logging.warning(f"WinRM readiness check failed: {e}")
            time.sleep(30)
    
    return False, f"WinRM not ready after {max_wait_minutes} minutes of waiting"
