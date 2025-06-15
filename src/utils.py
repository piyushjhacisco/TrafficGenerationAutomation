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
        # Launch the instance
        instance = ec2.run_instances(
            ImageId=config["ami_id"],
            InstanceType=config["instance_type"],
            KeyName=config["key_name"],
            SecurityGroupIds=[config["security_group_id"]],
            SubnetId=config["subnet_id"],
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": config["instance_name"]}]}
            ]
        )

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