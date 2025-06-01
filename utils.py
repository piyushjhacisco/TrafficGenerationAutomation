import boto3
import json
import logging
import time
import winrm

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

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

def get_windows_password(ec2, instance_id, key_file, max_retries=10, retry_interval=30):
    """Retrieve and decrypt the Windows Administrator password."""
    try:
        logging.info("Waiting for the instance to boot and generate the password for 180s...")
        time.sleep(240)
        
        
        for attempt in range(max_retries):
            logging.info(f"Attempt {attempt + 1}/{max_retries}: Retrieving Windows password...")
            response = ec2.get_password_data(InstanceId=instance_id)
            encrypted_password = response.get("PasswordData", "")

            if encrypted_password:
                logging.info("Password data is now available. Decrypting...")
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography.hazmat.backends import default_backend
                import base64

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

def ask_user_to_disable_firewall_and_enable_winrm(public_ip):
    """
    Asks the user to manually disable the Windows Firewall and enable WinRM on the Windows instance.
    Waits for the user to confirm that these tasks are completed.
    """
    logging.info("\n--- ACTION REQUIRED ---")
    logging.info(f"Please RDP into the Windows instance with Public IP: {public_ip}")
    logging.info("1. Disable the Windows Firewall:")
    logging.info("   - Open Control Panel > System and Security > Windows Defender Firewall.")
    logging.info("   - Click 'Turn Windows Defender Firewall on or off' and select 'Turn off' for all options.")
    logging.info("2. Enable WinRM:")
    logging.info("   - Open a command prompt on the instance and run:")
    logging.info('     winrm quickconfig')
    logging.info('     winrm set winrm/config/service/auth @{Basic="true"}')
    logging.info('     winrm set winrm/config/service @{AllowUnencrypted="true"}')
    input("\nOnce you have completed the above steps, press Enter to continue...")

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