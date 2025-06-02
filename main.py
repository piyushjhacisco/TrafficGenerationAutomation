import logging
import time
from utils import (
    load_config,
    save_instance_details,
    load_instance_details,
    create_instance,
    get_windows_password,
    disable_source_destination_check,
    terminate_instances,
    ask_user_to_disable_firewall_and_enable_winrm,
    check_internet_connectivity
)
from DNS.Tasks import execute_dns_tasks
from Firewall.Tasks import execute_firewall_tasks
from Web.Tasks import execute_web_tasks
from ZTNAClientless.Tasks import execute_ztna_clientless_tasks
from ZTNAClientbased.Tasks import execute_ztna_clientbased_tasks
import boto3

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def get_instance_details_from_aws(instance_id, aws_region, key_file=None):
    """
    Fetch instance details from AWS based on the instance ID provided by the user.
    """
    ec2 = boto3.client("ec2", region_name=aws_region)
    try:
        logging.info(f"Fetching details for instance {instance_id} from AWS...")
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        public_ip = instance.get('PublicIpAddress', 'N/A')
        private_ip = instance.get('PrivateIpAddress', 'N/A')
        instance_type = instance['InstanceType']

        logging.info(f"Fetched details for instance {instance_id}: Public IP: {public_ip}, Private IP: {private_ip}")

        # Prepare instance details
        instance_details = {
            "InstanceId": instance_id,
            "PublicIpAddress": public_ip,
            "PrivateIpAddress": private_ip,
            "InstanceType": instance_type
        }
        print("instance type",instance_type.lower())
        # If it's a Windows instance, retrieve the password
        if key_file:
            logging.info("Retrieving Windows password for the instance...")
            password = get_windows_password(ec2, instance_id, key_file)
            if password:
                logging.info("Windows password retrieved successfully.")
                instance_details["Password"] = password
                ask_user_to_disable_firewall_and_enable_winrm(public_ip)
            else:
                logging.error("Failed to retrieve Windows password.")
                return None

        return instance_details
    except Exception as e:
        logging.error(f"Failed to fetch details for instance {instance_id}: {e}")
        return None


def update_instance_in_json(instance_id, updated_details, instance_file):
    """
    Update the details of an instance in Instance.json.
    If the instance doesn't exist, append it as a new entry.
    """
    instances = load_instance_details(instance_file)

    # Check if the instance already exists in the list
    for instance in instances:
        if instance["InstanceId"] == instance_id:
            logging.info(f"Updating details for instance {instance_id} in Instance.json.")
            instance.update(updated_details)  # Update the existing instance details
            break
    else:
        # If the instance doesn't exist, append it
        logging.info(f"Adding new instance {instance_id} to Instance.json.")
        instances.append(updated_details)

    # Save the updated instances list
    save_instance_details(instance_file, instances)


def handle_instance_reuse_or_creation(config, task_name, instance_file):
    """
    Handles the workflow of reusing or creating an instance for a specific task.
    :param config: The configuration for the instance (from Config.json).
    :param task_name: The name of the task (e.g., "DNS", "Firewall").
    :param instance_file: The path to the Instance.json file.
    :return: The instance details (dictionary).
    """
    reuse_choice = input(f"Do you want to reuse an existing instance for {task_name}? (yes/no): ").strip().lower()
    if reuse_choice == "yes":
        instance_id = input(f"Enter the Instance ID for {task_name}: ").strip()
        instances = load_instance_details(instance_file)
        existing_instance = next((inst for inst in instances if inst["InstanceId"] == instance_id), None)

        if existing_instance:
            logging.info(f"Using existing instance {instance_id} for {task_name} from Instance.json.")
            ask_user_to_disable_firewall_and_enable_winrm(existing_instance["PublicIpAddress"])
            return existing_instance
        else:
            logging.info(f"Instance {instance_id} not found in Instance.json. Fetching details from AWS...")
            instance_details = get_instance_details_from_aws(instance_id, config["aws_region"], config.get("key_file"))
            if instance_details:
                update_instance_in_json(instance_id, instance_details, instance_file)
                ask_user_to_disable_firewall_and_enable_winrm(instance_details["PublicIpAddress"])
                return instance_details
            else:
                logging.error(f"Failed to fetch details for instance {instance_id}. Exiting.")
                return None
    else:
        logging.info(f"Creating a new instance for {task_name}...")
        instance_id, public_ip, private_ip = create_instance(config)
        if instance_id:
            disable_source_destination_check(instance_id)
            instance_details = {
                "InstanceId": instance_id,
                "PublicIpAddress": public_ip,
                "PrivateIpAddress": private_ip,
                "type": config["type"],
            }
            if "windows" in config["type"]:
                ec2 = boto3.client("ec2", region_name=config["aws_region"])
                password = get_windows_password(ec2, instance_id, config["key_file"])
                instance_details["Password"] = password
                instance_details["Username"] = "Administrator"
                # Update the instance.json file
                update_instance_in_json(instance_id, instance_details, instance_file)
                ask_user_to_disable_firewall_and_enable_winrm(public_ip)
            else:
                instance_details["Username"] = config.get("username", "ubuntu")
                update_instance_in_json(instance_id, instance_details, instance_file)
                print("waiting for 4 mins for initialization")
                time.sleep(240)  # Wait for 4 minutes for initialization

            return instance_details
        else:
            logging.error(f"Failed to create instance for {task_name}. Exiting.")
            return None
    


def main():
    """Main entry point for execution."""
    logging.info("Welcome to the Unified Instance Management System")

    # Load the configuration and instance details
    config_path = "Config.json"
    instance_file = "Instance.json"
    configs = load_config(config_path)

    # Prompt the user to select an event
    logging.info("\nAvailable Events:")
    logging.info("1. DNS")
    logging.info("2. Firewall")
    logging.info("3. Web")
    logging.info("4. ZTNA-Clientless")
    logging.info("5. ZTNA-Clientbased")
    logging.info("6. Terminate Instances")
    choice = input("\nEnter the number corresponding to the event you want to execute (e.g., 1, 2, 3, 4, 5, 6): ").strip()

    if choice == "1":  # DNS
        logging.info("Executing DNS Tasks...")
        config = next(config for config in configs if config["type"] == "windows")
        instance_details = handle_instance_reuse_or_creation(config, "DNS", instance_file)
        if instance_details:
            execute_dns_tasks(instance_details["InstanceId"], instance_details["PublicIpAddress"], load_instance_details(instance_file), instance_file)

    elif choice == "2":  # Firewall
        logging.info("Executing Firewall Tasks...")
        # Handle Windows instance
        windows_config = next(config for config in configs if config["type"] == "windows")
        windows_instance_details = handle_instance_reuse_or_creation(windows_config, "Firewall (Windows)", instance_file)

        # Handle Linux instance
        linux_config = next(config for config in configs if config["type"] == "linux")
        linux_instance_details = handle_instance_reuse_or_creation(linux_config, "Firewall (Linux)", instance_file)

        # Pass both instances to the Firewall task
        if windows_instance_details and linux_instance_details:
            execute_firewall_tasks(windows_instance_details, linux_instance_details, instance_file)
            logging.info("Firewall tasks executed successfully (placeholder).")
    elif choice == "3":  # Web
        logging.info("Executing Web Tasks...")
        config = next(config for config in configs if config["type"] == "windows")
        instance_details = handle_instance_reuse_or_creation(config, "Web", instance_file)
        if instance_details:
            execute_web_tasks(
                instance_details["InstanceId"],
                instance_details["PublicIpAddress"],
                load_instance_details(instance_file),
                instance_file
            )
    elif choice == "4":  # ZTNA-Clientless
        logging.info("Executing ZTNA-Clientless Tasks...")
        config = next(config for config in configs if config["type"] == "linux")
        instance_details = handle_instance_reuse_or_creation(config, "ZTNA-Clientless", instance_file)
        if instance_details:
            print(instance_details["PublicIpAddress"],instance_details["Username"],config["key_file"])
            execute_ztna_clientless_tasks(
                instance_details["PublicIpAddress"],
                instance_details["Username"],
                config["key_file"]
            )
            logging.info("ZTNA-Clientless tasks executed successfully (placeholder).")

    elif choice == "5":  # ZTNA-Clientbased
        logging.info("Executing ZTNA-Clientbased Tasks...")
        config = next(config for config in configs if config["type"] == "windows-ztna-client")
        instance_details = handle_instance_reuse_or_creation(config, "ZTNA-Clientbased", instance_file)
        if instance_details:
            execute_ztna_clientbased_tasks(
                public_ip=instance_details["PublicIpAddress"],
                username="Administrator",
                password=instance_details["Password"],
                key_file=config["key_file"],
                org_id=input("Enter OrgID: ").strip(),
                config=config
            )
            logging.info("ZTNA-Clientbased tasks executed successfully (placeholder).")

    elif choice == "6":  # Terminate Instances
        logging.info("Terminating Instances...")
        terminate_instances(instance_file)
        logging.info("All instances terminated successfully.")

    else:
        logging.error("Invalid choice. Exiting.")
        return


if __name__ == "__main__":
    main()