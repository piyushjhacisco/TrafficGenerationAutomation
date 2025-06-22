import streamlit as st
import json
from pathlib import Path
from src.workflows.dns_workflow import execute_dns_workflow
from src.workflows.firewall_workflow import execute_firewall_workflow
from src.workflows.web_workflow import execute_web_workflow
from src.workflows.ztna_clientbased_workflow import execute_ztna_clientbased_workflow
from src.workflows.ztna_clientless_workflow import execute_ztna_clientless_workflow
from src.utils import load_config, load_instance_file, save_instance_file
import boto3

# Save updated values to Config.json
def update_config(updated_values):
    """Update Config.json with user-provided values."""
    config_data = load_config("Config.json")
    for instance in config_data:
        instance["security_group_id"] = updated_values["security_group_id"]
        instance["vpc_id"] = updated_values["vpc_id"]
        instance["subnet_id"] = updated_values["subnet_id"]
        instance["key_name"] = updated_values["key_name"]
        instance["key_file"] = updated_values["key_file"]
    with open("Config.json", "w") as file:
        json.dump(config_data, file, indent=4)
    st.success("Config.json updated successfully!")

def ensure_winrm_ports_open(security_group_id, region):
    ec2 = boto3.client('ec2', region_name=region)
    try:
        ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 5985,
                    'ToPort': 5985,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 5986,
                    'ToPort': 5986,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )
    except ec2.exceptions.ClientError as e:
        if "InvalidPermission.Duplicate" in str(e):
            pass  # Rule already exists
        else:
            raise

# Instance reuse or creation logic
def handle_instance_reuse_or_creation(config, task_name, instance_file):
    """
    Handle instance reuse or creation for a specific task.
    :param config: AWS configuration for the instance.
    :param task_name: The name of the task (e.g., "DNS").
    :param instance_file: Path to the Instance.json file.
    :return: The instance details (dictionary).
    """
    instances = load_instance_file()
    reuse_choice = st.radio(f"Do you want to reuse an existing instance for {task_name}?", ["Yes", "No"])

    if reuse_choice == "Yes":
        if not instances:
            st.warning("No existing instances found. A new instance will be created.")
        else:
            # Select an existing instance
            instance_id = st.selectbox("Select an Instance ID to reuse:", [i["InstanceId"] for i in instances])
            instance = next((i for i in instances if i["InstanceId"] == instance_id), None)
            st.json(instance)
            return instance
    else:
        # Logic to create a new instance
        st.write("Creating a new instance...")
        new_instance = {
            "InstanceId": "i-1234567890abcdef0",  # Simulated value
            "PublicIpAddress": "54.123.45.67",    # Simulated value
            "PrivateIpAddress": "192.168.1.1",    # Simulated value
            "InstanceType": "t3.medium",
        }
        # Automatically open WinRM ports on the security group from config
        if config and "security_group_id" in config and "aws_region" in config:
            ensure_winrm_ports_open(config["security_group_id"], config["aws_region"])
        instances.append(new_instance)
        save_instance_file(instances)
        st.success("New instance created successfully!")
        st.json(new_instance)
        return new_instance

# Step 1: Input AWS Parameters
def input_aws_parameters():
    """Input page for AWS parameters."""
    st.title("Event Generation Automation")

    # AWS Parameter Inputs with toggleable info
    def aws_info(label, help_text, key):
        if "aws_info_open" not in st.session_state:
            st.session_state["aws_info_open"] = {}
        col_a, col_b = st.columns([10,1], gap="small")
        with col_a:
            value = st.text_input(label, key=key)
        with col_b:
            st.markdown("""
                <style>
                .stButton > button {
                    height: 38px !important;
                    width: 38px !important;
                    padding: 0 !important;
                    margin-top: 6px !important;
                    margin-bottom: 0 !important;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                </style>
            """, unsafe_allow_html=True)
            help_button = st.button("💡", key=f"info_{key}")
            if help_button:
                st.session_state["aws_info_open"][key] = not st.session_state["aws_info_open"].get(key, False)
        if st.session_state["aws_info_open"].get(key, False):
            st.info(help_text)
        return value

    security_group_id = aws_info(
        "Security Group ID",
        "The Security Group ID (e.g., sg-xxxxxxxx) controls inbound/outbound traffic for your EC2 instance. Find it in the AWS EC2 Console under 'Security Groups', or create a new one if needed.",
        "security_group_id"
    )
    vpc_id = aws_info(
        "VPC ID",
        "The VPC ID (e.g., vpc-xxxxxxxx) identifies your Virtual Private Cloud. Find it in the AWS VPC Console under 'Your VPCs', or create a new VPC if needed.",
        "vpc_id"
    )
    subnet_id = aws_info(
        "Subnet ID",
        "The Subnet ID (e.g., subnet-xxxxxxxx) specifies the subnet for your EC2 instance. Find it in the AWS VPC Console under 'Subnets', or create a new subnet if needed.",
        "subnet_id"
    )
    key_name = aws_info(
        "Key Name",
        "The Key Name is the name of your EC2 Key Pair (not the file). Find it in the AWS EC2 Console under 'Key Pairs', or create a new key pair if needed.",
        "key_name"
    )
    key_file_path = aws_info(
        "Key File Path (e.g., /path/to/key.pem)",
        "The Key File Path is the full path to your downloaded .pem file for the EC2 Key Pair. Download it when you create a new key pair, or use an existing one.",
        "key_file_path"
    )

    col1, col2, col3 = st.columns([1,8,1], gap="small")
    with col3:
        st.markdown("""
            <style>
            div[data-testid="column"] button[data-testid^='baseButton-aws_next_btn'] {
                min-width: 120px !important;
                max-width: 180px !important;
                width: 100% !important;
                padding: 0.5em 1.5em !important;
                font-size: 1.1em !important;
            }
            </style>
        """, unsafe_allow_html=True)
        # Enhancement: Disable Next button while processing
        if "aws_next_processing" not in st.session_state:
            st.session_state["aws_next_processing"] = False
        next_btn_disabled = st.session_state["aws_next_processing"]
        next_btn = st.button("Next", key="aws_next_btn", disabled=next_btn_disabled)
        if next_btn and not next_btn_disabled:
            st.session_state["aws_next_processing"] = True
            st.rerun()
        # Only process if Next was pressed and processing flag is set
        if st.session_state.get("aws_next_processing", False):
            if all([security_group_id, vpc_id, subnet_id, key_name, key_file_path]):
                try:
                    ec2 = boto3.client("ec2")
                    # Validate VPC
                    vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])
                    if not vpcs["Vpcs"]:
                        st.session_state["aws_next_processing"] = False
                        st.error(f"VPC ID {vpc_id} not found in AWS.")
                        return
                    # Validate Subnet
                    subnets = ec2.describe_subnets(SubnetIds=[subnet_id])
                    if not subnets["Subnets"]:
                        st.session_state["aws_next_processing"] = False
                        st.error(f"Subnet ID {subnet_id} not found in AWS.")
                        return
                    # Validate Key Pair
                    keys = ec2.describe_key_pairs(KeyNames=[key_name])
                    # Validate Security Group
                    sgs = ec2.describe_security_groups(GroupIds=[security_group_id])
                    if not sgs["SecurityGroups"]:
                        st.session_state["aws_next_processing"] = False
                        st.error(f"Security Group ID {security_group_id} not found in AWS.")
                        return
                    vpc_cidr = vpcs["Vpcs"][0]["CidrBlock"]
                    # Add all rules, but suppress per-rule logs
                    rule_errors = []
                    def add_rule(ip_permissions):
                        try:
                            ec2.authorize_security_group_ingress(GroupId=security_group_id, IpPermissions=ip_permissions)
                        except Exception as e:
                            if 'InvalidPermission.Duplicate' not in str(e):
                                rule_errors.append(str(e))
                    add_rule([{'IpProtocol': '-1','IpRanges': [{'CidrIp': vpc_cidr, 'Description': 'Allow all from VPC'}]}])
                    add_rule([{'IpProtocol': '-1','IpRanges': [{'CidrIp': '171.68.0.0/16', 'Description': 'Allow all from 171.68.0.0/16'}]}])
                    add_rule([{'IpProtocol': '-1','IpRanges': [{'CidrIp': '151.186.176.0/20', 'Description': 'Allow all from CCI Umbrella 2'}]}])
                    add_rule([{'IpProtocol': '-1','IpRanges': [{'CidrIp': '151.186.192.0/20', 'Description': 'Allow all from CCI Umbrella 3'}]}])
                    add_rule([
                        {'IpProtocol': 'tcp','FromPort': 5985,'ToPort': 5985,'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Allow WinRM 5985 from anywhere'}]},
                        {'IpProtocol': 'tcp','FromPort': 5986,'ToPort': 5986,'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Allow WinRM 5986 from anywhere'}]},
                    ])
                    if rule_errors:
                        st.session_state["aws_next_processing"] = False
                        st.error("One or more security group rules could not be added: " + "; ".join(rule_errors))
                        return
                except Exception as e:
                    st.session_state["aws_next_processing"] = False
                    st.error(f"AWS validation or security group rule addition failed: {e}")
                    return
                # Only update config if all checks pass
                st.session_state["aws_params"] = {
                    "security_group_id": security_group_id,
                    "vpc_id": vpc_id,
                    "subnet_id": subnet_id,
                    "key_name": key_name,
                    "key_file": key_file_path,
                }
                update_config(st.session_state["aws_params"])
                st.session_state["aws_next_processing"] = False
                st.session_state["page"] = "traffic_selection"
                st.rerun() if hasattr(st, 'rerun') else st.experimental_rerun()
            else:
                st.session_state["aws_next_processing"] = False
                st.warning("Please fill out all fields to proceed.")

# Step 2: Traffic Type Selection
def select_traffic_type():
    """Page for selecting traffic type."""
    st.title("Event Generation Automation")
    traffic_types = ["DNS", "Firewall", "Web", "ZTNA-Clientless", "ZTNA-Clientbased"]
    selected_type = st.radio("Select the traffic type you want to generate:", traffic_types)

    col1, col2 = st.columns([1,1])
    with col1:
        if st.button("Back", key="traffic_back_btn"):
            st.session_state["page"] = "aws_input"
            st.rerun() if hasattr(st, 'rerun') else st.experimental_rerun()
    with col2:
        if st.button("Next", key="traffic_next_btn"):
            st.session_state["traffic_type"] = selected_type
            st.session_state["page"] = "execute_task"
            st.rerun() if hasattr(st, 'rerun') else st.experimental_rerun()

# Step 3: Execute Selected Traffic Task
def execute_task():
    """Execute the selected traffic task."""
    st.title(f"Event Generation Automation: {st.session_state['traffic_type']} Task")
    col1, col2 = st.columns([1,1])
    with col1:
        if st.button("Back", key="task_back_btn"):
            st.session_state["page"] = "traffic_selection"
            st.rerun() if hasattr(st, 'rerun') else st.experimental_rerun()
    with col2:
        st.write("")  # Placeholder for alignment
    if st.session_state["traffic_type"] == "DNS":
        execute_dns_workflow()
    elif st.session_state["traffic_type"] == "Firewall":
        execute_firewall_workflow()
    elif st.session_state["traffic_type"] == "Web":
        execute_web_workflow()
    elif st.session_state["traffic_type"] == "ZTNA-Clientless":
        execute_ztna_clientless_workflow()
    elif st.session_state["traffic_type"] == "ZTNA-Clientbased":
        execute_ztna_clientbased_workflow()
    else:
        st.warning("Feature not implemented yet.")

# Prerequisites Acknowledgment
def show_prerequisites():
    st.markdown("""
    <h1 style='text-align: center; margin-bottom: 0.5em;'>Event Generation Automation</h1>
    """, unsafe_allow_html=True)
    st.header("Prerequisites")
    st.markdown("""
Before you begin, please ensure the following prerequisites are met:

1. **AWS Session Generation**
   - You must have access to generate an AWS session using Streamline.
   - Run the following command in your terminal:
     ```bash
     sl aws session generate --role-name engineer --account-id 07XXXXXXXX --profile default
     ```
   - Replace `07XXXXXXXX` with your **AWS account ID**.
   - This command will generate a temporary AWS session for the specified account.

2. **Prepare AWS EC2 Key Pair**
   - Ensure you have the correct `.pem` file for your AWS key pair.
   - This key file will be required to authenticate with your EC2 instances.

3. **Windows Remote Desktop App**
   - Install the Windows Remote Desktop app to access Windows EC2 instances.
   - You will need this to connect to your Windows instances after they are launched.
""")
    col1, col2 = st.columns([1,1])
    with col1:
        if st.button("Back", key="prereq_back_btn"):
            st.session_state["page"] = "aws_input"
            st.rerun() if hasattr(st, 'rerun') else st.experimental_rerun()
    with col2:
        if st.button("Next: Start Events Generation Automation"):
            st.session_state["prerequisites_acknowledged"] = True
            st.session_state["page"] = "aws_input"
            st.rerun() if hasattr(st, 'rerun') else st.experimental_rerun()

# Main App Navigation
def main_app():
    """Main app navigation."""
    if "page" not in st.session_state:
        st.session_state["page"] = "prerequisites"
    if not st.session_state.get("prerequisites_acknowledged"):
        show_prerequisites()
        return
    if st.session_state["page"] == "aws_input":
        input_aws_parameters()
    elif st.session_state["page"] == "traffic_selection":
        select_traffic_type()
    elif st.session_state["page"] == "execute_task":
        execute_task()

# Run the app
if __name__ == "__main__":
    main_app()