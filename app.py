import streamlit as st
import json
import os
import time
from pathlib import Path
from src.workflows.dns_workflow import execute_dns_workflow
from src.workflows.firewall_workflow import execute_firewall_workflow
from src.workflows.web_workflow import execute_web_workflow
from src.workflows.ztna_clientbased_workflow import execute_ztna_clientbased_workflow
from src.workflows.ztna_clientless_workflow import execute_ztna_clientless_workflow
from src.utils import load_config, handle_instance_reuse_or_creation, INSTANCE_JSON_FILE, load_instance_file, save_instance_file

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
    with col1:
        st.markdown("""
            <style>
            div[data-testid="column"] button[data-testid^='baseButton-aws_back_btn'] {
                min-width: 120px !important;
                max-width: 180px !important;
                width: 100% !important;
                padding: 0.5em 1.5em !important;
                font-size: 1.1em !important;
            }
            </style>
        """, unsafe_allow_html=True)
        if st.button("Back", key="aws_back_btn"):
            st.session_state["prerequisites_acknowledged"] = False
            st.session_state["page"] = "prerequisites"
            st.rerun() if hasattr(st, 'rerun') else st.experimental_rerun()
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
        if st.button("Next", key="aws_next_btn"):
            if all([security_group_id, vpc_id, subnet_id, key_name, key_file_path]):
                st.session_state["aws_params"] = {
                    "security_group_id": security_group_id,
                    "vpc_id": vpc_id,
                    "subnet_id": subnet_id,
                    "key_name": key_name,
                    "key_file": key_file_path,
                }
                update_config(st.session_state["aws_params"])
                st.session_state["page"] = "traffic_selection"
                st.rerun() if hasattr(st, 'rerun') else st.experimental_rerun()
            else:
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