import streamlit as st
from src.DNS.Tasks import check_internet_connectivity, configure_dns
from src.utils import (
    load_config,
    load_instance_file,
    save_instance_file,
    create_instance,
    get_windows_password,
    disable_source_destination_check,
    INSTANCE_JSON_FILE,
    get_instance_details_from_aws,
    show_disable_firewall_and_enable_winrm
)
import boto3

def update_instance_in_json(instance_id, updated_details, instance_file):
    instances = load_instance_file()
    for instance in instances:
        if instance["InstanceId"] == instance_id:
            instance.update(updated_details)
            break
    else:
        instances.append(updated_details)
    save_instance_file(instances)

def execute_dns_workflow():
    st.header("DNS Task Execution")
    config = load_config("Config.json")
    if not config:
        st.error("Config.json is empty. Please provide AWS parameters and update Config.json.")
        return
    dns_config = next((c for c in config if c["type"] == "windows"), None)
    if not dns_config:
        st.error("No Windows config found in Config.json.")
        return

    st.subheader("Instance Management")
    reuse = st.radio("Do you want to reuse an existing instance for DNS?", ["Yes", "No"])
    instance_details = None
    if reuse == "Yes":
        instance_id = st.text_input("Enter the Instance ID to reuse:")
        if instance_id:
            instances = load_instance_file()
            instance = next((i for i in instances if i["InstanceId"] == instance_id), None)
            if instance:
                st.success("Instance found in Instance.json.")
                st.json(instance)
                instance_details = instance
            else:
                st.info("Instance not found in Instance.json. Will fetch from AWS if you click below.")
                if st.button("Fetch from AWS"):
                    details = get_instance_details_from_aws(instance_id, dns_config["aws_region"], dns_config.get("key_file"))
                    if details:
                        update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                        st.success("Fetched and saved instance details from AWS.")
                        st.json(details)
                        instance_details = details
                    else:
                        st.error("Failed to fetch instance details from AWS.")
    else:
        instance_name = st.text_input("Enter a name for the new instance:", value=dns_config.get("instance_name", ""))
        if st.button("Create New Instance"):
            config_with_name = dict(dns_config)
            config_with_name["instance_name"] = instance_name
            instance_id, public_ip, private_ip = create_instance(config_with_name)
            if instance_id:
                disable_source_destination_check(instance_id)
                details = {
                    "InstanceId": instance_id,
                    "PublicIpAddress": public_ip,
                    "PrivateIpAddress": private_ip,
                    "InstanceType": dns_config["instance_type"],
                }
                if "windows" in dns_config["type"]:
                    ec2 = boto3.client("ec2", region_name=dns_config["aws_region"])
                    password = get_windows_password(ec2, instance_id, dns_config["key_file"], initial_wait=240)
                    details["Password"] = password
                    details["Username"] = "Administrator"
                update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                st.success("New instance created and saved.")
                st.json(details)
                instance_details = details
            else:
                st.error("Failed to create new instance.")

    # 1. Instance Management (already present)
    # 2. Disable firewall and enable WinRM
    if instance_details and instance_details.get("Password"):
        st.subheader("Step 2: Manual - Disable Firewall & Enable WinRM on Windows")
        show_disable_firewall_and_enable_winrm(instance_details["PublicIpAddress"])
        # Show credentials for RDP
        st.markdown("**RDP Credentials:**")
        st.code(f"Public IP: {instance_details['PublicIpAddress']}\nUsername: {instance_details.get('Username', 'Administrator')}\nPassword: {instance_details['Password']}", language="text")
        if st.button("I have disabled the firewall and enabled WinRM. Continue."):
            st.session_state["dns_precheck_ok"] = True
        if not st.session_state.get("dns_precheck_ok"):
            return

        # 3. Check Internet Connectivity
        st.subheader("Step 3: Check Internet Connectivity (Windows)")
        if st.button("Check Connectivity"):
            try:
                check_internet_connectivity(
                    instance_details["PublicIpAddress"],
                    instance_details.get("Username", "Administrator"),
                    instance_details["Password"],
                )
                st.success("Internet connectivity check completed successfully.")
                st.session_state["dns_internet_ok"] = True
            except Exception as e:
                st.error(f"Error: {e}")
                return
        if not st.session_state.get("dns_internet_ok"):
            return

        # 4. Register Network in SSE Dashboard
        st.subheader("Step 4: Manual - Register the Network in SSE Dashboard")
        register_steps = f"""
--- ACTION REQUIRED ---
Please follow these steps to register the network in the SSE Dashboard:
1. Go to **SSE Dashboard** → **Resources** → **Registered Networks** → Click on **Add Network**
2. Provide any Network Name and in **IPv4 Address** provide the public IP of the Windows client machine: **{instance_details.get('PublicIpAddress', 'N/A')}**
3. Click on Save.
"""
        st.code(register_steps, language="text")
        st.info("After completing the above steps, click below.")
        if st.button("I have registered the network in SSE Dashboard."):
            st.session_state["dns_network_registered"] = True
        if not st.session_state.get("dns_network_registered"):
            return

        # 5. Configure DNS
        st.subheader("Step 5: Configure DNS Settings")
        primary_dns = st.text_input("Enter Primary DNS Server:")
        alternate_dns = st.text_input("Enter Alternate DNS Server:")
        if st.button("Apply DNS Settings"):
            if primary_dns and alternate_dns:
                try:
                    configure_dns(
                        instance_details["PublicIpAddress"],
                        instance_details.get("Username", "Administrator"),
                        instance_details["Password"],
                        primary_dns,
                        alternate_dns
                    )
                    st.success("DNS configuration applied successfully.")
                    st.success("All DNS tasks completed successfully!")
                except Exception as e:
                    st.error(f"Error: {e}")
                    return
            else:
                st.warning("Please enter both Primary and Alternate DNS IPs to proceed.")
