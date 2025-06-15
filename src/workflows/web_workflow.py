import streamlit as st
from src.utils import (
    load_config,
    load_instance_file,
    save_instance_file,
    create_instance,
    INSTANCE_JSON_FILE,
    get_instance_details_from_aws,
    show_disable_firewall_and_enable_winrm
)
import boto3

from src.Web.Tasks import configure_proxy, install_firefox, configure_firefox_proxy, launch_and_close_firefox

def update_instance_in_json(instance_id, updated_details, instance_file):
    instances = load_instance_file()
    for instance in instances:
        if instance["InstanceId"] == instance_id:
            instance.update(updated_details)
            break
    else:
        instances.append(updated_details)
    save_instance_file(instances)

def execute_web_workflow():
    st.header("Web Task Execution")
    config = load_config("Config.json")
    if not config:
        st.error("Config.json is empty. Please provide AWS parameters and update Config.json.")
        return
    web_config = next((c for c in config if c["type"] == "windows"), None)
    if not web_config:
        st.error("No Windows config found in Config.json.")
        return

    st.subheader("Step 1: Instance Management")
    reuse = st.radio("Do you want to reuse an existing instance for Web?", ["Yes", "No"])
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
                if instance.get("PublicIpAddress"):
                    show_disable_firewall_and_enable_winrm(instance["PublicIpAddress"])
            else:
                st.info("Instance not found in Instance.json. Will fetch from AWS if you click below.")
                if st.button("Fetch from AWS"):
                    details = get_instance_details_from_aws(instance_id, web_config["aws_region"], web_config.get("key_file"))
                    if details:
                        update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                        st.success("Fetched and saved instance details from AWS.")
                        st.json(details)
                        instance_details = details
                        if details.get("PublicIpAddress"):
                            show_disable_firewall_and_enable_winrm(details["PublicIpAddress"])
                    else:
                        st.error("Failed to fetch instance details from AWS.")
    else:
        instance_name = st.text_input("Enter a name for the new Web instance:", value=web_config.get("instance_name", ""))
        if st.button("Create New Instance"):
            config_with_name = dict(web_config)
            config_with_name["instance_name"] = instance_name
            instance_id, public_ip, private_ip = create_instance(config_with_name)
            if instance_id:
                details = {
                    "InstanceId": instance_id,
                    "PublicIpAddress": public_ip,
                    "PrivateIpAddress": private_ip,
                    "InstanceType": web_config["instance_type"],
                }
                if "windows" in web_config["type"]:
                    ec2 = boto3.client("ec2", region_name=web_config["aws_region"])
                    password = get_windows_password(ec2, instance_id, web_config["key_file"], initial_wait=240)
                    details["Password"] = password
                    details["Username"] = "Administrator"
                update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                st.success("New instance created and saved.")
                st.json(details)
                instance_details = details
                if details.get("PublicIpAddress"):
                    show_disable_firewall_and_enable_winrm(details["PublicIpAddress"])
            else:
                st.error("Failed to create new instance.")

    # Only proceed if instance_details and password are set
    if not (instance_details and instance_details.get("Password")):
        return

    # Step 2: Manual - Disable Firewall & Enable WinRM
    if not st.session_state.get("web_precheck_ok"):
        st.subheader("Step 2: Manual - Disable Firewall & Enable WinRM on Windows")
        show_disable_firewall_and_enable_winrm(instance_details["PublicIpAddress"])
        st.markdown("**RDP Credentials:**")
        st.code(f"Public IP: {instance_details['PublicIpAddress']}\nUsername: {instance_details.get('Username', 'Administrator')}\nPassword: {instance_details['Password']}", language="text")
        if st.button("I have disabled the firewall and enabled WinRM. Continue."):
            st.session_state["web_precheck_ok"] = True
        return

    # Step 3: Manual - Register the Network in SSE Dashboard
    if not st.session_state.get("web_network_registered"):
        st.subheader("Step 3: Manual - Register the Network in SSE Dashboard")
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
            st.session_state["web_network_registered"] = True
        return

    # Step 4: Check Internet Connectivity (Windows)
    if not st.session_state.get("web_internet_ok"):
        st.subheader("Step 4: Check Internet Connectivity (Windows)")
        if st.button("Check Connectivity"):
            try:
                check_internet_connectivity(
                    instance_details["PublicIpAddress"],
                    instance_details.get("Username", "Administrator"),
                    instance_details["Password"],
                )
                st.success("Internet connectivity check completed successfully.")
            except Exception as e:
                st.error(f"Error: {e}")
                return
        if st.button("Continue after successful connectivity check"):
            st.session_state["web_internet_ok"] = True
        return

    # Step 5: Configure Proxy Settings (PAC file)
    if not st.session_state.get("web_proxy_ok"):
        st.subheader("Step 5: Configure Proxy Settings (PAC file)")
        pac_file = st.text_input("Enter PAC file URL:")
        if st.button("Apply Proxy Settings"):
            if pac_file:
                try:
                    configure_proxy(
                        instance_details["PublicIpAddress"],
                        instance_details.get("Username", "Administrator"),
                        instance_details["Password"],
                        pac_file
                    )
                    st.success("Proxy configuration applied successfully.")
                    st.session_state["web_proxy_ok"] = True
                except Exception as e:
                    st.error(f"Error: {e}")
                    return
            else:
                st.warning("Please enter the PAC file URL to proceed.")
        return

    # Step 6: Install Mozilla Firefox
    if not st.session_state.get("web_firefox_installed"):
        st.subheader("Step 6: Install Mozilla Firefox")
        if st.button("Install Firefox"):
            try:
                install_firefox(
                    instance_details["PublicIpAddress"],
                    instance_details.get("Username", "Administrator"),
                    instance_details["Password"]
                )
                st.success("Mozilla Firefox installed successfully.")
                st.session_state["web_firefox_installed"] = True
            except Exception as e:
                st.error(f"Error: {e}")
                return
        return

    # Step 7: Launch and Close Mozilla Firefox
    if not st.session_state.get("web_firefox_launched"):
        st.subheader("Step 7: Launch and Close Mozilla Firefox")
        if st.button("Launch and Close Firefox"):
            try:
                launch_and_close_firefox(
                    instance_details["PublicIpAddress"],
                    instance_details.get("Username", "Administrator"),
                    instance_details["Password"]
                )
                st.success("Mozilla Firefox launched and closed successfully.")
                st.session_state["web_firefox_launched"] = True
            except Exception as e:
                st.error(f"Error: {e}")
                return
        return

    # Step 8: Configure Proxy Settings in Firefox
    st.subheader("Step 8: Configure Proxy Settings in Firefox")
    firefox_proxy_url = st.text_input("Enter Proxy URL for Firefox:")
    if st.button("Apply Firefox Proxy Settings"):
        if firefox_proxy_url:
            try:
                configure_firefox_proxy(
                    instance_details["PublicIpAddress"],
                    instance_details.get("Username", "Administrator"),
                    instance_details["Password"],
                    firefox_proxy_url
                )
                st.success("Firefox proxy configuration applied successfully.")
            except Exception as e:
                st.error(f"Error: {e}")
                return
        else:
            st.warning("Please enter the Firefox proxy URL to proceed.")
