import streamlit as st
from src.utils import (
    load_config,
    load_instance_file,
    save_instance_file,
    create_instance,
    INSTANCE_JSON_FILE,
    get_instance_details_from_aws,
    show_disable_firewall_and_enable_winrm,
    get_windows_password,
    check_internet_connectivity
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

    # Step 1: Instance Management
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
            else:
                st.info("Instance not found in Instance.json. Will fetch from AWS if you click below.")
                if st.button("Fetch from AWS"):
                    details = get_instance_details_from_aws(instance_id, web_config["aws_region"], web_config.get("key_file"))
                    if details:
                        update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                        st.success("Fetched and saved instance details from AWS.")
                        st.json(details)
                        instance_details = details
                    else:
                        st.error("Failed to fetch instance details from AWS.")
    else:
        instance_name = st.text_input("Enter a name for the new Web instance:", value=web_config.get("instance_name", "web-instance"))
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
                    "InstanceName": instance_name
                }
                if "windows" in web_config["type"]:
                    import time
                    st.info("Waiting 4 minutes for Windows instance initialization. Please do not proceed until this completes.")
                    with st.empty():
                        for i in range(4*60, 0, -1):
                            mins, secs = divmod(i, 60)
                            st.write(f"\u23f3 Windows instance initializing: {mins:02d}:{secs:02d} remaining...")
                            time.sleep(1)
                    st.success("Windows instance initialization wait complete. You may proceed.")
                    ec2 = boto3.client("ec2", region_name=web_config["aws_region"])
                    password = get_windows_password(ec2, instance_id, web_config["key_file"], initial_wait=5)
                    details["Password"] = password
                    details["Username"] = "Administrator"
                update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                st.success("New instance created and saved.")
                st.json(details)
                instance_details = details
                st.session_state["web_instance_details"] = details
            else:
                st.error("Failed to create new instance.")
        instance_details = st.session_state.get("web_instance_details", instance_details)

    # Reset Instance Selection Option
    if instance_details:
        st.success(f"Using instance: {instance_details['InstanceId']}")
        st.json(instance_details)
        if st.button("Reset Instance Selection"):
            if "web_instance_details" in st.session_state:
                del st.session_state["web_instance_details"]
            for k in [
                "web_precheck_ok", "web_network_registered", "web_internet_ok", "web_proxy_ok", "web_firefox_installed"
            ]:
                if k in st.session_state:
                    del st.session_state[k]
            st.rerun()

    # Only proceed if instance_details and password are set
    if instance_details and instance_details.get("Password"):
        st.session_state["web_instance_details"] = instance_details
    instance_details = st.session_state.get("web_instance_details")
    if not (instance_details and instance_details.get("Password")):
        return

    # Step 2: Manual - Disable Firewall & Enable WinRM
    st.subheader("Step 2: Manual - Disable Firewall & Enable WinRM on Windows")
    show_disable_firewall_and_enable_winrm(instance_details["PublicIpAddress"])
    st.markdown("**RDP Credentials:**")
    st.code(f"Public IP: {instance_details['PublicIpAddress']}\nUsername: {instance_details.get('Username', 'Administrator')}\nPassword: {instance_details['Password']}", language="text")
    if st.button("I have disabled the firewall and enabled WinRM. Continue."):
        st.session_state["web_precheck_ok"] = True
    if not st.session_state.get("web_precheck_ok"):
        return

    # Step 3: Manual - Register the Network in SSE Dashboard
    if st.session_state.get("web_precheck_ok"):
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
        if not st.session_state.get("web_network_registered"):
            if st.button("I have registered the network in SSE Dashboard."):
                st.session_state["web_network_registered"] = True
        if not st.session_state.get("web_network_registered"):
            return

    # Step 4: Check Internet Connectivity (Windows)
    if st.session_state.get("web_network_registered"):
        st.subheader("Step 4: Check Internet Connectivity (Windows)")
        if not st.session_state.get("web_internet_ok"):
            if st.button("Check Connectivity"):
                try:
                    success, output = check_internet_connectivity(
                        instance_details["PublicIpAddress"],
                        instance_details.get("Username", "Administrator"),
                        instance_details["Password"],
                    )
                    st.text_area("Ping Output", output, height=120)
                    if success:
                        st.success("Internet connectivity check completed successfully.")
                        st.session_state["web_internet_ok"] = True
                    else:
                        st.error("Ping failed. Check network settings.")
                except Exception as e:
                    st.error(f"Error during connectivity check: {e}")
            # Only return if connectivity is not yet confirmed
            if not st.session_state.get("web_internet_ok"):
                return

    # Step 5: Configure Proxy Settings (PAC file)
    if st.session_state.get("web_internet_ok"):
        st.subheader("Step 5: Configure Proxy Settings (PAC file)")
        st.info("""
For PAC file you have to obtain it by following the below steps:
1. Login to SSE Dashboard, then navigate to **Connect → End User Connectivity → Internet Security**
2. Copy the Secure Access PAC file and store it somewhere to use further.
""")
        pac_file = st.text_input("Enter PAC file URL:")
        if not st.session_state.get("web_proxy_ok"):
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
                else:
                    st.warning("Please enter the PAC file URL to proceed.")
        if not st.session_state.get("web_proxy_ok"):
            return

    # Step 6: Install Mozilla Firefox
    if st.session_state.get("web_proxy_ok"):
        st.subheader("Step 6: Install Mozilla Firefox")
        if not st.session_state.get("web_firefox_installed"):
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
        if not st.session_state.get("web_firefox_installed"):
            return

    # Step 7: Launch and Close Mozilla Firefox
    if st.session_state.get("web_firefox_installed"):
        st.subheader("Step 7: Launch and Close Mozilla Firefox")
        if not st.session_state.get("web_firefox_launched"):
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
        if not st.session_state.get("web_firefox_launched"):
            return

    # Step 8: Configure Proxy Settings in Firefox
    if st.session_state.get("web_firefox_launched"):
        st.subheader("Step 8: Configure Proxy Settings in Firefox")
        st.info("Contact SWG team and get the Proxy URL directly (all the PAC file points to the proxy URL only)")
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

    # Final step: All done
    if all([
        st.session_state.get("web_precheck_ok"),
        st.session_state.get("web_network_registered"),
        st.session_state.get("web_internet_ok"),
        st.session_state.get("web_proxy_ok"),
        st.session_state.get("web_firefox_installed"),
        st.session_state.get("web_firefox_launched")
    ]):
        st.success("Web workflow completed successfully!")
        st.balloons()
