import streamlit as st
from src.DNS.Tasks import configure_dns
from src.utils import (
    load_config,
    load_instance_file,
    save_instance_file,
    create_instance,
    get_windows_password,
    disable_source_destination_check,
    INSTANCE_JSON_FILE,
    get_instance_details_from_aws,
    check_internet_connectivity,
    test_winrm_connection,
    wait_for_winrm_ready,
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
    config = load_config("Config.json")
    if not config:
        st.error("Config.json is empty. Please provide AWS parameters and update Config.json.")
        return
    dns_config = next((c for c in config if c["type"] == "windows"), None)
    if not dns_config:
        st.error("No Windows config found in Config.json.")
        return

    st.subheader("Step 1 : Creation/Reuse of Instance")
    reuse = st.radio("Do you want to reuse an existing instance for DNS?", ["Yes", "No"], key="dns_reuse")
    instance_details = None
    if reuse == "Yes":
        instance_id = st.text_input("Enter the Instance ID to reuse:", key="dns_instance_id")
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
        instance_name = st.text_input("Enter a name for the new instance:", value=dns_config.get("instance_name", "dns-instance"), key="dns_instance_name")
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
                    "InstanceName": instance_name
                }
                if "windows" in dns_config["type"]:
                    import time
                    st.info("Waiting 4 minutes for Windows instance initialization and WinRM configuration. Please do not proceed until this completes.")
                    st.info("🔧 The instance is being automatically configured with WinRM for remote access (Ansible-style automation). No manual steps required.")
                    with st.empty():
                        for i in range(4*60, 0, -1):
                            mins, secs = divmod(i, 60)
                            if i > 4*60:
                                status = "Windows booting and generating password"
                            else:
                                status = "WinRM configuration in progress"
                            st.write(f"⏳ {status}: {mins:02d}:{secs:02d} remaining...")
                            time.sleep(1)
                    st.success("Windows instance initialization and WinRM configuration should be complete.")
                    ec2 = boto3.client("ec2", region_name=dns_config["aws_region"])
                    password = get_windows_password(ec2, instance_id, dns_config["key_file"], initial_wait=5)
                    details["Password"] = password
                    details["Username"] = "Administrator"
                    st.info("🔍 Verifying WinRM configuration is complete...")
                    winrm_ready, winrm_message = wait_for_winrm_ready(
                        details["PublicIpAddress"],
                        details["Username"],
                        details["Password"],
                        max_wait_minutes=5
                    )
                    if winrm_ready:
                        st.success(f"✅ {winrm_message}")
                        details["WinRMConfigured"] = True
                    else:
                        st.error(f"❌ {winrm_message}")
                        details["WinRMConfigured"] = False
                update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                st.success("New instance created and saved.")
                st.json(details)
                instance_details = details
                st.session_state["dns_instance_details"] = details
            else:
                st.error("Failed to create new instance.")
        instance_details = st.session_state.get("dns_instance_details", instance_details)

    # Reset Instance Selection Option
    if instance_details:
        st.success(f"Using instance: {instance_details['InstanceId']}")
        if st.button("Reset Instance Selection"):
            for k in [
                "dns_instance_details",
                "dns_precheck_ok",
                "dns_internet_ok",
                "dns_network_registered",
                "dns_task_ok",
                "dns_reuse",
                "dns_instance_id",
                "dns_instance_name"
            ]:
                if k in st.session_state:
                    del st.session_state[k]
            st.rerun()

    # 2. Step 2: WinRM info or connectivity check
    if instance_details and instance_details.get("Password"):
        if reuse == "Yes":
            st.subheader("Step 2: Manual - Disable Firewall & Enable WinRM on Windows")
            show_disable_firewall_and_enable_winrm(instance_details["PublicIpAddress"])
            st.markdown("**RDP Credentials:**")
            st.code(f"Public IP: {instance_details['PublicIpAddress']}\nUsername: {instance_details.get('Username', 'Administrator')}\nPassword: {instance_details['Password']}", language="text")
            if st.button("I have disabled the firewall and enabled WinRM. Continue."):
                st.session_state["dns_precheck_ok"] = True
            if not st.session_state.get("dns_precheck_ok"):
                return

        else:
            st.subheader("Step 2: Automated WinRM Connectivity Check")
            st.info("Testing WinRM connection. All configuration is automated via user data. No manual steps required.")
            test_button = st.button("🔍 Test WinRM Connection")
            if test_button:
                with st.spinner("Testing WinRM connection..."):
                    success, message = test_winrm_connection(
                        instance_details["PublicIpAddress"],
                        instance_details.get("Username", "Administrator"),
                        instance_details["Password"]
                    )
                    if success:
                        st.success("✅ WinRM is configured and working!")
                        st.text_area("Connection Test Result", message, height=100)
                        st.session_state["dns_precheck_ok"] = True
                    else:
                        st.error("❌ WinRM connection failed. Please check instance configuration or try again.")
                        st.text_area("Connection Test Result", message, height=100)
                        st.session_state["dns_precheck_ok"] = False
            if not st.session_state.get("dns_precheck_ok"):
                return

        # 3. Check Internet Connectivity
        st.subheader("Step 3: Check Internet Connectivity (Windows)")
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
                    st.session_state["dns_internet_ok"] = True
                else:
                    st.error("Ping failed. Check network settings.")
            except Exception as e:
                st.error(f"Error during connectivity check: {e}")
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
                    st.session_state["dns_task_ok"] = True
                except Exception as e:
                    st.error(f"Error: {e}")
                    return
            else:
                st.warning("Please enter both Primary and Alternate DNS IPs to proceed.")

    # Final step: All done
    if all([
        st.session_state.get("dns_precheck_ok"),
        st.session_state.get("dns_internet_ok"),
        st.session_state.get("dns_task_ok")
    ]):
        st.success("DNS workflow completed successfully!")
        st.balloons()