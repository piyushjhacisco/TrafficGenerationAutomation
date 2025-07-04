import streamlit as st
from src.utils import (
    load_config,
    load_instance_file,
    save_instance_file,
    create_instance,
    disable_source_destination_check,
    INSTANCE_JSON_FILE,
    get_instance_details_from_aws,
    show_disable_firewall_and_enable_winrm,
    get_windows_password,
    check_internet_connectivity,
    wait_for_winrm_ready,
    test_winrm_connection
)
from src.Firewall.Tasks import change_default_gateway_winrm
import boto3
import time

def update_instance_in_json(instance_id, updated_details, instance_file):
    instances = load_instance_file()
    for instance in instances:
        if instance["InstanceId"] == instance_id:
            instance.update(updated_details)
            break
    else:
        instances.append(updated_details)
    save_instance_file(instances)

def execute_firewall_workflow():
    config = load_config("Config.json")
    if not config:
        st.error("Config.json is empty. Please provide AWS parameters and update Config.json.")
        return
    windows_config = next((c for c in config if c.get("type", "").lower() == "windows"), None)
    linux_config = next((c for c in config if c.get("type", "").lower() == "linux"), None)
    if not windows_config or not linux_config:
        st.error("Both Windows and Linux configs are required in Config.json.")
        return

    # --- Step running state management ---
    if "fw_step_running" not in st.session_state:
        st.session_state["fw_step_running"] = False

    def set_step_running(val=True):
        st.session_state["fw_step_running"] = val

    def disable_if_running(**kwargs):
        return {**kwargs, "disabled": st.session_state["fw_step_running"]}

    # --- Windows Instance Management (Reuse or Create) ---
    st.subheader("Step 1: Windows Instance Management")
    win_instance = None
    win_mode = st.session_state.get("fw_win_instance_selected")
    reuse = st.radio("Do you want to reuse an existing instance for Firewall?", ["Yes", "No"], key="fw_win_reuse")
    if reuse == "Yes":
        st.session_state["fw_win_instance_selected"] = "reuse"
        instance_id = st.text_input("Enter the Instance ID to reuse:", key="fw_win_instance_id")
        if instance_id:
            instances = load_instance_file()
            instance = next((i for i in instances if i["InstanceId"] == instance_id), None)
            if instance:
                st.success("Instance found in Instance.json.")
                win_instance = instance
                st.session_state["fw_win_instance"] = win_instance
            else:
                st.info("Instance not found in Instance.json. Will fetch from AWS if you click below.")
                if st.button("Fetch from AWS", key="fw_win_fetch_aws"):
                    details = get_instance_details_from_aws(instance_id, windows_config["aws_region"], windows_config.get("key_file"))
                    if details:
                        update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                        st.success("Fetched and saved instance details from AWS.")
                        win_instance = details
                        st.session_state["fw_win_instance"] = win_instance
                    else:
                        st.error("Failed to fetch instance details from AWS.")
    else:
        st.session_state["fw_win_instance_selected"] = "create"
        instance_name = st.text_input("Enter a name for the new Windows instance:", value=windows_config.get("instance_name", "firewall-instance"), key="fw_win_instance_name")
        if st.button("Create New Instance", key="fw_win_create_instance"):
            config_with_name = dict(windows_config)
            config_with_name["instance_name"] = instance_name
            instance_id, public_ip, private_ip = create_instance(config_with_name)
            if instance_id:
                disable_source_destination_check(instance_id)
                details = {
                    "InstanceId": instance_id,
                    "PublicIpAddress": public_ip,
                    "PrivateIpAddress": private_ip,
                    "InstanceType": windows_config["instance_type"],
                    "InstanceName": instance_name
                }
                if "windows" in windows_config["type"]:
                    st.info("Waiting 4 minutes for Windows instance initialization. Please do not proceed until this completes.")
                    with st.empty():
                        for i in range(4*60, 0, -1):
                            mins, secs = divmod(i, 60)
                            st.write(f"\u23f3 Windows instance initializing: {mins:02d}:{secs:02d} remaining...")
                            time.sleep(1)
                    st.success("Windows instance initialization wait complete. You may proceed.")
                    ec2 = boto3.client("ec2", region_name=windows_config["aws_region"])
                    password = get_windows_password(ec2, instance_id, windows_config["key_file"], initial_wait=5)
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
                win_instance = details
                st.session_state["fw_win_instance"] = win_instance
            else:
                st.error("Failed to create new instance.")
    # Always restore win_instance from session state if available
    if not win_instance and st.session_state.get("fw_win_instance"):
        win_instance = st.session_state["fw_win_instance"]

    # Only proceed if win_instance is valid
    if not win_instance or not win_instance.get("Password"):
        st.warning("Please select or create a valid Windows instance to proceed.")
        return
    st.session_state["fw_win_instance"] = win_instance

    # Always show instance details if valid
    if win_instance and win_instance.get("Password"):
        st.success(f"Using instance: {win_instance['InstanceId']}")
        st.json(win_instance)

    # Reset Instance Selection Option (Windows)
    if st.button("Reset Instance Selection (Windows)"):
        for k in [
            "fw_win_instance", "fw_precheck_ok", "fw_win_connectivity", "fw_sse_tunnel_ready", "fw_step_running",
            "fw_linux_instance", "fw_linux_connectivity", "fw_ipsec_details", "fw_ipsec_ok",
            "fw_leftid", "fw_right", "fw_psk",
            "fw_win_reuse", "fw_win_instance_id", "fw_win_instance_name",
            "fw_linux_reuse", "fw_linux_instance_id"
        ]:
            if k in st.session_state:
                del st.session_state[k]
        st.rerun()

    # --- Step 2: WinRM/Firewall Step (Manual for reuse, Automated for create) ---
    win_mode = st.session_state.get("fw_win_instance_selected")
    if win_mode == "reuse":
        st.subheader("Step 2: Manual - Disable Firewall & Enable WinRM on Windows")
        show_disable_firewall_and_enable_winrm(win_instance["PublicIpAddress"])
        st.markdown("**RDP Credentials:**")
        st.code(f"Public IP: {win_instance['PublicIpAddress']}\nUsername: {win_instance.get('Username', 'Administrator')}\nPassword: {win_instance['Password']}", language="text")
        if st.button("I have disabled the firewall and enabled WinRM. Continue."):
            st.session_state["fw_precheck_ok"] = True
        if not st.session_state.get("fw_precheck_ok"):
            return
    elif win_mode == "create":
        st.subheader("Step 2: Test WinRM Connectivity (Automated)")
        if st.button("Test WinRM Connectivity", disabled=st.session_state["fw_step_running"]):
            set_step_running(True)
            try:
                success, output = test_winrm_connection(
                    win_instance["PublicIpAddress"],
                    win_instance["Username"],
                    win_instance["Password"]
                )
                st.text_area("WinRM Test Output", output, height=120)
                if success:
                    st.session_state["fw_precheck_ok"] = True
                    st.success("WinRM connectivity test passed.")
                else:
                    st.error("WinRM connectivity test failed. Please check instance setup.")
            except Exception as e:
                st.error(f"Error during WinRM connectivity test: {e}")
            set_step_running(False)
        if not st.session_state.get("fw_precheck_ok"):
            return
    else:
        st.warning("Please select or create a Windows instance to proceed.")
        return

    # --- Check internet connectivity on Windows ---
    st.subheader("Step 3: Check Internet Connectivity (Windows)")
    if st.button("Check Connectivity (Windows)", disabled=st.session_state["fw_step_running"]):
        set_step_running(True)
        try:
            success, output = check_internet_connectivity(
                win_instance["PublicIpAddress"],
                win_instance["Username"],
                win_instance["Password"]
            )
            st.text_area("Ping Output", output, height=120)
            if success:
                st.session_state["fw_win_connectivity"] = True
                st.success("Windows instance has internet connectivity.")
            else:
                st.error("Ping failed. Check network settings.")
        except Exception as e:
            st.error(f"Error during connectivity check: {e}")
        set_step_running(False)
    if not st.session_state.get("fw_win_connectivity"):
        return

    # --- Step 4: Manual - Create Tunnel on SSE Dashboard ---
    st.subheader("Step 4: Manual - Create Tunnel on SSE Dashboard")
    sse_steps = f"""
    --- ACTION REQUIRED ---
    Please follow these steps to create a tunnel on the SSE Dashboard:
    1. Go to **SSE Dashboard** → **Connect** → **Network Connections** → **Network Tunnel Groups** → Click on **Add**
    2. Provide any tunnel name, select **Region** where SFCN entrypoints are deployed, set **Device type** to **Others**
    3. Provide any tunnel ID and passphrase
    4. Click on **Static Routing**, add Windows private IP: **{win_instance.get('PrivateIpAddress', 'N/A')}** into the box, and save the details. Keep the tunnel ID and passphrase for further use.
    """
    st.code(sse_steps, language="text")
    st.info("After completing the above steps, click below.")
    if st.button("I have created the tunnel on SSE Dashboard."):
        st.session_state["fw_sse_tunnel_ready"] = True
    if not st.session_state.get("fw_sse_tunnel_ready"):
        return

    # --- Linux Instance Management (Reuse or Create) ---
    st.subheader("Step 5: Linux Instance Management")
    reuse_linux = st.radio("Do you want to reuse an existing Linux instance?", ["Yes", "No"], key="fw_linux_reuse")
    if reuse_linux == "Yes":
        linux_instance_id = st.text_input("Enter Linux Instance ID to reuse:", key="fw_linux_instance_id")
        if linux_instance_id:
            instances = load_instance_file()
            instance = next((i for i in instances if i["InstanceId"] == linux_instance_id), None)
            if instance:
                st.success("Instance found in Instance.json.")
                linux_instance = instance
                st.session_state["fw_linux_instance"] = linux_instance
            else:
                st.info("Instance not found in Instance.json. Will fetch from AWS if you click below.")
                if st.button("Fetch from AWS (Linux)", key="fw_linux_fetch_aws"):
                    details = get_instance_details_from_aws(linux_instance_id, linux_config["aws_region"], linux_config.get("key_file"))
                    if details:
                        update_instance_in_json(linux_instance_id, details, INSTANCE_JSON_FILE)
                        st.success("Fetched and saved Linux instance details from AWS.")
                        linux_instance = details
                        st.session_state["fw_linux_instance"] = linux_instance
                    else:
                        st.error("Failed to fetch instance details from AWS.")
    else:
        linux_instance_name = st.text_input("Enter a name for the new Linux instance:", value=linux_config.get("instance_name", "linux-instance"), key="fw_linux_instance_name")
        if st.button("Create Linux Instance", key="fw_linux_create_instance"):
            config_with_name = dict(linux_config)
            config_with_name["instance_name"] = linux_instance_name
            instance_id, public_ip, private_ip = create_instance(config_with_name)
            if instance_id:
                disable_source_destination_check(instance_id)
                details = {
                    "InstanceId": instance_id,
                    "PublicIpAddress": public_ip,
                    "PrivateIpAddress": private_ip,
                    "InstanceType": linux_config["instance_type"],
                    "InstanceName": linux_instance_name,
                    "Username": linux_config.get("username", "ubuntu")
                }
                update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                st.session_state["fw_linux_instance"] = details
                st.success("Linux instance created and saved. Waiting 4 minutes for initialization...")
                with st.spinner("Waiting for Ubuntu instance to initialize (4 minutes)..."):
                    time.sleep(240)
                linux_instance = details
                st.session_state["fw_linux_instance"] = linux_instance
            else:
                st.error("Failed to create Linux instance.")
    # Only proceed if linux_instance is valid
    linux_instance = st.session_state.get("fw_linux_instance")
    if not linux_instance or not linux_instance.get("InstanceId") or not linux_instance.get("PublicIpAddress"):
        st.warning("Please select or create a valid Linux instance to proceed.")
        return

    # Only show details after a valid selection/creation
    if st.session_state.get("fw_linux_reuse") in ("Yes", "No") and linux_instance and linux_instance.get("InstanceId") and linux_instance.get("PublicIpAddress"):
        st.success(f"Using Linux instance: {linux_instance['InstanceId']}")
        st.json(linux_instance)

    # --- Check internet connectivity on Linux (via SSH and ping) ---
    if linux_instance:
        st.subheader("Step 6: Check Internet Connectivity (Linux)")
        if "fw_linux_connectivity" not in st.session_state:
            if st.button("Check Connectivity (Linux)", key="fw_check_linux_conn", disabled=st.session_state["fw_step_running"]):
                import paramiko
                import io
                log_area = st.empty()
                try:
                    log_area.info("Connecting to Linux instance via SSH...")
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    key_file = linux_config.get("key_file")
                    private_key = paramiko.RSAKey.from_private_key_file(key_file)
                    ssh.connect(hostname=linux_instance["PublicIpAddress"], username=linux_instance["Username"], pkey=private_key, timeout=60)
                    log_area.info("Connected. Running ping...")
                    stdin, stdout, stderr = ssh.exec_command("ping -c 4 8.8.8.8")
                    output = stdout.read().decode()
                    error = stderr.read().decode()
                    if output:
                        log_area.text_area("Ping Output", output, height=120)
                    if error:
                        log_area.text_area("Ping Error", error, height=120)
                    # Pass if output contains 'bytes from', 'Reply from', '0% packet loss', or 'Minimum ='
                    if ("bytes from" in output or "Reply from" in output or "0% packet loss" in output or "Minimum =" in output):
                        st.session_state["fw_linux_connectivity"] = True
                        st.success("Linux instance has internet connectivity.")
                    else:
                        st.error("Ping failed. Check network settings.")
                except Exception as e:
                    log_area.error(f"SSH/Ping error: {e}")
                    st.error(f"Error: {e}")
                finally:
                    try:
                        ssh.close()
                    except:
                        pass
        else:
            st.success("Linux instance has internet connectivity.")
    if not st.session_state.get("fw_linux_connectivity"):
        return

    # --- IPsec Setup (Ubuntu) ---
    st.subheader("Step 7: IPsec Setup (Ubuntu)")
    leftid = st.text_input("Left ID (e.g., TestTraffic@domain.com):", key="fw_leftid")
    right = st.text_input("Right Address (e.g., 54.71.129.174):", key="fw_right")
    psk = st.text_input("PSK (Pre-Shared Key):", type="password", key="fw_psk")
    if st.button("Save IPsec Details", **disable_if_running()):
        if leftid and right and psk:
            ipsec_details = {
                "leftid": leftid,
                "leftsubnet": win_instance.get("PrivateIpAddress", ""),
                "right": right,
                "psk": psk
            }
            st.session_state["fw_ipsec_details"] = ipsec_details
            st.success("IPsec details saved. Proceed to configure IPsec on Ubuntu.")
        else:
            st.warning("Please fill out all IPsec fields.")
    ipsec_details = st.session_state.get("fw_ipsec_details")
    if ipsec_details and st.button("Configure IPsec on Ubuntu", **disable_if_running()):
        set_step_running(True)
        try:
            import json
            with open("ipsec_details.json", "w") as f:
                json.dump(ipsec_details, f, indent=4)
            # Use load_config from src.utils, not from src.Firewall.Tasks
            ubuntu_config = load_config("Config.json")
            ubuntu_linux_config = next((c for c in ubuntu_config if c.get("type", "").lower() == "linux"), None)
            from src.Firewall.Tasks import ssh_and_configure_ipsec
            logs = ssh_and_configure_ipsec(
                linux_instance["PublicIpAddress"],
                linux_instance["Username"],
                ubuntu_linux_config["key_file"],
                ipsec_details
            )
            st.session_state["fw_ipsec_ok"] = True
            st.success("IPsec configured on Ubuntu successfully.")
            st.text_area("IPsec Setup Logs", logs, height=200)
        except Exception as e:
            st.error(f"Error configuring IPsec: {e}")
            if hasattr(e, 'args') and e.args:
                st.text_area("IPsec Setup Logs", e.args[0], height=200)
            if st.button("Retry IPsec Setup", **disable_if_running()):
                set_step_running(False)
                st.experimental_rerun()
            set_step_running(False)
            return
        set_step_running(False)
    if not st.session_state.get("fw_ipsec_ok"):
        return

    # --- Step 8: Change Default Gateway (Windows) ---
    if 'fw_win_instance' in st.session_state and st.session_state['fw_win_instance']:
        win_instance = st.session_state['fw_win_instance']
        st.subheader("Step 8: Change Default Gateway (Windows)")
        if st.button("Change Default Gateway on Windows"):
            try:
                logs, old_gw = change_default_gateway_winrm(win_instance, linux_instance)
                st.text_area("Change Default Gateway Logs", "\n".join(logs), height=200)
                st.session_state["fw_old_default_gateway"] = old_gw
                st.success("Default gateway changed on Windows (see logs above for details)")
            except Exception as e:
                st.error(f"Error changing default gateway: {e}")
                import traceback
                st.text_area("Change Default Gateway Logs", traceback.format_exc(), height=200)
    else:
        st.warning("Please select or create a Windows instance and set st.session_state['fw_win_instance'] before testing this step.")
        
    # --- Step 8: Change Default Gateway (Windows) ---
    if 'fw_win_instance' in st.session_state and st.session_state['fw_win_instance']:
        win_instance = st.session_state['fw_win_instance']
        st.subheader("Step 9: Manual - Configure Gateway Settings on Windows")
        gateway_steps = '''
        --- ACTION REQUIRED ---
        Please follow these steps to manually configure gateway and DNS settings on your Windows instance:
        1. Go to **Network and Internet settings**
        2. Select **Ethernet**
        3. Double click on **Ethernet** → click on **Properties**
        4. Select **Internet Protocol Version 4 (TCP/IPv4)** and click **Properties**
        5. Select **Use the following IP address** and provide the required details (IP address, Subnet mask, Default gateway)
        6. For **Preferred DNS server** and **Alternate DNS server**, enter: **8.8.8.8** and **1.1.1.1** (for testing)
        7. Click **OK** to save the settings.
        '''
        st.code(gateway_steps, language="text")
        st.info("After completing the above steps, click below.")
        if st.button("I have configured the gateway and DNS settings on Windows."):
            st.session_state["fw_gateway_settings_done"] = True
        if not st.session_state.get("fw_gateway_settings_done"):
            return       
    if all([
        st.session_state.get("fw_precheck_ok"),
        st.session_state.get("fw_win_connectivity"),
        st.session_state.get("fw_sse_tunnel_ready"),
        st.session_state.get("fw_linux_instance"),
        st.session_state.get("fw_linux_connectivity"),
        st.session_state.get("fw_ipsec_ok"),
        st.session_state.get("fw_gateway_settings_done")
    ]):
        st.success("Firewall workflow completed successfully!")
        st.balloons()

