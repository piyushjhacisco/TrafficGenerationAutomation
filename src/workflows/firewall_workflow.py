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
    check_internet_connectivity
)
from src.Firewall.Tasks import change_default_gateway_winrm
import boto3
import winrm

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
    st.header("Firewall Task Execution")
    st.subheader("Step 1: Windows Instance Management")
    reuse = st.radio("Do you want to reuse an existing instance for Firewall?", ["Yes", "No"])
    win_instance = None
    if reuse == "Yes":
        instance_id = st.text_input("Enter the Instance ID to reuse:")
        if instance_id:
            instances = load_instance_file()
            instance = next((i for i in instances if i["InstanceId"] == instance_id), None)
            if instance:
                st.success("Instance found in Instance.json.")
                win_instance = instance
            else:
                st.info("Instance not found in Instance.json. Will fetch from AWS if you click below.")
                if st.button("Fetch from AWS"):
                    details = get_instance_details_from_aws(instance_id, windows_config["aws_region"], windows_config.get("key_file"))
                    if details:
                        update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                        st.success("Fetched and saved instance details from AWS.")
                        win_instance = details
                    else:
                        st.error("Failed to fetch instance details from AWS.")
    else:
        instance_name = st.text_input("Enter a name for the new Windows instance:", value=windows_config.get("instance_name", ""))
        if st.button("Create New Instance"):
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
                }
                if "windows" in windows_config["type"]:
                    ec2 = boto3.client("ec2", region_name=windows_config["aws_region"])
                    password = get_windows_password(ec2, instance_id, windows_config["key_file"], initial_wait=240)
                    details["Password"] = password
                    details["Username"] = "Administrator"
                update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                st.success("New instance created and saved.")
                win_instance = details
            else:
                st.error("Failed to create new instance.")
    # Only proceed if win_instance is valid
    if not win_instance or not win_instance.get("Password"):
        st.warning("Please select or create a valid Windows instance to proceed.")
        return
    st.session_state["fw_win_instance"] = win_instance
    st.json(win_instance)

    # --- Step 2: Disable firewall and enable WinRM ---
    if win_instance.get("Password"):
        st.subheader("Step 2: Manual - Disable Firewall & Enable WinRM on Windows")
        show_disable_firewall_and_enable_winrm(win_instance["PublicIpAddress"])
        st.markdown("**RDP Credentials:**")
        st.code(f"Public IP: {win_instance['PublicIpAddress']}\nUsername: {win_instance.get('Username', 'Administrator')}\nPassword: {win_instance['Password']}", language="text")
        if st.button("I have disabled the firewall and enabled WinRM. Continue."):
            st.session_state["fw_precheck_ok"] = True
        if not st.session_state.get("fw_precheck_ok"):
            return
    else:
        st.warning("Instance does not have a password. Please ensure the instance is fully initialized.")
        return

    # --- Check internet connectivity on Windows ---
    st.subheader("Step 3: Check Internet Connectivity (Windows)")
    if st.button("Check Connectivity (Windows)", disabled=st.session_state["fw_step_running"]):
        try:
            check_internet_connectivity(
                win_instance["PublicIpAddress"],
                win_instance["Username"],
                win_instance["Password"]
            )
            st.session_state["fw_win_connectivity"] = True
            st.success("Windows instance has internet connectivity.")
        except Exception as e:
            st.error(f"Error: {e}")
            return
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
    reuse_linux = st.radio("Do you want to reuse an existing Linux instance?", ["Yes", "No"])
    linux_instance = None
    if reuse_linux == "Yes":
        linux_instance_id = st.text_input("Enter Linux Instance ID to reuse:")
        if linux_instance_id:
            instances = load_instance_file()
            instance = next((i for i in instances if i["InstanceId"] == linux_instance_id), None)
            if instance:
                st.success("Instance found in Instance.json.")
                linux_instance = instance
            else:
                st.info("Instance not found in Instance.json. Will fetch from AWS if you click below.")
                if st.button("Fetch from AWS (Linux)"):
                    details = get_instance_details_from_aws(linux_instance_id, linux_config["aws_region"], linux_config.get("key_file"))
                    if details:
                        update_instance_in_json(linux_instance_id, details, INSTANCE_JSON_FILE)
                        st.success("Fetched and saved Linux instance details from AWS.")
                        linux_instance = details
                    else:
                        st.error("Failed to fetch instance details from AWS.")
    else:
        if st.button("Create Linux Instance"):
            instance_id, public_ip, private_ip = create_instance(linux_config)
            if instance_id:
                disable_source_destination_check(instance_id)
                details = {
                    "InstanceId": instance_id,
                    "PublicIpAddress": public_ip,
                    "PrivateIpAddress": private_ip,
                    "InstanceType": linux_config["instance_type"],
                    "Username": linux_config.get("username", "ubuntu")
                }
                update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                st.success("Linux instance created and saved. Waiting 4 minutes for initialization...")
                import time
                with st.spinner("Waiting for Ubuntu instance to initialize (4 minutes)..."):
                    time.sleep(240)
                linux_instance = details
            else:
                st.error("Failed to create Linux instance.")
    # Only proceed if linux_instance is valid
    if not linux_instance or not linux_instance.get("InstanceId") or not linux_instance.get("PublicIpAddress"):
        st.warning("Please select or create a valid Linux instance to proceed.")
        return
    st.session_state["fw_linux_instance"] = linux_instance
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
                    if "0% packet loss" in output:
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

    # Final step: All done
    if all([
        st.session_state.get("firewall_precheck_ok"),
        st.session_state.get("firewall_internet_ok"),
        st.session_state.get("firewall_task_ok")
    ]):
        st.success("Firewall workflow completed successfully!")
        st.balloons()

