import streamlit as st
from src.utils import (
    load_config,
    load_instance_file,
    save_instance_file,
    create_instance,
    get_windows_password,
    disable_source_destination_check,
    INSTANCE_JSON_FILE,
    check_internet_connectivity,
    get_instance_details_from_aws,
    show_disable_firewall_and_enable_winrm
)
import boto3
from src.ZTNAClientbased.Tasks import execute_ztna_clientbased_tasks

def update_instance_in_json(instance_id, updated_details, instance_file):
    instances = load_instance_file()
    for instance in instances:
        if instance["InstanceId"] == instance_id:
            instance.update(updated_details)
            break
    else:
        instances.append(updated_details)
    save_instance_file(instances)

def execute_ztna_clientbased_workflow():
    config = load_config("Config.json")
    if not config:
        st.error("Config.json is empty. Please provide AWS parameters and update Config.json.")
        return
    ztna_config = next((c for c in config if c["type"] == "windows-ztna-client"), None)
    if not ztna_config:
        st.error("No ZTNA Clientbased config found in Config.json.")
        return

    # --- Step 1: Instance Management ---
    instance_details = st.session_state.get("ztna_clientbased_instance_details")
    if not instance_details:
        st.subheader("Step 1: Instance Management")
        reuse = st.radio("Do you want to reuse an existing instance for ZTNA Clientbased?", ["Yes", "No"])
        if reuse == "Yes":
            instance_id = st.text_input("Enter the Instance ID to reuse:")
            if instance_id:
                instances = load_instance_file()
                instance = next((i for i in instances if i["InstanceId"] == instance_id), None)
                if instance:
                    st.success("Instance found in Instance.json.")
                    st.json(instance)
                    st.session_state["ztna_clientbased_instance_details"] = instance
                    st.rerun()
                else:
                    st.info("Instance not found in Instance.json. Will fetch from AWS if you click below.")
                    if st.button("Fetch from AWS"):
                        details = get_instance_details_from_aws(instance_id, ztna_config["aws_region"], ztna_config.get("key_file"))
                        if details:
                            update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                            st.success("Fetched and saved instance details from AWS.")
                            st.json(details)
                            st.session_state["ztna_clientbased_instance_details"] = details
                            st.rerun()
                        else:
                            st.error("Failed to fetch instance details from AWS.")
        else:
            # Prompt for instance name before creating
            default_name = ztna_config.get("instance_name", "ztna-client-instance")
            instance_name = st.text_input("Enter a name for the new instance:", value=default_name)
            if st.button("Create New Instance"):
                # Update config with user-provided instance name
                ztna_config_with_name = dict(ztna_config)
                ztna_config_with_name["instance_name"] = instance_name
                instance_id, public_ip, private_ip = create_instance(ztna_config_with_name)
                if instance_id:
                    disable_source_destination_check(instance_id)
                    details = {
                        "InstanceId": instance_id,
                        "PublicIpAddress": public_ip,
                        "PrivateIpAddress": private_ip,
                        "InstanceType": ztna_config["instance_type"],
                        "InstanceName": instance_name
                    }
                    if "windows" in ztna_config["type"]:
                        ec2 = boto3.client("ec2", region_name=ztna_config["aws_region"])
                        password = get_windows_password(ec2, instance_id, ztna_config["key_file"], initial_wait=240)
                        details["Password"] = password
                        details["Username"] = "Administrator"
                    update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                    st.success("New instance created and saved.")
                    st.json(details)
                    st.session_state["ztna_clientbased_instance_details"] = details
                    st.rerun()
                else:
                    st.error("Failed to create new instance.")
        return  # Do not proceed until instance is set

    # --- After instance is set, show next steps ---
    st.success(f"Using instance: {instance_details['InstanceId']}")
    st.json(instance_details)
    if st.button("Reset Instance Selection"):
        del st.session_state["ztna_clientbased_instance_details"]
        # Also clear all step session state for a clean restart
        for k in [
            "ztna_clientbased_precheck_ok", "ztna_clientbased_internet_ok", "ztna_cb_ssh_ok", "ztna_cb_zip_ok", "ztna_cb_unzip_ok", "ztna_cb_modules_ok", "ztna_cb_hosts_ok", "ztna_cb_files_ok"
        ]:
            if k in st.session_state:
                del st.session_state[k]
        st.rerun()

    # Step 2: Disable firewall and enable WinRM
    if instance_details and instance_details.get("Password"):
        st.subheader("Step 2: Manual - Disable Firewall & Enable WinRM on Windows")
        show_disable_firewall_and_enable_winrm(instance_details["PublicIpAddress"])
        st.markdown("**RDP Credentials:**")
        st.code(f"Public IP: {instance_details['PublicIpAddress']}\nUsername: {instance_details.get('Username', 'Administrator')}\nPassword: {instance_details['Password']}", language="text")
        if st.button("I have disabled the firewall and enabled WinRM. Continue."):
            st.session_state["ztna_clientbased_precheck_ok"] = True
        if not st.session_state.get("ztna_clientbased_precheck_ok"):
            return
    elif instance_details:
        st.session_state["ztna_clientbased_precheck_ok"] = True  # Linux, skip

    # Step 3: Check Internet Connectivity
    st.subheader("Step 3: Check Internet Connectivity")
    if st.button("Check Connectivity"):
        try:
            check_internet_connectivity(
                instance_details["PublicIpAddress"],
                instance_details.get("Username", "Administrator"),
                instance_details["Password"]
            )
            st.success("Internet connectivity check completed successfully.")
            st.session_state["ztna_clientbased_internet_ok"] = True
        except Exception as e:
            st.error(f"Error: {e}")
            return
    if not st.session_state.get("ztna_clientbased_internet_ok"):
        return

    # --- Modular Step-by-Step Orchestration ---
    st.subheader("Step 4: ZTNA Clientbased Orchestration (Modular)")
    st.markdown("""
**This workflow will perform the following steps:**
1. Set up SSH server on Windows
2. Transfer Cisco Secure Client ZIP
3. Unzip Cisco Secure Client ZIP
4. Install ZTNA modules (Core VPN, DART, ZTA)
5. Replace hosts file
6. Copy additional files (cert, enrollment)
        """)
    # Step 4.1: Set up SSH server
    btn_ssh_disabled = bool(st.session_state.get("ztna_cb_ssh_ok", False))
    if st.button("Step 4.1: Set up SSH server on Windows", disabled=btn_ssh_disabled):
        from src.ZTNAClientbased.Tasks import setup_ssh_server
        try:
            ok = setup_ssh_server(
                instance_details["PublicIpAddress"],
                instance_details["Username"],
                instance_details["Password"]
            )
            if ok:
                st.success("SSH server set up successfully.")
                st.session_state["ztna_cb_ssh_ok"] = True
            else:
                st.error("Failed to set up SSH server.")
        except Exception as e:
            st.error(f"Error: {e}")
    if not st.session_state.get("ztna_cb_ssh_ok"):
        return

    # Step 4.2: Transfer Cisco Secure Client ZIP
    btn_zip_disabled = bool(st.session_state.get("ztna_cb_zip_ok", False))
    if st.button("Step 4.2: Transfer Cisco Secure Client ZIP", disabled=btn_zip_disabled):
        from src.ZTNAClientbased.Tasks import transfer_file_with_paramiko, ZIP_FILE, REMOTE_ZIP_PATH
        try:
            ok = transfer_file_with_paramiko(
                instance_details["Password"], ZIP_FILE, instance_details["Username"],
                instance_details["PublicIpAddress"], REMOTE_ZIP_PATH
            )
            if ok:
                st.success("ZIP file transferred successfully.")
                st.session_state["ztna_cb_zip_ok"] = True
            else:
                st.error("Failed to transfer ZIP file.")
        except Exception as e:
            st.error(f"Error: {e}")
    if not st.session_state.get("ztna_cb_zip_ok"):
        return

    # Step 4.3: Unzip Cisco Secure Client ZIP
    btn_unzip_disabled = bool(st.session_state.get("ztna_cb_unzip_ok", False))
    if st.button("Step 4.3: Unzip Cisco Secure Client ZIP", disabled=btn_unzip_disabled):
        from src.ZTNAClientbased.Tasks import unzip_file_ssh, REMOTE_ZIP_PATH, REMOTE_UNZIP_DIR
        try:
            ok = unzip_file_ssh(
                instance_details["PublicIpAddress"],
                instance_details["Username"],
                ztna_config["key_file"],
                REMOTE_ZIP_PATH, REMOTE_UNZIP_DIR
            )
            if ok:
                st.success("ZIP file unzipped successfully.")
                st.session_state["ztna_cb_unzip_ok"] = True
            else:
                st.error("Failed to unzip ZIP file.")
        except Exception as e:
            st.error(f"Error: {e}")
    if not st.session_state.get("ztna_cb_unzip_ok"):
        return

    # Step 4.4: Install ZTNA modules
    btn_modules_disabled = bool(st.session_state.get("ztna_cb_modules_ok", False))
    if st.button("Step 4.4: Install ZTNA modules (Core VPN, DART, ZTA)", disabled=btn_modules_disabled):
        from src.ZTNAClientbased.Tasks import create_winrm_session, find_installer, install_msi, REMOTE_UNZIP_DIR
        try:
            session = create_winrm_session(
                instance_details["PublicIpAddress"],
                instance_details["Username"],
                instance_details["Password"]
            )
            modules = [
                {"name": "Core VPN", "keyword": "core-vpn", "log_file": "C:/Users/Administrator/core-install.log"},
                {"name": "DART", "keyword": "dart", "log_file": "C:/Users/Administrator/dart-install.log"},
                {"name": "ZTA", "keyword": "zta", "log_file": "C:/Users/Administrator/zta-install.log"},
            ]
            logs = ""
            for module in modules:
                st.write(f"Processing module: {module['name']}")
                installer_path = find_installer(session, REMOTE_UNZIP_DIR, module["keyword"])
                if not installer_path:
                    logs += f"No installer found for {module['name']}\n"
                    continue
                ok = install_msi(session, installer_path, module["log_file"])
                if ok:
                    logs += f"Installed {module['name']} successfully.\n"
                else:
                    logs += f"Failed to install {module['name']}.\n"
            st.text_area("Module Install Logs", logs, height=150)
            st.session_state["ztna_cb_modules_ok"] = True
        except Exception as e:
            st.error(f"Error: {e}")
    if not st.session_state.get("ztna_cb_modules_ok"):
        return

    # Step 4.5: Replace hosts file
    btn_hosts_disabled = bool(st.session_state.get("ztna_cb_hosts_ok", False))
    if st.button("Step 4.5: Replace hosts file", disabled=btn_hosts_disabled):
        from src.ZTNAClientbased.Tasks import replace_hosts_file, HOSTS_FILE
        try:
            ok = replace_hosts_file(
                instance_details["PublicIpAddress"],
                instance_details["Username"],
                instance_details["Password"],
                ztna_config.get("org_id", ""),
                HOSTS_FILE,
                "C:\\Windows\\System32\\drivers\\etc\\hosts"
            )
            if ok:
                st.success("Hosts file replaced successfully.")
                st.session_state["ztna_cb_hosts_ok"] = True
            else:
                st.error("Failed to replace hosts file.")
        except Exception as e:
            st.error(f"Error: {e}")
    if not st.session_state.get("ztna_cb_hosts_ok"):
        return

    # Step 4.6: Copy additional files
    btn_files_disabled = bool(st.session_state.get("ztna_cb_files_ok", False))
    if st.button("Step 4.6: Copy additional files (cert, enrollment)", disabled=btn_files_disabled):
        from src.ZTNAClientbased.Tasks import copy_additional_files_paramiko, CERT_FILE, ENROLLMENT_FILE, REMOTE_CACERTS_DIR, REMOTE_ENROLLMENT_DIR
        try:
            ok = copy_additional_files_paramiko(
                instance_details["PublicIpAddress"],
                instance_details["Username"],
                ztna_config["key_file"],
                CERT_FILE, ENROLLMENT_FILE, REMOTE_CACERTS_DIR, REMOTE_ENROLLMENT_DIR
            )
            if ok:
                st.success("Additional files copied successfully.")
                st.session_state["ztna_cb_files_ok"] = True
            else:
                st.error("Failed to copy additional files.")
        except Exception as e:
            st.error(f"Error: {e}")
    if not st.session_state.get("ztna_cb_files_ok"):
        return

    # Final step: All done
    st.success("ZTNA Clientbased workflow completed successfully!")
    st.balloons()
    # --- Manual Steps Section ---
    st.subheader("Manual Steps – Complete ZTNA Clientbased Setup")
    st.markdown("""
1. **Whitelist this instance by raising a ticket.**
2. **After whitelisting, enroll into ZTA.**
3. **Have the same setup for firewall ready.**  
   If not, generate it using the provided script.
4. **Create an access policy to access the Windows client using the ZTA machine.**

For more details, follow the [Confluence page](https://confluence-eng-rtp2.cisco.com/conf/display/PROD/ZTNA-Clientbased+%28CLAP%29+events+generation+in+INT+environment?src=contextnavpagetreemode).
""")
