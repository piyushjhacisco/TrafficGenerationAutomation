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
from src.ZTNAClientless.Tasks import execute_ztna_clientless_tasks

def update_instance_in_json(instance_id, updated_details, instance_file):
    instances = load_instance_file()
    for instance in instances:
        if instance["InstanceId"] == instance_id:
            instance.update(updated_details)
            break
    else:
        instances.append(updated_details)
    save_instance_file(instances)

def execute_ztna_clientless_workflow():
    st.header("ZTNA Clientless Task Execution")
    config = load_config("Config.json")
    if not config:
        st.error("Config.json is empty. Please provide AWS parameters and update Config.json.")
        return
    # Use the linux config for ZTNA-Clientless
    ztna_clientless_config = next((c for c in config if c["type"] == "linux"), None)
    if not ztna_clientless_config:
        st.error("No Linux config found in Config.json for ZTNA Clientless workflow.")
        return

    # --- Step 1: Instance Management ---
    instance_details = st.session_state.get("ztna_clientless_instance_details")
    if not instance_details:
        st.subheader("Step 1: Instance Management")
        reuse = st.radio("Do you want to reuse an existing instance for ZTNA Clientless?", ["Yes", "No"])
        if reuse == "Yes":
            instance_id = st.text_input("Enter the Instance ID to reuse:")
            if instance_id:
                instances = load_instance_file()
                instance = next((i for i in instances if i["InstanceId"] == instance_id), None)
                if instance:
                    st.success("Instance found in Instance.json.")
                    st.json(instance)
                    st.session_state["ztna_clientless_instance_details"] = instance
                    if instance.get("PublicIpAddress"):
                        show_disable_firewall_and_enable_winrm(instance["PublicIpAddress"])
                    st.rerun()
                else:
                    st.info("Instance not found in Instance.json. Will fetch from AWS if you click below.")
                    if st.button("Fetch from AWS"):
                        details = get_instance_details_from_aws(instance_id, ztna_clientless_config["aws_region"], ztna_clientless_config.get("key_file"))
                        if details:
                            update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                            st.success("Fetched and saved instance details from AWS.")
                            st.json(details)
                            st.session_state["ztna_clientless_instance_details"] = details
                            if details.get("PublicIpAddress"):
                                show_disable_firewall_and_enable_winrm(details["PublicIpAddress"])
                            st.rerun()
                        else:
                            st.error("Failed to fetch instance details from AWS.")
        else:
            # Prompt for instance name before creating
            default_name = ztna_clientless_config.get("instance_name", "ztna-clientless-instance")
            instance_name = st.text_input("Enter a name for the new instance:", value=default_name)
            if st.button("Create New Instance"):
                # Update config with user-provided instance name
                ztna_clientless_config_with_name = dict(ztna_clientless_config)
                ztna_clientless_config_with_name["instance_name"] = instance_name
                instance_id, public_ip, private_ip = create_instance(ztna_clientless_config_with_name)
                if instance_id:
                    disable_source_destination_check(instance_id)
                    details = {
                        "InstanceId": instance_id,
                        "PublicIpAddress": public_ip,
                        "PrivateIpAddress": private_ip,
                        "InstanceType": ztna_clientless_config["instance_type"],
                        "Username": ztna_clientless_config.get("username", "ubuntu"),
                        "InstanceName": instance_name
                    }
                    update_instance_in_json(instance_id, details, INSTANCE_JSON_FILE)
                    st.success("New instance created and saved.")
                    st.json(details)
                    # Show 4-minute initialization wait for Linux
                    import time
                    st.info("Waiting 4 minutes for Linux instance initialization. Please do not proceed until this completes.")
                    with st.empty():
                        for i in range(4*60, 0, -1):
                            mins, secs = divmod(i, 60)
                            st.write(f"\u23f3 Linux instance initializing: {mins:02d}:{secs:02d} remaining...")
                            time.sleep(1)
                    st.success("Linux instance initialization wait complete. You may proceed.")
                    st.session_state["ztna_clientless_instance_details"] = details
                    st.rerun()
                else:
                    st.error("Failed to create new instance.")
        return  # Do not proceed until instance is set

    # --- After instance is set, show next steps ---
    # Patch Username if missing (for backward compatibility or AWS fetch)
    if instance_details and not instance_details.get("Username"):
        instance_details["Username"] = ztna_clientless_config.get("username", "ubuntu")
        update_instance_in_json(instance_details["InstanceId"], instance_details, INSTANCE_JSON_FILE)

    if instance_details and instance_details.get("Password"):
        st.subheader("Step 2: Manual - Disable Firewall & Enable WinRM on Windows")
        show_disable_firewall_and_enable_winrm(instance_details["PublicIpAddress"])
        st.markdown("**RDP Credentials:**")
        st.code(f"Public IP: {instance_details['PublicIpAddress']}\nUsername: {instance_details.get('Username', 'Administrator')}\nPassword: {instance_details['Password']}", language="text")
        if st.button("I have disabled the firewall and enabled WinRM. Continue."):
            st.session_state["ztna_clientless_precheck_ok"] = True
        if not st.session_state.get("ztna_clientless_precheck_ok"):
            return

    st.success(f"Using instance: {instance_details['InstanceId']}")
    st.json(instance_details)
    if st.button("Reset Instance Selection"):
        del st.session_state["ztna_clientless_instance_details"]
        # Also clear all step session state for a clean restart
        for k in [
            "ztna_clientless_internet_ok", "ztna_clientless_nginx_ok", "ztna_clientless_ssl_ok", "ztna_clientless_nginx_https_ok", "ztna_clientless_restart_ok"
        ]:
            if k in st.session_state:
                del st.session_state[k]
        st.rerun()

    # Step 2: Check Internet Connectivity (Linux: SSH ping)
    st.subheader("Step 2: Check Internet Connectivity (Linux)")
    if st.button("Check Connectivity"):
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            private_key = paramiko.RSAKey.from_private_key_file(ztna_clientless_config["key_file"])
            ssh.connect(hostname=instance_details["PublicIpAddress"], username=instance_details["Username"], pkey=private_key, timeout=10)
            # Run ping to 8.8.8.8
            stdin, stdout, stderr = ssh.exec_command("ping -c 4 8.8.8.8")
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            ssh.close()
            st.text_area("Ping Output", output, height=120)
            if error:
                st.text_area("Ping Error", error, height=80)
            if "0% packet loss" in output or "1% packet loss" in output or "2% packet loss" in output or "3% packet loss" in output:
                st.success("Internet connectivity check completed successfully.")
                st.session_state["ztna_clientless_internet_ok"] = True
            else:
                st.error("Connectivity check failed: No/partial packet loss or ping failed.")
                return
        except Exception as e:
            st.error(f"Error: {e}")
            return
    if not st.session_state.get("ztna_clientless_internet_ok"):
        return

    # Step 3: Install Nginx
    st.subheader("Step 3: Install Nginx")
    if st.button("Install Nginx"):
        try:
            from src.ZTNAClientless.Tasks import install_nginx
            install_nginx(
                instance_details["PublicIpAddress"],
                instance_details["Username"],
                ztna_clientless_config["key_file"]
            )
            st.success("Nginx installed successfully.")
            st.session_state["ztna_clientless_nginx_ok"] = True
        except Exception as e:
            st.error(f"Error installing Nginx: {e}")
            return
    if not st.session_state.get("ztna_clientless_nginx_ok"):
        return

    # Step 4: Configure SSL
    st.subheader("Step 4: Configure Self-Signed SSL Certificate")
    if st.button("Configure SSL"):
        try:
            from src.ZTNAClientless.Tasks import configure_ssl
            configure_ssl(
                instance_details["PublicIpAddress"],
                instance_details["Username"],
                ztna_clientless_config["key_file"]
            )
            st.success("Self-signed SSL certificate configured successfully.")
            st.session_state["ztna_clientless_ssl_ok"] = True
        except Exception as e:
            st.error(f"Error configuring SSL: {e}")
            return
    if not st.session_state.get("ztna_clientless_ssl_ok"):
        return

    # Step 5: Configure Nginx for HTTPS
    st.subheader("Step 5: Configure Nginx for HTTPS")
    if st.button("Configure Nginx for HTTPS"):
        try:
            from src.ZTNAClientless.Tasks import configure_nginx_https
            configure_nginx_https(
                instance_details["PublicIpAddress"],
                instance_details["Username"],
                ztna_clientless_config["key_file"]
            )
            st.success("Nginx configured for HTTPS successfully.")
            st.session_state["ztna_clientless_nginx_https_ok"] = True
        except Exception as e:
            st.error(f"Error configuring Nginx for HTTPS: {e}")
            return
    if not st.session_state.get("ztna_clientless_nginx_https_ok"):
        return

    # Step 6: Restart Nginx
    st.subheader("Step 6: Restart Nginx")
    if st.button("Restart Nginx"):
        try:
            from src.ZTNAClientless.Tasks import restart_nginx
            restart_nginx(
                instance_details["PublicIpAddress"],
                instance_details["Username"],
                ztna_clientless_config["key_file"]
            )
            st.success("Nginx restarted successfully.")
            st.session_state["ztna_clientless_restart_ok"] = True
        except Exception as e:
            st.error(f"Error restarting Nginx: {e}")
            return
    if not st.session_state.get("ztna_clientless_restart_ok"):
        return

    # Step 7: Download .crt and .key files
    st.subheader("Step 7: Download SSL Certificate and Key")
    crt_path = "/etc/ssl/certs/self-signed.crt"
    key_path = "/etc/ssl/private/self-signed.key"
    from src.ZTNAClientless.Tasks import fetch_cert_and_key
    crt_data, key_data, fetch_error = fetch_cert_and_key(
        instance_details["PublicIpAddress"],
        instance_details["Username"],
        ztna_clientless_config["key_file"],
        crt_path,
        key_path
    )

    if crt_data is not None:
        st.download_button("Download Certificate (.crt)", crt_data, file_name="self-signed.crt")
    if key_data is not None:
        st.download_button("Download Private Key (.key)", key_data, file_name="self-signed.key")
    if crt_data is None or key_data is None:
        st.warning("Could not fetch certificate or key directly from the instance. Please use the SCP instructions below and upload manually if needed.")
        if fetch_error:
            st.error(f"Fetch error: {fetch_error}")
        st.code(f"scp -i <your-key.pem> ubuntu@{instance_details['PublicIpAddress']}:{crt_path} ./self-signed.crt\nscp -i <your-key.pem> ubuntu@{instance_details['PublicIpAddress']}:{key_path} ./self-signed.key", language="bash")

    # Step 8: Manual Steps – Complete ZTNA Clientless Setup
    st.subheader("Step 8: Manual Steps – Complete ZTNA Clientless Setup")
    st.markdown(f"""
#### Step 1: Register the Instance as a Private Resource in SSE Dashboard
- Go to the SSE Dashboard.
- Navigate to the section for registering a new Private Resource.
- Follow the instructions in the [Confluence Guide](https://confluence-eng-rtp2.cisco.com/conf/display/PROD/ZTNA+Clientless+%28BAP%29+events+generation+in+INT#ZTNAClientless(BAP)eventsgenerationinINT-CreationofPrivateResource).

#### Step 2: Configure Users on Okta and their IDP
- In Okta, add the users who should have access to this resource.
- Ensure their Identity Provider (IDP) is configured as per your organization’s requirements.
- Refer to the same [Confluence Guide](https://confluence-eng-rtp2.cisco.com/conf/display/PROD/ZTNA+Clientless+%28BAP%29+events+generation+in+INT#ZTNAClientless(BAP)eventsgenerationinINT-CreationofPrivateResource) for details.

#### Step 3: Create an Access Policy to Allow User Access
- In the SSE Dashboard, create a new access policy.
- Assign the users and the private resource you registered.
- Set the appropriate permissions to allow access.

---
""")
