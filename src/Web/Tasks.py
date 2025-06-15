import logging
import json
import winrm

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def load_config(file_path, instance_type):
    """Load configuration from Config.json."""
    try:
        with open(file_path, 'r') as file:
            configs = json.load(file)
            for config in configs:
                if config["type"].lower() == instance_type.lower():
                    return config
            logging.error(f"Configuration for instance type '{instance_type}' not found.")
            return None
    except FileNotFoundError:
        logging.error(f"Configuration file '{file_path}' not found.")
        exit(1)
    except json.JSONDecodeError:
        logging.error(f"Configuration file '{file_path}' contains invalid JSON.")
        exit(1)

def load_instance_details(instance_id=None):
    """
    Load instance details from Instance.json. If instance_id is provided, return details of that instance.
    Otherwise, return all instances.
    """
    try:
        with open("Instance.json", "r") as file:  # Adjust the relative path if necessary
            instances = json.load(file)

            # If instance_id is provided, return the specific instance
            if instance_id:
                for instance in instances:
                    if instance["InstanceId"] == instance_id:
                        return instance
                logging.error(f"Instance ID {instance_id} not found in Instance.json.")
                return None

            # If no instance_id is provided, return all instances
            return instances
    except FileNotFoundError:
        logging.warning("Instance.json file not found. Returning an empty list.")
        return []  # Return an empty list if file is missing
    except json.JSONDecodeError:
        logging.error("Instance.json contains invalid JSON. Returning an empty list.")
        return []  # Return an empty list if JSON is invalid


def configure_proxy(host, username, password, pac_file):
    """
    Configures the Windows instance to use a PAC file for proxy settings via Automatic Proxy Setup.
    """
    if not pac_file:
        logging.error("PAC file URL is missing. Cannot configure proxy.")
        return

    try:
        logging.info(f"Configuring proxy on Windows instance at {host} using PAC file: {pac_file}")

        # Create a WinRM session
        session = winrm.Session(f'http://{host}:5985/wsman', auth=(username, password), transport='basic', server_cert_validation='ignore')

        # PowerShell command to configure proxy using Automatic Proxy Setup
        command = f"""
        Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" -Name AutoConfigURL -Value "{pac_file}"
        Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" -Name ProxyEnable -Value 0
        """
        
        result = session.run_ps(command)

        # Log the output
        logging.info(result.std_out.decode())
        if result.std_err:
            logging.warning(f"Error: {result.std_err.decode()}")

        logging.info("Proxy configuration completed successfully.")
    except winrm.exceptions.InvalidCredentialsError:
        logging.error("Invalid credentials. Please verify the username and password.")
    except winrm.exceptions.WinRMTransportError:
        logging.error("WinRM transport error. Ensure WinRM is enabled and configured on the instance.")
    except Exception as e:
        logging.error(f"An error occurred while configuring the proxy: {e}")


def install_firefox(host, username, password):
    """
    Installs Mozilla Firefox on the Windows instance.
    """
    try:
        logging.info(f"Installing Mozilla Firefox on Windows instance at {host}...")

        # Create a WinRM session
        session = winrm.Session(f'http://{host}:5985/wsman', auth=(username, password), transport='basic', server_cert_validation='ignore')

        # PowerShell script to install Firefox
        powershell_script = """
        # Define variables
        $firefoxInstallerUrl = "https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-US"
        $installerPath = "$env:USERPROFILE\\Downloads\\FirefoxInstaller.exe"

        # Download the Firefox installer
        Invoke-WebRequest -Uri $firefoxInstallerUrl -OutFile $installerPath

        # Run the installer silently
        Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait

        # Cleanup: Remove the installer after installation
        Remove-Item -Path $installerPath -Force

        Write-Host "Mozilla Firefox has been installed successfully."
        """

        # Execute the PowerShell script
        result = session.run_ps(powershell_script)

        # Log the output
        logging.info(result.std_out.decode())
        if result.std_err:
            logging.warning(f"Error: {result.std_err.decode()}")

        logging.info("Mozilla Firefox installation completed successfully.")
    except winrm.exceptions.InvalidCredentialsError:
        logging.error("Invalid credentials. Please verify the username and password.")
    except winrm.exceptions.WinRMTransportError:
        logging.error("WinRM transport error. Ensure WinRM is enabled and configured on the instance.")
    except Exception as e:
        logging.error(f"An error occurred while installing Firefox: {e}")


def configure_firefox_proxy(host, username, password, proxy_url):
    """
    Ensures Manual Proxy Configuration is selected in Mozilla Firefox and updates the proxy settings.
    """
    if not proxy_url:
        logging.error("Proxy URL is missing. Cannot configure Firefox proxy settings.")
        return

    try:
        logging.info(f"Enabling Manual Proxy Configuration in Firefox on Windows instance at {host} with proxy URL: {proxy_url}")

        # Create a WinRM session
        session = winrm.Session(f'http://{host}:5985/wsman', auth=(username, password), transport='basic', server_cert_validation='ignore')

        # PowerShell script to enable manual proxy configuration
        powershell_script = f"""
        # Define the proxy URL and ports
        $proxyUrl = "{proxy_url}"
        $httpPort = 80
        $httpsPort = 443

        # Locate the Firefox profile directory
        $firefoxProfilesPath = "$env:APPDATA\\Mozilla\\Firefox\\Profiles"
        $profileDirectory = Get-ChildItem -Path $firefoxProfilesPath -Directory | Select-Object -First 1

        if ($profileDirectory) {{
            $userJsPath = Join-Path $profileDirectory.FullName "user.js"

            # Create or overwrite the user.js file with the proxy settings
            $proxySettings = @"
user_pref("network.proxy.type", 1); // Enable manual proxy configuration
user_pref("network.proxy.http", "$proxyUrl");
user_pref("network.proxy.http_port", $httpPort);
user_pref("network.proxy.ssl", "$proxyUrl");
user_pref("network.proxy.ssl_port", $httpsPort);
user_pref("network.proxy.no_proxies_on", "localhost, 127.0.0.1");
"@

            Set-Content -Path $userJsPath -Value $proxySettings -Force
            Write-Host "Manual Proxy Configuration has been enabled in Firefox."
        }} else {{
            Write-Host "Firefox profile directory not found. Ensure Firefox is installed and launched at least once."
        }}
        """

        # Execute the PowerShell script
        result = session.run_ps(powershell_script)

        # Log the output
        logging.info(result.std_out.decode())
        if result.std_err:
            logging.warning(f"Error: {result.std_err.decode()}")

        logging.info("Manual Proxy Configuration has been enabled in Firefox successfully.")
    except winrm.exceptions.InvalidCredentialsError:
        logging.error("Invalid credentials. Please verify the username and password.")
    except winrm.exceptions.WinRMTransportError:
        logging.error("WinRM transport error. Ensure WinRM is enabled and configured on the instance.")
    except Exception as e:
        logging.error(f"An error occurred while enabling Manual Proxy Configuration in Firefox: {e}")


def launch_and_close_firefox(host, username, password):
    """
    Launches and closes Mozilla Firefox on the Windows instance.
    """
    try:
        logging.info(f"Launching and closing Mozilla Firefox on Windows instance at {host}...")

        # Create a WinRM session
        session = winrm.Session(f'http://{host}:5985/wsman', auth=(username, password), transport='basic', server_cert_validation='ignore')

        # PowerShell script to launch and close Firefox
        powershell_script = """
        # Launch Mozilla Firefox
        Start-Process -FilePath "C:\\Program Files\\Mozilla Firefox\\firefox.exe"

        # Wait for 5 seconds
        Start-Sleep -Seconds 5

        # Close Mozilla Firefox
        Stop-Process -Name "firefox" -Force

        Write-Host "Mozilla Firefox was launched and closed successfully."
        """

        # Execute the PowerShell script
        result = session.run_ps(powershell_script)

        # Log the output
        logging.info(result.std_out.decode())
        if result.std_err:
            logging.warning(f"Error: {result.std_err.decode()}")

        logging.info("Mozilla Firefox was launched and closed successfully.")
    except winrm.exceptions.InvalidCredentialsError:
        logging.error("Invalid credentials. Please verify the username and password.")
    except winrm.exceptions.WinRMTransportError:
        logging.error("WinRM transport error. Ensure WinRM is enabled and configured on the instance.")
    except Exception as e:
        logging.error(f"An error occurred while launching and closing Firefox: {e}")