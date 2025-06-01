import subprocess
import re
import webbrowser

def sl_login():
    """
    Automate the `sl login` process:
    1. Execute `sl login` to authenticate the user.
    2. No additional processing is done here.
    """
    try:
        # Run the `sl login` command
        print("Executing `sl login` command...")
        result = subprocess.run(['sl', 'login'], capture_output=True, text=True)

        # Check if the command was successful
        if result.returncode != 0:
            print(f"Error executing `sl login`: {result.stderr}")
            return False

        print("Authentication completed successfully.")
        return True

    except Exception as e:
        print(f"An error occurred during the `sl login` process: {e}")
        return False


def generate_aws_session(role_name, account_id, profile):
    """
    Generate the AWS session URL using `sl aws session generate`.
    1. Execute the command with the provided role, account ID, and profile.
    2. Extract the AWS session URL and open it in the browser.
    """
    try:
        # Step 1: Run the `sl aws session generate` command
        print(f"Generating AWS session for role {role_name} and account {account_id}...")
        result = subprocess.run(
            [
                'sl', 'aws', 'session', 'generate',
                '--role-name', role_name,
                '--account-id', account_id,
                '--profile', profile
            ],
            capture_output=True,
            text=True
        )

        # Check if the command was successful
        if result.returncode != 0:
            print(f"Error generating AWS session: {result.stderr}")
            return False

        # Step 2: Extract the AWS session URL from the command output
        session_output = result.stdout
        print("Output from `sl aws session generate`:\n", session_output)  # Debugging: Display raw output

        # Use regex to find the URL (assuming it starts with http or https)
        url_match = re.search(r'(https?://[^\s]+)', session_output)
        if not url_match:
            print("AWS session URL not found in the output.")
            return False

        aws_url = url_match.group(0)
        print(f"AWS Session URL: {aws_url}")

        # Step 3: Open the AWS session URL in the default web browser
        print("Opening the AWS session URL in your default browser...")
        webbrowser.open(aws_url)

        # Step 4: Wait for the user to complete the AWS login process
        input("Please complete the AWS session login in your browser and press Enter to continue...")

        print("AWS session assumed successfully.")
        return True

    except Exception as e:
        print(f"An error occurred during the AWS session generation process: {e}")
        return False