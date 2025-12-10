import subprocess
import os

# --- IMPORTANT: VERIFY THIS PATH ---
# This must be the absolute path to your scanner script.
# Run 'pwd' in your project directory and add '/scanner.py' to it.
SCANNER_PATH = '/home/kali-attacker/digital_twin_project/scanner.py'
PYTHON_PATH = '/usr/bin/python3' # This is usually correct. Verify with 'which python3'
TARGET_IP = '192.168.11.0/24' # Use your lab's IP range

print("--- Starting Sudo Test ---")

if not os.path.exists(SCANNER_PATH):
    print(f"ERROR: Scanner script not found at '{SCANNER_PATH}'")
    print("Please correct the SCANNER_PATH variable in this script.")
    exit()

print(f"Attempting to run command:")
print(f"sudo {PYTHON_PATH} {SCANNER_PATH} --target {TARGET_IP}")
print("-" * 20)

try:
    # This is the exact same command your app.py tries to run.
    # We add 'capture_output=True' and 'text=True' to see any errors.
    result = subprocess.run(
        ["sudo", PYTHON_PATH, SCANNER_PATH, "--target", TARGET_IP],
        capture_output=True,
        text=True,
        check=True # This will cause an error if the command fails
    )
    
    print("SUCCESS! The command executed without asking for a password.")
    print("\n--- Scanner Output ---")
    print(result.stdout)

except subprocess.CalledProcessError as e:
    print("ERROR: The command failed.")
    print("\n--- Stderr (Error Message from sudo) ---")
    print(e.stderr)
    print("\nThis failure means your /etc/sudoers rule is incorrect or not working.")
    print("Please double-check your sudoers file using the checklist.")

except FileNotFoundError:
    print(f"ERROR: The command 'sudo' or '{PYTHON_PATH}' was not found.")
    
print("\n--- Sudo Test Finished ---")

