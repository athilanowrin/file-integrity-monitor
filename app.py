import os
import hashlib
import json
from datetime import datetime

MONITORED_FOLDER = "monitored_files"
BASELINE_FILE = "baseline.json"
LOG_FILE = os.path.join("logs", "security.log")


def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while True:
                data = file.read(4096)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except (PermissionError, OSError) as error:
        print(f"Could not read {file_path}: {error}")
        return None


def scan_files():
    """Scan all files inside the monitored folder."""
    file_hashes = {}

    for root, _, files in os.walk(MONITORED_FOLDER):

        for filename in files:
            file_path = os.path.join(root, filename)

            file_hash = calculate_hash(file_path)

            if file_hash:
                file_hashes[file_path] = file_hash

    return file_hashes


def log_event(event_type, file_path):
    """Save security events to the log file."""

    os.makedirs("logs", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    message = f"[{timestamp}] {event_type}: {file_path}"

    with open(LOG_FILE, "a") as log:
        log.write(message + "\n")

    print(message)


def create_baseline():
    """Create the initial trusted file baseline."""

    file_hashes = scan_files()

    baseline_data = {
        "created_at": datetime.now().isoformat(),
        "files": file_hashes
    }

    with open(BASELINE_FILE, "w") as file:
        json.dump(baseline_data, file, indent=4)

    print("\nBaseline created successfully!")
    print(f"Files recorded: {len(file_hashes)}")


def load_baseline():
    """Load the existing baseline."""

    if not os.path.exists(BASELINE_FILE):
        print("Baseline does not exist.")
        return None

    with open(BASELINE_FILE, "r") as file:
        return json.load(file)


def check_integrity():
    """Compare current files with the trusted baseline."""

    baseline_data = load_baseline()

    if baseline_data is None:
        return

    old_files = baseline_data["files"]
    current_files = scan_files()

    print("\n=== Integrity Check ===")

    # Check for new and modified files
    for file_path, current_hash in current_files.items():

        if file_path not in old_files:
            print(f"[NEW FILE] {file_path}")
            log_event("NEW FILE", file_path)

        elif old_files[file_path] != current_hash:
            print(f"[MODIFIED] {file_path}")
            log_event("MODIFIED", file_path)

    # Check for deleted files
    for file_path in old_files:

        if file_path not in current_files:
            print(f"[DELETED] {file_path}")
            log_event("DELETED", file_path)

    print("\nIntegrity check completed.")


if __name__ == "__main__":

    os.makedirs(MONITORED_FOLDER, exist_ok=True)

    print("=== File Integrity Monitoring System ===")
    print("1. Create Baseline")
    print("2. Check Integrity")
    print("3. Exit")

    choice = input("\nEnter your choice: ")

    if choice == "1":
        create_baseline()

    elif choice == "2":
        check_integrity()

    elif choice == "3":
        print("Exiting...")

    else:
        print("Invalid choice.")