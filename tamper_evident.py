import hashlib
import hmac
import json
import time
import os

class TamperEvidentLogger:
    # A simple tamper-evident logging system using hashes and HMAC.
    def __init__(self, log_file="secure_logs.json", secret_key=None):
        self.log_file = log_file
        if secret_key:
            self.secret_key = secret_key
        else:
            # Default secret key if none provided
            self.secret_key = os.getenv("TAMPER_SECRET_KEY", "super_secret_key").encode()

    def _generate_hash(self, data):
        # Generates a SHA-256 hash
        return hashlib.sha256(data.encode()).hexdigest()

    def _generate_hmac(self, data):
        # Generates an HMAC using the secret key
        return hmac.new(self.secret_key, data.encode(), hashlib.sha256).hexdigest()

    def load_logs(self):
        # Load logs from the JSON file
        if not os.path.exists(self.log_file):
            return []
        
        try:
            with open(self.log_file, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading logs: {e}")
            return []

    def save_logs(self, logs):
        # Save logs to the JSON file
        try:
            with open(self.log_file, "w") as f:
                json.dump(logs, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving logs: {e}")
            return False

    def add_log(self, event_type, description):
        # Add a new log entry
        logs = self.load_logs()

        timestamp = str(time.time())
        log_index = len(logs)
        
        # Get previous hash or use 0 for the first log
        if logs:
            previous_hash = logs[-1]["hash"]
        else:
            previous_hash = "0"

        # Combine data to create hash and hmac
        data = f"{log_index}|{timestamp}|{event_type}|{description}|{previous_hash}"
        current_hash = self._generate_hash(data)
        current_hmac = self._generate_hmac(data)

        log_entry = {
            "index": log_index,
            "timestamp": timestamp,
            "event_type": event_type,
            "description": description,
            "previous_hash": previous_hash,
            "hash": current_hash,
            "hmac": current_hmac
        }

        logs.append(log_entry)
        if self.save_logs(logs):
            print("Log added securely")

    def verify_logs(self):
        # Verify if any logs have been tampered with
        logs = self.load_logs()
        if not logs:
            print("No logs found")
            return True
            
        tampered_indices = []
        
        for i, log in enumerate(logs):
            if i > 0:
                previous_hash = logs[i - 1]["hash"]
            else:
                previous_hash = "0"
                
            data = f"{log['index']}|{log['timestamp']}|{log['event_type']}|{log['description']}|{previous_hash}"
            recalculated_hash = self._generate_hash(data)
            recalculated_hmac = self._generate_hmac(data)
            
            # Check for tampering
            if log["index"] != i:
                tampered_indices.append((i, "Reordering"))
            if log["previous_hash"] != previous_hash:
                tampered_indices.append((i, "Chain Break"))
            if log["hash"] != recalculated_hash:
                tampered_indices.append((i, "Data Tampering"))
            if log["hmac"] != recalculated_hmac:
                tampered_indices.append((i, "HMAC Failure"))
                
        if tampered_indices:
            print("Tampering detected:")
            for idx, reason in tampered_indices:
                print(f" - Log {idx}: {reason}")
            return False
            
        print("All logs are verified and intact")
        return True


class TamperSimulator:
    # Simulates tampering with logs for testing
    def __init__(self, logger):
        self.logger = logger

    def modify(self, index, new_description):
        logs = self.logger.load_logs()
        if index >= len(logs) or index < 0:
            print("Invalid index")
            return

        print(f"BEFORE: {logs[index]['description']}")
        logs[index]["description"] = new_description
        print(f"AFTER: {logs[index]['description']}")
        
        self.logger.save_logs(logs)
        print("Log modified")

    def delete(self, index):
        logs = self.logger.load_logs()
        if index >= len(logs) or index < 0:
            print("Invalid index")
            return

        logs.pop(index)
        self.logger.save_logs(logs)
        print("Log deleted")

    def reorder(self):
        logs = self.logger.load_logs()
        if len(logs) < 2:
            print("Not enough logs to reorder")
            return

        logs[0], logs[1] = logs[1], logs[0]
        self.logger.save_logs(logs)
        print("Logs reordered")


def view_logs(logger):
    # Print all logs
    logs = logger.load_logs()
    if not logs:
        print("No logs available")
        return

    for log in logs:
        print("----------------------")
        for key, value in log.items():
            print(f"{key}: {value}")
    print("----------------------")


def menu():
    # Simple CLI menu
    logger = TamperEvidentLogger()
    simulator = TamperSimulator(logger)

    while True:
        print("\n--- Tamper Evident Logging System ---")
        print("1. Add Log")
        print("2. View Logs")
        print("3. Verify Logs")
        print("4. Tamper: Modify Log")
        print("5. Tamper: Delete Log")
        print("6. Tamper: Reorder Logs")
        print("7. Exit")
        print("8. Reset Logs")

        choice = input("Enter choice: ")

        if choice == "1":
            event = input("Enter event type: ")
            desc = input("Enter description: ")
            logger.add_log(event, desc)
        elif choice == "2":
            view_logs(logger)
        elif choice == "3":
            logger.verify_logs()
        elif choice == "4":
            try:
                idx = int(input("Enter log index to modify: "))
                new_desc = input("Enter new description: ")
                simulator.modify(idx, new_desc)
            except ValueError:
                print("Invalid input")
        elif choice == "5":
            try:
                idx = int(input("Enter log index to delete: "))
                simulator.delete(idx)
            except ValueError:
                print("Invalid input")
        elif choice == "6":
            simulator.reorder()
        elif choice == "7":
            print("Exiting...")
            break
        elif choice == "8":
            logger.save_logs([])
            print("Logs reset")
        else:
            print("Invalid choice")


if __name__ == "__main__":
    menu()