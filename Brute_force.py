import os
import time
import hashlib
import random
import json
from tqdm import tqdm
from multiprocessing import Pool, cpu_count, Manager
from ecdsa import SigningKey, SECP256k1
from colorama import Fore, Style, init

# Initialize colorama
init()

# Constants
PROGRESS_FILE = "progress.json"
SAVE_INTERVAL = 10000  # Save progress every 10000 keys

def load_targets(file_path):
    """Load target addresses from challenge.txt"""
    try:
        with open(file_path, 'r') as file:
            targets = set(line.strip() for line in file if line.strip())
        return targets
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return set()

def save_results(file_path, found_data):
    """Save found addresses and private keys to I_win.txt"""
    try:
        with open(file_path, 'a') as file:
            for address, private_key in found_data:
                file.write(f"Address: {address}, Private Key: {private_key}\n")
    except Exception as e:
        print(f"Error writing to file {file_path}: {e}")

def save_progress(last_key, keys_checked):
    """Save progress to progress.json"""
    progress_data = {
        "last_key": last_key,
        "keys_checked": keys_checked
    }
    try:
        with open(PROGRESS_FILE, 'w') as file:
            json.dump(progress_data, file, indent=4)
        print(f"{Fore.YELLOW}Progress saved: Last Key = {last_key}, Keys Checked = {keys_checked}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error saving progress: {e}{Style.RESET_ALL}")

def load_progress():
    """Load progress from progress.json"""
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE, 'r') as file:
                progress_data = json.load(file)
                return progress_data["last_key"], progress_data["keys_checked"]
        except Exception as e:
            print(f"{Fore.RED}Error loading progress: {e}{Style.RESET_ALL}")
    return None, 0

def generate_private_key(current_hex):
    """Generate the next private key sequentially"""
    start_int = int(current_hex, 16)
    next_int = start_int + 1  # Increment by 1 to cover the key space
    return hex(next_int)[2:].zfill(64)

def derive_address(private_key_hex):
    """Derive a Bitcoin address from a private key"""
    try:
        private_key = bytes.fromhex(private_key_hex)
        sk = SigningKey.from_string(private_key, curve=SECP256k1)
        public_key = sk.verifying_key.to_string()
        public_key_hex = b'\x04' + public_key  # Prefix with 0x04 for uncompressed key

        # Hash the public key
        sha256 = hashlib.sha256(public_key_hex).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()

        # Add network byte and checksum
        network_byte = b'\x00'  # Mainnet
        checksum = hashlib.sha256(hashlib.sha256(network_byte + ripemd160).digest()).digest()[:4]
        address = (network_byte + ripemd160 + checksum).hex()

        return address
    except Exception as e:
        print(f"{Fore.RED}Error deriving address: {e}{Style.RESET_ALL}")
        return None

def brute_force_worker(args):
    """Worker function for multiprocessing"""
    start_hex, end_hex, targets, found_data, progress = args
    current_hex = start_hex
    keys_checked = 0  # Number of keys checked

    while int(current_hex, 16) <= int(end_hex, 16):
        private_key = generate_private_key(current_hex)
        address = derive_address(private_key)
        keys_checked += 1

        # Print progress
        if keys_checked % 1000 == 0:  # Print every 1000 keys
            print(f"{Fore.GREEN}Checked {keys_checked} keys{Style.RESET_ALL}")

        if address and address in targets:
            found_data.append((address, private_key))
            targets.remove(address)  # Remove found address from targets

        current_hex = private_key  # Continue from the last generated key

        # Save progress every SAVE_INTERVAL keys
        if keys_checked % SAVE_INTERVAL == 0:
            save_progress(current_hex, keys_checked)

    return keys_checked

def brute_force(targets, start_hex, end_hex):
    """Brute force algorithm with multiprocessing"""
    manager = Manager()
    shared_targets = manager.list(targets)  # Shared list for targets
    shared_found_data = manager.list()  # Shared list for found data

    num_processes = cpu_count()  # Use all available CPU cores
    range_size = (int(end_hex, 16) - int(start_hex, 16)) // num_processes

    # Prepare arguments for each worker
    args = [
        (hex(int(start_hex, 16) + i * range_size), 
         hex(int(start_hex, 16) + (i + 1) * range_size), 
         shared_targets, shared_found_data, manager.Value('i', 0))
        for i in range(num_processes)
    ]

    # Start multiprocessing
    with Pool(num_processes) as pool:
        with tqdm(total=len(targets), desc="Searching") as pbar:
            while len(shared_targets) > 0:
                pool.map(brute_force_worker, args)
                pbar.update(len(shared_found_data))

    return list(shared_found_data)

if __name__ == '__main__':
    # Load target addresses from challenge.txt
    targets = load_targets('challenge.txt')

    if not targets:
        print("No targets loaded. Exiting.")
    else:
        # Define the starting and ending hex keys
        start_hex = "eccc7dfc52dc86782901058d54fb4024552c48fbd42e4f17e9721775d698f338"
        end_hex = "ef24f3ec61bf180d5d267190850455797bcbbfd5919118035d0d383661824650"

        # Load progress if available
        last_key, keys_checked = load_progress()
        if last_key:
            print(f"{Fore.YELLOW}Resuming from last key: {last_key}{Style.RESET_ALL}")
            start_hex = last_key

        print(f"Starting search from HEX: {start_hex} to HEX: {end_hex}")

        # Run brute force algorithm
        start_time = time.time()
        found_data = brute_force(targets, start_hex, end_hex)
        end_time = time.time()

        # Save results to I_win.txt
        save_results('I_win.txt', found_data)

        print(f"All addresses found! Time Taken: {end_time - start_time:.2f} seconds")
