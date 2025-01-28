import os
import time
import hashlib
import random
from tqdm import tqdm
from multiprocessing import Pool, cpu_count, Manager
from ecdsa import SigningKey, SECP256k1
from colorama import Fore, Style
import datetime

# تهيئة colorama
from colorama import init
init()

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

def generate_private_key(start_hex):
    """Generate a private key starting from a specific hex value with random jumps"""
    start_int = int(start_hex, 16)
    jump = random.randint(1000000, 15000000)  # Random jump between 1 and 5 million
    new_int = start_int + jump
    return hex(new_int)[2:].zfill(64), jump

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
        print(f"Error deriving address: {e}")
        return None

def brute_force_worker(args):
    """Worker function for multiprocessing"""
    start_hex, end_hex, targets, found_data, progress = args
    current_hex = start_hex
    start_time = time.time()  # وقت بدء العملية
    keys_checked = 0  # عدد المفاتيح التي تم فحصها
    while True:
        private_key, jump = generate_private_key(current_hex)
        address = derive_address(private_key)
        keys_checked += 1
        
        # حساب السرعة (مفاتيح في الثانية)
        elapsed_time = time.time() - start_time
        keys_per_second = keys_checked / elapsed_time if elapsed_time > 0 else 0
        
        # طباعة المفتاح والقفز والسرعة
        print(f"{Fore.GREEN}Current Key: {private_key}{Style.RESET_ALL}, "
              f"{Fore.BLUE}Jump: {jump}{Style.RESET_ALL}, "
              f"{Fore.CYAN}Speed: {keys_per_second:.2f} keys/s{Style.RESET_ALL}")
        
        if address and address in targets:
            found_data.append((address, private_key))
            targets.remove(address)  # إزالة العنوان الذي تم العثور عليه
        current_hex = private_key  # الاستمرار من المفتاح الأخير الذي تم إنشاؤه
        if int(current_hex, 16) >= int(end_hex, 16):
            break  # التوقف إذا تجاوزنا end_hex
        progress.value += 1  # تحديث التقدم

def brute_force(targets, start_hex, end_hex):
    """Brute force algorithm with multiprocessing and random jumps"""
    manager = Manager()
    shared_targets = manager.list(targets)  # Shared list for targets
    shared_found_data = manager.list()  # Shared list for found data
    progress = manager.Value('i', 0)  # Shared progress counter

    num_processes = cpu_count()  # Use all available CPU cores

    # Prepare arguments for each worker
    args = [(start_hex, end_hex, shared_targets, shared_found_data, progress) for _ in range(num_processes)]

    # Start multiprocessing
    with Pool(num_processes) as pool:
        with tqdm(total=len(targets), desc="Searching") as pbar:
            while len(shared_targets) > 0:
                pool.map(brute_force_worker, args)
                pbar.update(progress.value)  # Update progress bar
                progress.value = 0  # Reset progress counter

    return list(shared_found_data)

if __name__ == '__main__':
    # Load target addresses from challenge.txt
    targets = load_targets('challenge.txt')

    if not targets:
        print("No targets loaded. Exiting.")
    else:
        # Define the starting and ending hex keys
        start_hex = "b9c27669757b7f281868e3e2eb2c5c20bd60c2834ab4ecf036db88ec53b8d110"
        end_hex = "c7721e075da91afc2ef762aa7806aa74d952a65d5176d03cc9ac7a0ec0902bb8"

        print(f"Starting search from HEX: {start_hex} to HEX: {end_hex}")

        # Run brute force algorithm
        start_time = time.time()
        found_data = brute_force(targets, start_hex, end_hex)
        end_time = time.time()

        # Save results to I_win.txt
        save_results('I_win.txt', found_data)

        print(f"All addresses found! Time Taken: {end_time - start_time:.2f} seconds")
