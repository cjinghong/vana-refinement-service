#!/usr/bin/env python3
from coincurve import PrivateKey
import json
import os
import sys
from eth_utils import keccak

def generate_wallet_file(private_key_hex: str, output_path: str):
    """
    Generate a Vana wallet file with the correct format. 
    Use this script if you want to generate a wallet file from a private key instead of from a mnemonic.
    
    Args:
        private_key_hex: Private key in hex format (with or without 0x prefix)
        output_path: Path where the wallet file should be saved
    """
    # Remove 0x prefix if present
    private_key_hex = private_key_hex.removeprefix('0x')
    
    # Create private key object
    private_key = PrivateKey(bytes.fromhex(private_key_hex))
    
    # Get public key (uncompressed format)
    public_key_bytes = private_key.public_key.format(compressed=False)
    public_key = '0x' + public_key_bytes.hex()
    
    # Ethereum address: keccak256 hash of public key (without 0x04 prefix), last 20 bytes
    pubkey_no_prefix = public_key_bytes[1:]
    address_bytes = keccak(pubkey_no_prefix)[-20:]
    address = '0x' + address_bytes.hex()
    
    # Create wallet data
    wallet_data = {
        "address": address,
        "publicKey": public_key,
        "privateKey": f"0x{private_key_hex}"
    }
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Write wallet file
    with open(output_path, 'w') as f:
        json.dump(wallet_data, f, indent=2)
    
    print(f"Wallet file generated at: {output_path}")
    print(f"Address: {address}")
    print(f"Public Key: {public_key}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python generate_wallet.py <private_key>")
        print("Example: python generate_wallet.py 8ba41234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        sys.exit(1)
    
    private_key = sys.argv[1]
    output_path = os.path.expanduser("~/.vana/wallets/default/hotkeys/default")
    generate_wallet_file(private_key, output_path) 