#!/usr/bin/env python3
"""
DES Sender Script

This script initiates the DES encryption/decryption process as a sender.
It can send encrypted messages to a receiver and receive encrypted messages from it.

Usage:
    python sender.py [OPTIONS]

Options:
    --host HOST      Receiver's host address (default: localhost)
    --port PORT      Receiver's port (default: 12345)
    --debug          Enable debug output
    --help           Show this help message
"""

import sys
import argparse
import time
from network_communication import Sender

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="DES Sender")
    parser.add_argument("--host", default="localhost", help="Receiver's host address")
    parser.add_argument("--port", type=int, default=12345, help="Receiver's port")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()
    
    print("=== DES Encryption/Decryption System - Sender ===")
    print(f"Receiver host: {args.host}")
    print(f"Receiver port: {args.port}")
    print(f"Debug mode: {'Enabled' if args.debug else 'Disabled'}")
    
    # Get encryption key
    while True:
        key = input("\nEnter 8-character encryption key: ")
        if len(key) == 8:
            break
        print("Error: Key must be exactly 8 characters.")
    
    # Create sender
    sender = Sender(key.encode('utf-8'), args.host, args.port, debug=args.debug)
    
    # Main loop
    try:
        if not sender.connect():
            print("Failed to connect. Exiting.")
            return
        
        while True:
            print("\nOptions:")
            print("1. Send message")
            print("2. Receive message")
            print("3. Exit")
            
            choice = input("Enter choice (1-3): ")
            
            if choice == "1":
                sender.send_message()
            elif choice == "2":
                sender.receive_message()
            elif choice == "3":
                break
            else:
                print("Invalid choice. Please try again.")
    
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    
    finally:
        sender.close()
        print("Sender terminated.")

if __name__ == "__main__":
    main()
