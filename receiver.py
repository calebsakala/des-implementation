#!/usr/bin/env python3
"""
DES Receiver Script

This script initiates the DES encryption/decryption process as a receiver.
It can receive encrypted messages from a sender and send encrypted messages to it.

Usage:
    python receiver.py [OPTIONS]

Options:
    --host HOST      Host address to listen on (default: 0.0.0.0)
    --port PORT      Port to listen on (default: 12345)
    --debug          Enable debug output
    --help           Show this help message
"""

import sys
import argparse
import time
from network_communication import Receiver

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="DES Receiver")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to listen on")
    parser.add_argument("--port", type=int, default=12345, help="Port to listen on")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()
    
    print("=== DES Encryption/Decryption System - Receiver ===")
    print(f"Listening on host: {args.host}")
    print(f"Listening on port: {args.port}")
    print(f"Debug mode: {'Enabled' if args.debug else 'Disabled'}")
    
    # Get encryption key
    while True:
        key = input("\nEnter 8-character encryption key: ")
        if len(key) == 8:
            break
        print("Error: Key must be exactly 8 characters.")
    
    # Create receiver
    receiver = Receiver(key.encode('utf-8'), args.host, args.port, debug=args.debug)
    
    # Main loop
    try:
        if not receiver.start_server():
            print("Failed to start server. Exiting.")
            return
        
        print("\nWaiting for connection...")
        if not receiver.accept_connection():
            print("Failed to accept connection. Exiting.")
            return
        
        print("\nConnection established. Ready to communicate.")
        
        while True:
            print("\nOptions:")
            print("1. Receive message")
            print("2. Send message")
            print("3. Exit")
            
            choice = input("Enter choice (1-3): ")
            
            if choice == "1":
                receiver.receive_message()
            elif choice == "2":
                receiver.send_message()
            elif choice == "3":
                break
            else:
                print("Invalid choice. Please try again.")
    
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    
    finally:
        receiver.close()
        print("Receiver terminated.")

if __name__ == "__main__":
    main()
