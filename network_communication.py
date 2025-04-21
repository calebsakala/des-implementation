"""
DES Network Communication Components

This module provides the Sender and Receiver classes for network communication
using DES encryption. Both classes can send and receive encrypted messages.
"""

import socket
import pickle
import os
import sys
import time
from des import DES

class DESCommunicator:
    """Base class for DES network communication."""
    
    def __init__(self, key, host, port, debug=False):
        """
        Initialize the DES communicator.
        
        Args:
            key (bytes): 8-byte key for DES encryption
            host (str): Host address to connect to or listen on
            port (int): Port to connect to or listen on
            debug (bool): Enable debug output
        """
        self.des = DES(key, debug=debug)
        self.host = host
        self.port = port
        self.debug = debug
        self.socket = None
        self.connection = None
    
    def create_message(self, prompt=None):
        """
        Create a message to send.
        
        Args:
            prompt (str): Optional custom prompt
            
        Returns:
            bytes: Message as bytes
        """
        if prompt is None:
            prompt = "Enter message to send: "
        
        message = input(prompt)
        return message.encode('utf-8')
    
    def encrypt_message(self, message):
        """
        Encrypt a message using DES.
        
        Args:
            message (bytes): Message to encrypt
            
        Returns:
            bytes: Encrypted message
        """
        print("Encrypting message...")
        if self.debug:
            print(f"Original message (bytes): {message}")
        
        encrypted = self.des.encrypt(message)
        
        if self.debug:
            print(f"Encrypted message (bytes): {encrypted}")
        
        return encrypted
    
    def decrypt_message(self, encrypted_message):
        """
        Decrypt a message using DES.
        
        Args:
            encrypted_message (bytes): Message to decrypt
            
        Returns:
            bytes: Decrypted message
        """
        print("Decrypting message...")
        if self.debug:
            print(f"Encrypted message (bytes): {encrypted_message}")
        
        decrypted = self.des.decrypt(encrypted_message)
        
        if self.debug:
            print(f"Decrypted message (bytes): {decrypted}")
        
        return decrypted
    
    def display_message(self, message):
        """
        Display a decrypted message.
        
        Args:
            message (bytes): Message to display
        """
        try:
            decoded = message.decode('utf-8')
            print("\nReceived message:")
            print("-" * 40)
            print(decoded)
            print("-" * 40)
        except UnicodeDecodeError:
            print("Warning: Could not decode message as UTF-8.")
            print("Raw bytes:", message)
    
    def close(self):
        """Close any open connections and sockets."""
        if self.connection and self.connection != self.socket:
            self.connection.close()
        
        if self.socket:
            self.socket.close()
            
        print("Connection closed.")


class Sender(DESCommunicator):
    """DES message sender component."""
    
    def connect(self):
        """Connect to the receiver."""
        print(f"Connecting to {self.host}:{self.port}...")
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect((self.host, self.port))
            self.connection = self.socket
            print(f"Connected to {self.host}:{self.port}")
            return True
        except ConnectionRefusedError:
            print(f"Connection to {self.host}:{self.port} refused. Is the receiver running?")
            return False
        except Exception as e:
            print(f"Error connecting: {e}")
            return False
    
    def send_message(self, message=None):
        """
        Create, encrypt and send a message.
        
        Args:
            message (bytes, optional): Message to send. If None, user will be prompted.
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.connection:
            print("Not connected. Call connect() first.")
            return False
        
        try:
            # Create message if not provided
            if message is None:
                message = self.create_message()
            
            # Encrypt message
            encrypted = self.encrypt_message(message)
            
            # Send message length first
            self.connection.sendall(len(encrypted).to_bytes(4, byteorder='big'))
            
            # Send encrypted message
            self.connection.sendall(encrypted)
            
            print("Message sent successfully.")
            return True
        except Exception as e:
            print(f"Error sending message: {e}")
            return False
    
    def receive_message(self):
        """
        Receive, decrypt and display a message.
        
        Returns:
            bytes: Decrypted message, or None if failed
        """
        if not self.connection:
            print("Not connected. Call connect() first.")
            return None
        
        try:
            # Receive message length first
            length_bytes = self.connection.recv(4)
            if not length_bytes:
                print("Connection closed by receiver.")
                return None
            
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive encrypted message
            encrypted_message = b''
            remaining = message_length
            
            while remaining > 0:
                chunk = self.connection.recv(min(4096, remaining))
                if not chunk:
                    print("Connection closed by receiver.")
                    return None
                
                encrypted_message += chunk
                remaining -= len(chunk)
            
            print(f"Received {len(encrypted_message)} encrypted bytes.")
            
            # Decrypt message
            decrypted = self.decrypt_message(encrypted_message)
            
            # Display message
            self.display_message(decrypted)
            
            return decrypted
        except Exception as e:
            print(f"Error receiving message: {e}")
            return None


class Receiver(DESCommunicator):
    """DES message receiver component."""
    
    def start_server(self):
        """
        Start listening for connections.
        
        Returns:
            bool: True if server started successfully, False otherwise
        """
        print(f"Starting server on {self.host}:{self.port}...")
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(1)
            print(f"Listening on {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Error starting server: {e}")
            return False
    
    def accept_connection(self):
        """
        Accept a connection from a sender.
        
        Returns:
            bool: True if connection accepted, False otherwise
        """
        if not self.socket:
            print("Server not started. Call start_server() first.")
            return False
        
        print("Waiting for connection...")
        try:
            self.connection, addr = self.socket.accept()
            print(f"Connection from {addr[0]}:{addr[1]}")
            return True
        except Exception as e:
            print(f"Error accepting connection: {e}")
            return False
    
    def receive_message(self):
        """
        Receive, decrypt and display a message.
        
        Returns:
            bytes: Decrypted message, or None if failed
        """
        if not self.connection:
            print("No connection. Call accept_connection() first.")
            return None
        
        try:
            # Receive message length first
            length_bytes = self.connection.recv(4)
            if not length_bytes:
                print("Connection closed by sender.")
                return None
            
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive encrypted message
            encrypted_message = b''
            remaining = message_length
            
            while remaining > 0:
                chunk = self.connection.recv(min(4096, remaining))
                if not chunk:
                    print("Connection closed by sender.")
                    return None
                
                encrypted_message += chunk
                remaining -= len(chunk)
            
            print(f"Received {len(encrypted_message)} encrypted bytes.")
            
            # Decrypt message
            decrypted = self.decrypt_message(encrypted_message)
            
            # Display message
            self.display_message(decrypted)
            
            return decrypted
        except Exception as e:
            print(f"Error receiving message: {e}")
            return None
    
    def send_message(self, message=None):
        """
        Create, encrypt and send a message.
        
        Args:
            message (bytes, optional): Message to send. If None, user will be prompted.
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.connection:
            print("No connection. Call accept_connection() first.")
            return False
        
        try:
            # Create message if not provided
            if message is None:
                message = self.create_message()
            
            # Encrypt message
            encrypted = self.encrypt_message(message)
            
            # Send message length first
            self.connection.sendall(len(encrypted).to_bytes(4, byteorder='big'))
            
            # Send encrypted message
            self.connection.sendall(encrypted)
            
            print("Message sent successfully.")
            return True
        except Exception as e:
            print(f"Error sending message: {e}")
            return False
