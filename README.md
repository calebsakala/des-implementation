# DES Implementation for Computer Security Lab 2

This project implements the Data Encryption Standard (DES) algorithm as a distributed application that allows two computers to securely communicate with encrypted messages. The implementation includes all components of the DES algorithm and network functionality for sending and receiving encrypted messages.

## Project Structure

The project consists of the following files:

- `des.py`: Core DES algorithm implementation
- `network_communication.py`: Network communication components
- `sender.py`: Script for the sending computer
- `receiver.py`: Script for the receiving computer
- `test_des.py`: Test script to verify the correctness of the DES implementation

## Features

- Complete implementation of DES algorithm:
  - Initial permutation and its inverse
  - Expansion permutation
  - Key scheduling (PC-1, shift schedule, PC-2)
  - S-box substitution
  - Permutation P
  - Feistel function
  - 16-round structure

- Network functionality:
  - Socket-based communication between two computers
  - Support for both sending and receiving on each computer
  - Error handling for network communication

- Debugging and testing:
  - Debug mode for tracing the algorithm's execution
  - Test suite to verify the correctness of all transformations

## Requirements

- Python 3.6 or higher
- Two computers connected to the same network

## Setup Instructions

1. Copy the code files to both computers.

2. Make sure both computers can communicate over the network:
   - Determine the IP address of the computer that will run the receiver.
   - Ensure the chosen port (default: 12345) is not blocked by a firewall.

3. Install required dependencies (if any):
   ```
   pip install -r requirements.txt
   ```

## Usage

### Running the Receiver

On the first computer (which will act as the server/receiver), run:

```bash
python receiver.py [--host HOST] [--port PORT] [--debug]
```

Options:
- `--host HOST`: Host address to listen on (default: 0.0.0.0)
- `--port PORT`: Port to listen on (default: 12345)
- `--debug`: Enable debug output

The receiver will prompt you to enter an 8-character encryption key, then it will start listening for connections.

### Running the Sender

On the second computer (which will act as the client/sender), run:

```bash
python sender.py --host RECEIVER_IP [--port PORT] [--debug]
```

Options:
- `--host HOST`: Receiver's host address (default: localhost)
- `--port PORT`: Receiver's port (default: 12345)
- `--debug`: Enable debug output

Replace `RECEIVER_IP` with the IP address of the receiver computer. The sender will prompt you to enter the same 8-character encryption key used on the receiver, then it will attempt to connect to the receiver.

### Using the Application

Once the connection is established, both the sender and receiver provide a menu-driven interface to:
1. Send messages
2. Receive messages
3. Exit the application

Messages are encrypted using DES before transmission and decrypted upon reception.

## Testing

To test the DES implementation without setting up the network communication, run:

```bash
python test_des.py
```

This will execute a series of tests to verify the correctness of:
- Initial permutation
- Expansion permutation
- Key generation
- S-box substitution
- Permutation P
- Feistel function
- Complete DES encryption and decryption

## Security Considerations

- This implementation is for educational purposes and may not be secure for real-world applications.
- The DES algorithm is considered obsolete for secure communications.
- The key is limited to 8 characters (64 bits, with 56 bits actually used).
- No additional security measures (like padding, authentication, integrity verification) are implemented.
- The communication protocol is simple and does not handle advanced features like session management.

## How the DES Algorithm Works

### Overview
DES operates on 64-bit blocks of data using a 56-bit key (although the key is typically represented as 64 bits with 8 parity bits). The algorithm consists of an initial permutation, 16 rounds of a complex function, and a final permutation (which is the inverse of the initial permutation).

### Key Components

1. **Initial Permutation (IP)** - Rearranges the bits of the 64-bit input block according to a fixed table.

2. **Key Schedule** - Generates sixteen 48-bit subkeys from the 56-bit key through:
   - Permuted Choice 1 (PC-1): Reduces the 64-bit key to 56 bits by removing parity bits
   - Left Circular Shifts: According to a predefined schedule
   - Permuted Choice 2 (PC-2): Further reduces to 48 bits for each round

3. **Rounds (16x)** - Each round consists of:
   - Expansion: Expands the 32-bit right half to 48 bits
   - Key mixing: XOR with the round's subkey
   - Substitution: Through eight S-boxes, reducing back to 32 bits
   - Permutation: Rearranges the bits according to the P-box
   - Combination: XOR with the left half
   - Swap: Left and right halves are swapped (except in the final round)

4. **Final Permutation (IP⁻¹)** - The inverse of the initial permutation

### Encryption Process
1. Apply initial permutation
2. Split into left and right halves
3. Perform 16 rounds
4. Recombine the halves (in reverse order)
5. Apply final permutation

### Decryption Process
The decryption process is identical to encryption, but uses the subkeys in reverse order.

## Implementation Notes

### DES Class
The `DES` class encapsulates all the functionality of the DES algorithm, including:
- Bit manipulation utilities
- Permutation functions
- Key schedule generation
- Round function implementation
- Block encryption and decryption
- Support for arbitrary-length messages

### Network Communication
The network implementation follows a client-server model where:
- `Receiver` acts as a server, listening for connections
- `Sender` acts as a client, initiating connections
- Both can send and receive messages once connected

The communication protocol is simple:
1. Send the length of the encrypted message (4 bytes)
2. Send the encrypted message
3. Receive the length of the encrypted message (4 bytes)
4. Receive the encrypted message

## Report Preparation Guidelines

As per the lab requirements, prepare a report including:

1. **Cover page** with university, department, course details, team members, etc.
2. **Outline** of the project
3. **Problem definition** from the lab task
4. **Work done**:
   - Code explanation with screenshots of the running program
   - Screenshots showing each step of the DES algorithm's execution
   - Description of the distributed system setup
5. **Conclusion**
6. **References**
7. **Appendix** with source code

## Known Limitations

- The implementation may not be optimized for performance
- Error handling could be improved
- No support for different modes of operation (CBC, CTR, etc.)
- The key is limited to 8 characters
- No key validation or strength checking

## License

This project is available for educational purposes.
