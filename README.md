# THMessage - Secure Messaging over Tor Network

![THMessage Logo](https://via.placeholder.com/150?text=THMessage)

THMessage is a high-security messaging application designed for maximum privacy and anonymity, operating exclusively over the Tor network. This application provides end-to-end encrypted communication with advanced security features including post-quantum cryptography, zero-knowledge authentication, and plausible deniability mechanisms.

## Key Features

### Privacy & Anonymity
- **Tor-based Networking**: All communications route through the Tor network for strong anonymity
- **Metadata Minimization**: Traffic padding and cover traffic to prevent metadata analysis
- **Zero-knowledge Architecture**: Even server operators cannot access your messages

### Advanced Encryption
- **End-to-end Encryption**: All messages are encrypted using strong cryptographic algorithms
- **Post-Quantum Security**: Optional post-quantum cryptographic algorithms to protect against quantum computing threats
- **Plausible Deniability**: OTR-like deniability so conversations cannot be cryptographically proven

### User Security
- **Self-Destructing Messages**: Messages can be set to automatically expire and securely delete after reading or specific time periods
- **Secure Contact Verification**: QR code-based key verification and short authentication strings
- **Hidden Spaces**: Separate storage areas accessible only with different credentials for duress situations

### Local Security
- **Zero-knowledge Authentication**: OPAQUE protocol for secure authentication without password transmission
- **Local Database Encryption**: All stored data is encrypted with strong, memory-hard key derivation
- **Secure Deletion**: Multiple-pass secure message deletion to prevent forensic recovery

## Installation

### Prerequisites
- Go 1.21 or higher
- Tor service installed and running

### Building from Source
```bash
git clone https://github.com/yourusername/THMessage.git
cd THMessage
go build -o thmessage cmd/main.go
```

### Running THMessage
```bash
./thmessage
```

## Usage

THMessage features a terminal-based interface with the following main menus:

1. **Messages**: Send and receive encrypted messages with your contacts
2. **Contacts**: Manage your contacts and verify their identity
3. **Settings**: Configure security settings including:
   - Password management
   - Recovery code generation
   - Post-quantum cryptography toggle
   - Default message expiration times

## Security Recommendations

- Verify contact identities through out-of-band channels
- Use long, randomly generated passwords
- Enable post-quantum encryption for maximum security
- Set appropriate message expiration times
- Consider using hardware security tokens when available

## Architecture

THMessage is built with a modular architecture:
- `auth`: Zero-knowledge authentication system
- `crypto`: Cryptographic operations including E2EE and post-quantum algorithms
- `network`: Tor networking and traffic obfuscation
- `storage`: Secure, encrypted local storage
- `ui`: Terminal user interface

## Development Status

THMessage is currently in alpha development. While core functionality is implemented, the application should not yet be used in situations where security is critical.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to the Tor Project for providing the anonymous network infrastructure
- All cryptographic libraries and tools that make this application possible

## Disclaimer

THMessage is provided as-is without any warranty. While we strive for maximum security, no communication system can guarantee absolute security. Use at your own risk.