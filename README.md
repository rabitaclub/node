# Rabita Smart Contracts (Pay To Reach)

Rabita is a decentralized messaging and verification protocol connecting KOLs (Key Opinion Leaders) with their audience on the blockchain.

## Overview

The repo consists of two main components:

1. **RabitaRegistry**: Handles KOL registration and verification
2. **Messaging**: Manages the messaging service between users and verified KOLs

## Features

- Secure KOL verification using cryptographic signatures
- Direct messaging to verified KOLs
- Message response tracking with automatic timeout handling
- Fee distribution system with platform fees
- Security features to prevent common attacks

## Development Setup

### Prerequisites

- Node.js (v22+)
- Yarn or NPM

### Installation

```bash
# Clone the repository
git clone https://github.com/0xrobinr/rabita-node.git
cd rabita-node

# Install dependencies
npm install
```

### Compile Contracts

```bash
npx hardhat compile
```

### Run Tests

```bash
npx hardhat test
```

## Deployment

The deployment process is managed using Hardhat Ignition, which provides a clean, declarative way to deploy smart contracts.

### Local Deployment

```bash
npx hardhat run scripts/deployRabita.ts --network localhost
```

### Testnet/Mainnet Deployment

1. Create a `.env` file with your private keys and RPC URLs:
```
BSC_URL=https://bsc-dataseed.binance.org/
TEST_URL=https://data-seed-prebsc-1-s1.binance.org:8545/
BSC_KEY=your_private_key
TEST_KEY=your_private_key
```

2. Run the deployment script:
```bash
# For testnet
npx hardhat run scripts/deployRabita.ts --network testnet

# For BSC mainnet
npx hardhat run scripts/deployRabita.ts --network bsc
```

The deployment script will create a `.env.deployment` file with the deployed contract addresses.

## Post-Deployment Configuration

After deployment, you can configure using the configuration script:

1. Modify the `.env.deployment` file to set your configuration options
2. Run the configuration script:
```bash
npx hardhat run scripts/configureRabita.ts --network testnet
```

### Configuration Options

- **Update Verifier**: Change the verification signer address
- **Register KOL**: Register an initial KOL with specified details

## Smart Contract Architecture

### RabitaRegistry

The `RabitaRegistry` contract handles:
- KOL registration with cryptographic verification
- KOL profile management
- Verifier updates (owner only)

### Messaging

The `Messaging` contract handles:
- Message sending to verified KOLs
- Message response tracking
- Fee distribution
- Message timeout handling
- Platform fee collection

## Security Considerations

The contracts implement security measures including:
- Reentrancy guards
- Proper fee handling
- Timelock mechanisms
- Access control
- Message expiration

## License

MIT
