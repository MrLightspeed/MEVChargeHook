# MEVChargeHook

MEVChargeHook is a Solidity smart contract designed specifically for Uniswap V4. It implements cooldown periods and dynamic fee mechanisms to effectively mitigate Maximum Extractable Value (MEV) attacks and enhance fairness in token swaps.

## Features

- **Cooldown Periods:** Prevent rapid, repeated trades from the same user.
- **Dynamic Fees:** Apply fees based on reversed square-root time decay and price impact.
- **Gas Efficient:** Optimized storage and computation for lower deployment and execution costs.

## Installation

### Requirements

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- [Git](https://git-scm.com)

### Setup

Clone the repository and install dependencies:

```bash
git clone https://github.com/MrLightspeed/MEVChargeHook.git
cd MEVChargeHook
forge install
```

### Installing Project Dependencies

Ensure you have the necessary imports by running:

```bash
forge install foundry-rs/forge-std
forge install Uniswap/v4-core
forge install Uniswap/v4-periphery
forge install OpenZeppelin/openzeppelin-contracts
forge install paulrberg/prb-math
```

### Environment Configuration

Create a `.env` file at the root of your project with the following variables:

```env
PRIVATE_KEY=your_private_key
ETHERSCAN_API_KEY=your_etherscan_api_key
RPC_URL=https:your_rpc_url_with_key
DEPLOYER_ADDRESS=your_wallet_address
```

**Important Security Considerations:**
- **Never commit your `.env` file.** Make sure `.env` is listed in your `.gitignore`.
- Regularly audit your repository to prevent accidental exposure of sensitive data.
- Confirm environment variables are loaded correctly before running deployment scripts.

## Compilation

Clean previous builds and compile contracts:

```bash
forge clean
forge build
```

## Deployment

### Local Testing

Start a local Ethereum node and deploy for testing:

**Unix/Mac:**

```bash
anvil
forge script scripts/DeployHook.s.sol:DeployHookScript --rpc-url http://localhost:8545 --broadcast
```

**Windows (PowerShell):**

```powershell
anvil
forge script scripts/DeployHook.s.sol:DeployHookScript --rpc-url http://localhost:8545 --broadcast
```

### Deploying to Mainnet/Testnet

Ensure environment variables (`PRIVATE_KEY`, `RPC_URL`, `ETHERSCAN_API_KEY`) are properly configured and loaded, then deploy:

**Unix/Mac:**

```bash
forge script scripts/DeployHook.s.sol:DeployHookScript --rpc-url $RPC_URL --broadcast --verify --etherscan-api-key $ETHERSCAN_API_KEY
```

**Windows (PowerShell):**

```powershell
forge script scripts/DeployHook.s.sol:DeployHookScript --rpc-url $env:RPC_URL --broadcast --verify --etherscan-api-key $env:ETHERSCAN_API_KEY
```

This command deploys and automatically verifies contracts using your provided Etherscan API key.

## Project Structure

```
.
├── lib/ (Dependencies)
├── scripts/ (Deployment scripts)
├── src/ (Solidity contracts)
├── test/ (Contract tests)
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
├── README.md
├── PROJECT_OVERVIEW.md
├── foundry.toml
└── remappings.txt

```

## Documentation & Resources

- [📄 Project Overview](./PROJECT_OVERVIEW.md)
- [📖 Foundry Book](https://book.getfoundry.sh)

## Security

Review the [SECURITY.md](./SECURITY.md) for our detailed security policies and how to responsibly disclose vulnerabilities.

## Contributions

We welcome contributions! Please follow guidelines in [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT License © 2024 MrLightspeed
