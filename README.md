# MEVChargeHook

MEVChargeHook is a Solidity smart contract for Uniswap V4. It implements cooldown periods and dynamic fee mechanisms designed to mitigate Maximum Extractable Value (MEV) attacks and enhance swap fairness.

## Features

- **Cooldown periods** to limit rapid trading.
- **Dynamic fees** based on reversed square-root time decay and price impact.
- Designed specifically for use with **Uniswap V4**.

## Installation

### Requirements
- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- [Git](https://git-scm.com)

### Setup
Clone and install dependencies:

```
git clone https://github.com/MrLightspeed/MEVChargeHook.git
cd MEVChargeHook
forge install
```

Create a `.env` file in the project root:

```
PRIVATE_KEY=your_private_key
ETHERSCAN_API_KEY=your_etherscan_api_key
RPC_URL=https://rpc.ankr.com/eth
DEPLOYER_ADDRESS=your_wallet_address
```

## Compilation

Build the contracts:

```
forge clean
forge build
```

## Deployment

Deploy locally for testing:

```
anvil
forge script scripts/DeployHook.s.sol:DeployHookScript --rpc-url http://localhost:8545 --broadcast
```

Deploy to Mainnet/Testnet:

```
forge script scripts/DeployHook.s.sol:DeployHookScript --rpc-url $RPC_URL --broadcast --verify
```

## Project Structure

```
.
├── lib/ (Dependencies)
├── scripts/ (Deployment scripts)
├── src/ (Solidity contracts)
├── images/ (Explanatory images)
├── .env (Environment variables)
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

## Security

Please see [SECURITY.md](./SECURITY.md) for our security policy and reporting instructions.

## Contributions

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT License © 2024 MrLightspeed