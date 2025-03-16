# SynthOS Smart Contracts

### SynthOS is a Verifiable DeFAI Agent Marketplace that implements a cross-chain policy validation system between Base and Scroll networks. The system enables secure validation of agent transactions against predefined policies across different chains.

### System Architecture

The system consists of four main smart contracts:

1. **PolicyRegistry.sol**

   - Manages the registration and storage of policies
   - Defines rules and constraints for agent actions
   - Handles policy lifecycle (creation, activation, deactivation)

2. **AgentRegistry.sol**

   - Manages agent registration and metadata
   - Links agents to their associated policies
   - Tracks agent status and capabilities

3. **PolicyCoordinator.sol**

   - Core contract for transaction validation
   - Coordinates between agents and their policies
   - Validates transactions against time, function, and resource constraints
   - Receives cross-chain messages from Base network
   - Deployed on Scroll Sepolia

4. **CrosschainSender.sol**
   - Handles cross-chain communication from Base to Scroll
   - Integrates with Hyperlane for secure message passing
   - Acts as an AVS Logic hook for task validation
   - Deployed on Base Sepolia

### Cross-Chain Flow

![Image](https://github.com/user-attachments/assets/ccee5253-acdf-43c6-8cb6-f7efd1e12589)

### Key Features

- **Cross-Chain Validation**: Enables policy validation across Base and Scroll networks
- **Policy Management**: Flexible policy definition with time, function, and resource constraints
- **Agent Registry**: Secure registration and management of DeFi agents
- **Hyperlane Integration**: Secure cross-chain message passing
- **Task Validation**: Comprehensive validation system for agent actions

### Deployed Contracts

- **Scroll Sepolia**:

  - PolicyRegistry: [`0xa7b0446a0fa8e8c503774987931e071e3ddf271a`](https://sepolia.scrollscan.com/address/0xa7b0446a0fa8e8c503774987931e071e3ddf271a#code)
  - AgentRegistry: [`0x6ed02bf56beb79d47f734ee6bb4701b9789b4d5b`](https://sepolia.scrollscan.com/address/0x6ed02bf56beb79d47f734ee6bb4701b9789b4d5b#code)
  - TaskRegistry: [`0x8eab19f680afcfd21f0d42353e06c85f3359024c`](https://sepolia.scrollscan.com/address/0x8eab19f680afcfd21f0d42353e06c85f3359024c#code)
  - PolicyCoordinator: [`0x2e22bc79b58117015bf458045488e09aaa0bb794`](https://sepolia.scrollscan.com/address/0x2e22bc79b58117015bf458045488e09aaa0bb794#code)

- **Base Sepolia**:

  - CrosschainSender Contract (AVS Logic Hook): [`0x201cE172d07566BEa747D18848534f4d8aDBe69f`](https://base-sepolia.blockscout.com/address/0x201cE172d07566BEa747D18848534f4d8aDBe69f?tab=contract)
