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

  - PolicyRegistry: [`0x3579D1B3606d7401A524F78ba8565374639348Fd`](https://sepolia.scrollscan.com/address/0x3579D1B3606d7401A524F78ba8565374639348Fd#code)
  - AgentRegistry: [`0xd97d57bae995259fe1Eb040a63A02F86a4398285`](https://sepolia.scrollscan.com/address/0xd97d57bae995259fe1Eb040a63A02F86a4398285#code)
  - TaskRegistry: [`0x5e38f31693CcAcFCA4D8b70882d8b696cDc24273`](https://sepolia.scrollscan.com/address/0x5e38f31693CcAcFCA4D8b70882d8b696cDc24273#code)
  - PolicyCoordinator: [`0xbAdfD548E1D369633Cf23a53C7c8dC37607001e9`](https://sepolia.scrollscan.com/address/0xbAdfD548E1D369633Cf23a53C7c8dC37607001e9#code)

- **Base Sepolia**:

  - CrosschainSender Contract (AVS Logic Hook): [`0xd97d57bae995259fe1Eb040a63A02F86a4398285`](https://base-sepolia.blockscout.com/address/0xd97d57bae995259fe1Eb040a63A02F86a4398285?tab=contract)
