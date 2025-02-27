// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EnumerableSet} from "@openzeppelin-contracts-5.2.0/utils/structs/EnumerableSet.sol";
import "./PolicyRegistry.sol";
import "./interfaces/IPolicy.sol";

/**
 * @title AgentRegistry
 * @notice Manages registration of agents identified by their Dockerfile hash
 */
contract AgentRegistry {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    enum AgentCategory {
        General, // General purpose agents
        DeFi, // DeFi-specific agents (lending, trading, etc.)
        Security, // Security monitoring and analysis
        Oracle, // Oracle monitoring and validation
        Analytics // Data analysis and metrics
    }

    struct Agent {
        address owner;
        uint256 executionFee;
        address[] avsPolicies;
        bool isRegistered;
        string dockerfileHash;
        string agentLocation; // URL/IPFS hash where agent is hosted
        string description; // Brief description of the agent
        AgentCategory category; // Category the agent belongs to
    }

    // Dockerfile hash => Agent details
    mapping(string => Agent) public agents;

    // Set of all registered dockerfile hashes (as bytes32)
    EnumerableSet.Bytes32Set private _registeredHashes;

    // Events
    event AgentRegistered(
        string indexed dockerfileHash,
        address owner,
        uint256 executionFee,
        string agentLocation,
        string description,
        AgentCategory category
    );
    event AgentUpdated(string indexed dockerfileHash, uint256 newExecutionFee);
    event AVSPoliciesUpdated(
        string indexed dockerfileHash,
        address[] avsPolicies
    );
    event AgentMetadataUpdated(
        string indexed dockerfileHash,
        string newLocation,
        string newDescription,
        AgentCategory newCategory
    );

    // Errors
    error AgentAlreadyRegistered(string dockerfileHash);
    error AgentNotRegistered();
    error NotAgentOwner();
    error InvalidExecutionFee();
    error EmptyAVSPolicies();
    error EmptyDockerfileHash();
    error EmptyAgentLocation();
    error EmptyDescription();
    error InvalidIndex();

    PolicyRegistry public policyRegistry;

    constructor(address _policyRegistry) {
        policyRegistry = PolicyRegistry(_policyRegistry);
    }

    /**
     * @notice Register a new agent with execution fee and AVS policies
     * @param dockerfileHash Hash of the agent's Dockerfile
     * @param executionFee Fee to be charged for each agent execution, in wei
     * @param avsPolicies Array of AVS policy contract addresses
     * @param agentLocation URL/IPFS hash where agent is hosted
     * @param description Brief description of the agent
     * @param category Category the agent belongs to
     */
    function registerAgent(
        string calldata dockerfileHash,
        uint256 executionFee,
        address[] calldata avsPolicies,
        string calldata agentLocation,
        string calldata description,
        AgentCategory category
    ) external {
        if (bytes(dockerfileHash).length == 0) revert EmptyDockerfileHash();
        if (bytes(agentLocation).length == 0) revert EmptyAgentLocation();
        if (bytes(description).length == 0) revert EmptyDescription();
        if (agents[dockerfileHash].isRegistered)
            revert AgentAlreadyRegistered(dockerfileHash);
        if (executionFee == 0) revert InvalidExecutionFee();
        if (avsPolicies.length == 0) revert EmptyAVSPolicies();

        // Verify all policies are valid and active
        policyRegistry.verifyPolicies(avsPolicies);

        // Register the agent
        agents[dockerfileHash] = Agent({
            owner: msg.sender,
            executionFee: executionFee,
            avsPolicies: avsPolicies,
            isRegistered: true,
            dockerfileHash: dockerfileHash,
            agentLocation: agentLocation,
            description: description,
            category: category
        });

        // Convert string to bytes32 for storage
        bytes32 hashAsBytes32 = keccak256(bytes(dockerfileHash));
        _registeredHashes.add(hashAsBytes32);

        emit AgentRegistered(
            dockerfileHash,
            msg.sender,
            executionFee,
            agentLocation,
            description,
            category
        );
    }

    /**
     * @notice Update agent's execution fee
     * @param dockerfileHash Hash of the agent's Dockerfile
     * @param newExecutionFee New fee to be charged for each agent execution
     */
    function updateExecutionFee(
        string calldata dockerfileHash,
        uint256 newExecutionFee
    ) external {
        if (!agents[dockerfileHash].isRegistered) {
            revert AgentNotRegistered();
        }
        if (msg.sender != agents[dockerfileHash].owner) {
            revert NotAgentOwner();
        }
        if (newExecutionFee == 0) {
            revert InvalidExecutionFee();
        }

        agents[dockerfileHash].executionFee = newExecutionFee;
        emit AgentUpdated(dockerfileHash, newExecutionFee);
    }

    /**
     * @notice Update agent's AVS policies
     * @param dockerfileHash Hash of the agent's Dockerfile
     * @param newAVSPolicies New array of AVS policy contract addresses
     */
    function updateAVSPolicies(
        string calldata dockerfileHash,
        address[] calldata newAVSPolicies
    ) external {
        if (!agents[dockerfileHash].isRegistered) {
            revert AgentNotRegistered();
        }
        if (msg.sender != agents[dockerfileHash].owner) {
            revert NotAgentOwner();
        }
        if (newAVSPolicies.length == 0) {
            revert EmptyAVSPolicies();
        }

        agents[dockerfileHash].avsPolicies = newAVSPolicies;
        emit AVSPoliciesUpdated(dockerfileHash, newAVSPolicies);
    }

    /**
     * @notice Update agent's metadata
     * @param dockerfileHash Hash of the agent's Dockerfile
     * @param newLocation New URL/IPFS hash where agent is hosted
     * @param newDescription New description of the agent
     * @param newCategory New category for the agent
     */
    function updateAgentMetadata(
        string calldata dockerfileHash,
        string calldata newLocation,
        string calldata newDescription,
        AgentCategory newCategory
    ) external {
        if (!agents[dockerfileHash].isRegistered) revert AgentNotRegistered();
        if (msg.sender != agents[dockerfileHash].owner) revert NotAgentOwner();
        if (bytes(newLocation).length == 0) revert EmptyAgentLocation();
        if (bytes(newDescription).length == 0) revert EmptyDescription();

        Agent storage agent = agents[dockerfileHash];
        agent.agentLocation = newLocation;
        agent.description = newDescription;
        agent.category = newCategory;

        emit AgentMetadataUpdated(
            dockerfileHash,
            newLocation,
            newDescription,
            newCategory
        );
    }

    /**
     * @notice Get agent details
     * @param dockerfileHash Hash of the agent's Dockerfile
     */
    function getAgent(
        string calldata dockerfileHash
    )
        external
        view
        returns (
            address owner,
            uint256 executionFee,
            address[] memory avsPolicies,
            bool isRegistered,
            string memory agentDockerfileHash,
            string memory agentLocation,
            string memory description,
            AgentCategory category
        )
    {
        Agent memory agent = agents[dockerfileHash];
        return (
            agent.owner,
            agent.executionFee,
            agent.avsPolicies,
            agent.isRegistered,
            agent.dockerfileHash,
            agent.agentLocation,
            agent.description,
            agent.category
        );
    }

    /**
     * @notice Get total number of registered agents
     * @return Number of registered agents
     */
    function getAgentCount() external view returns (uint256) {
        return _registeredHashes.length();
    }

    /**
     * @notice Get agent hash at specific index
     * @param index Index in the set of registered hashes
     * @return Agent's dockerfile hash at the specified index
     */
    function getAgentHashAtIndex(
        uint256 index
    ) external view returns (string memory) {
        if (index >= _registeredHashes.length()) {
            revert InvalidIndex();
        }
        bytes32 hashAsBytes32 = _registeredHashes.at(index);
        // Note: This is a simplified conversion. In practice, you might want to store
        // the original string mapping alongside the bytes32 hash
        return string(abi.encodePacked(hashAsBytes32));
    }

    /**
     * @notice Get all registered agent hashes
     * @return Array of all registered dockerfile hashes
     */
    function getAllAgentHashes() external view returns (string[] memory) {
        uint256 length = _registeredHashes.length();
        string[] memory hashes = new string[](length);

        for (uint256 i = 0; i < length; i++) {
            bytes32 hashAsBytes32 = _registeredHashes.at(i);
            hashes[i] = string(abi.encodePacked(hashAsBytes32));
        }

        return hashes;
    }

    /**
     * @notice Add new function to validate actions against policies
     * @param dockerfileHash Hash of the agent's Dockerfile
     * @param actionData Encoded action data to validate
     * @return bool True if action is valid according to all policies
     */
    function validateAgentAction(
        string calldata dockerfileHash,
        bytes calldata actionData
    ) external view returns (bool) {
        Agent memory agent = agents[dockerfileHash];
        if (!agent.isRegistered) revert AgentNotRegistered();

        // Check against each policy
        for (uint256 i = 0; i < agent.avsPolicies.length; i++) {
            address policyAddr = agent.avsPolicies[i];
            (bool valid, string memory reason) = IPolicy(policyAddr)
                .validateAction(dockerfileHash, actionData);
            if (!valid) {
                revert(reason);
            }
        }

        return true;
    }
}
