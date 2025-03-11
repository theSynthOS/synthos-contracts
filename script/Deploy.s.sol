// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {Test, console} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {AgentRegistry} from "../src/AgentRegistry.sol";

contract DeployScript is Script {
    function run() external {
        uint256 privKey = vm.envUint("PRIV_KEY");
        address deployer = vm.rememberKey(privKey);

        console.log("Deployer: ", deployer);
        console.log("Deployer Nonce: ", vm.getNonce(deployer));

        vm.startBroadcast(deployer);

        // Deploy PolicyRegistry first
        PolicyRegistry policyRegistry = new PolicyRegistry();
        console.log("PolicyRegistry deployed at: ", address(policyRegistry));

        // Deploy AgentRegistry with PolicyRegistry address
        AgentRegistry agentRegistry = new AgentRegistry(
            address(policyRegistry)
        );
        console.log("AgentRegistry deployed at: ", address(agentRegistry));

        // Example: Register a sample policy
        string memory policyName = "Sample Policy";
        string memory policyDesc = "A sample policy for testing";
        address policyImpl = address(
            0x1234567890123456789012345678901234567890
        ); // Replace with actual policy implementation

        policyRegistry.registerPolicy(policyName, policyDesc, policyImpl);
        console.log("Registered sample policy at: ", policyImpl);

        // Example: Register a sample agent
        string memory dockerfileHash = "sample_hash";
        uint256 executionFee = 0.001 ether;
        address[] memory avsPolicies = new address[](1);
        avsPolicies[0] = policyImpl;
        string memory agentLocation = "ipfs://QmSampleHash";
        string memory description = "Sample Agent";
        AgentRegistry.AgentCategory category = AgentRegistry
            .AgentCategory
            .General;

        agentRegistry.registerAgent(
            dockerfileHash,
            executionFee,
            avsPolicies,
            agentLocation,
            description,
            category
        );
        console.log("Registered sample agent with hash: ", dockerfileHash);

        vm.stopBroadcast();

        // Log final state
        console.log(
            "Total policies registered: ",
            policyRegistry.getAllPolicies().length
        );
        console.log(
            "Total agents registered: ",
            agentRegistry.getAgentCount()
        );
    }
}
