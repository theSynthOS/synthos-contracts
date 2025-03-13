// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {Test, console} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {AgentRegistry} from "../src/AgentRegistry.sol";
import {PolicyCoordinator} from "../src/PolicyCoordinator.sol";

contract DeployScript is Script {
    function run() external {
        uint256 privKey = vm.envUint("PRIV_KEY");
        address deployer = vm.rememberKey(privKey);

        console.log("Deployer: ", deployer);
        console.log("Deployer Nonce: ", vm.getNonce(deployer));

        vm.startBroadcast(deployer);

        // 1. Deploy PolicyRegistry first
        PolicyRegistry policyRegistry = new PolicyRegistry();
        console.log("PolicyRegistry deployed at: ", address(policyRegistry));

        // 2. Deploy AgentRegistry with PolicyRegistry address
        AgentRegistry agentRegistry = new AgentRegistry(
            address(policyRegistry)
        );
        console.log("AgentRegistry deployed at: ", address(agentRegistry));

        // 3. Deploy PolicyCoordinator with both registries
        PolicyCoordinator policyCoordinator = new PolicyCoordinator(
            address(agentRegistry),
            address(policyRegistry)
        );
        console.log(
            "PolicyCoordinator deployed at: ",
            address(policyCoordinator)
        );

        // 4. Register AAVE policy
        bytes4[] memory allowedFunctions = new bytes4[](4);
        allowedFunctions[0] = 0x617ba037;
        allowedFunctions[1] = 0xf7a73840;
        allowedFunctions[2] = 0x02c205f0;
        allowedFunctions[3] = 0x680dd47c;

        address[] memory allowedContracts = new address[](1);
        allowedContracts[0] = 0x48914C788295b5db23aF2b5F0B3BE775C4eA9440;

        uint256 policyId = policyRegistry.registerPolicy(
            "AAVE Supply AVS Plugin",
            "This plugin allows for the supply actions to be done for the Scroll AAVE Market",
            0, // no start time
            0, // no end time
            allowedFunctions,
            allowedContracts
        );
        console.log("Registered AAVE policy with ID: ", policyId);

        // 5. Register agent with the AAVE policy
        string
            memory dockerfileHash = "d8bfaebbd824a94fb487216736378993ef6ec13339b4100a2b9a05e9236c8622";
        uint256 executionFee = 0.001 ether;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        string
            memory agentLocation = "https://autonome.alt.technology/synthos-arimua/ed9ddab6-6713-055c-bca6-3390aee6bf72/message";
        string
            memory description = "The first Verifiable AAVE DeFAI Agent on Scroll";
        AgentRegistry.AgentCategory category = AgentRegistry.AgentCategory.DeFi;

        agentRegistry.registerAgent(
            dockerfileHash,
            executionFee,
            policyIds,
            agentLocation,
            description,
            category
        );
        console.log("Registered AAVE agent with hash: ", dockerfileHash);

        vm.stopBroadcast();

        // Log final state
        console.log(
            "Total policies registered: ",
            policyRegistry.getAllPolicyIds().length
        );
        console.log("Total agents registered: ", agentRegistry.getAgentCount());
    }
}
