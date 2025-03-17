// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {Test, console} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {AgentRegistry} from "../src/AgentRegistry.sol";
import {PolicyCoordinator} from "../src/PolicyCoordinator.sol";
import {CrosschainSender} from "../src/CrosschainSender.sol";
import {IAttestationCenter} from "../src/interfaces/IAttestationCenter.sol";
import {IAvsLogic} from "../src/interfaces/IAvsLogic.sol";
import {ITaskRegistry} from "../src/interfaces/ITaskRegistry.sol";

contract DeployScript is Script {
    function run() external {
        uint256 privKey = vm.envUint("PRIV_KEY");
        address deployer = vm.rememberKey(privKey);

        address SCROLL_HYPERLANE_MAILBOX = 0x3C5154a193D6e2955650f9305c8d80c18C814A68;
        uint32 BASE_DOMAIN_ID = 84532;
        address TASK_REGISTRY = 0x5e38f31693CcAcFCA4D8b70882d8b696cDc24273;

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
            address(policyRegistry),
            TASK_REGISTRY,
            SCROLL_HYPERLANE_MAILBOX,
            BASE_DOMAIN_ID
        );
        console.log(
            "PolicyCoordinator deployed at: ",
            address(policyCoordinator)
        );

        // 4. Register AAVE policy with support for Supply, Withdraw, Borrow, Repay and Deposit
        bytes4[] memory allowedFunctions = new bytes4[](15);
        // Supply
        allowedFunctions[0] = 0x617ba037;
        allowedFunctions[1] = 0xf7a73840;
        allowedFunctions[2] = 0x02c205f0;
        allowedFunctions[3] = 0x680dd47c;
        // Borrow
        allowedFunctions[4] = 0xa415bcad;
        allowedFunctions[5] = 0xd5eed868;
        // Repay
        allowedFunctions[6] = 0x563dd613;
        allowedFunctions[7] = 0x573ade81;
        allowedFunctions[8] = 0x2dad97d4;
        allowedFunctions[9] = 0xdc7c0bff;
        allowedFunctions[10] = 0x94b576de;
        allowedFunctions[11] = 0xee3e210b;
        // Withdraw
        allowedFunctions[12] = 0x69328dec;
        allowedFunctions[13] = 0x8e19899e;
        // Deposit
        allowedFunctions[14] = 0xe8eda9df;

        address[] memory allowedContracts = new address[](2);
        allowedContracts[0] = 0x48914C788295b5db23aF2b5F0B3BE775C4eA9440;
        allowedContracts[1] = 0xB186894F315133C2396104CAb386C3A0fEC09025;

        uint256 policyId = policyRegistry.registerPolicy(
            "AAVE Complete AVS Plugin",
            "This plugin allows for the supply, borrow, repay, withdraw and deposit actions to be done for the Scroll AAVE Market",
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

        // 6. Register 2 task in the task registry, one invalid and one valid
        ITaskRegistry taskRegistry = ITaskRegistry(TASK_REGISTRY);
        taskRegistry.registerTask(
            "6e9a7ddb-679d-478e-a3d0-9de372857884",
            0x07eA79F68B2B3df564D0A34F8e19D9B1e339814b,
            hex"a415bcad000000000000000000000000036cbd53842c5426634e7929541ec2318f3dcf7e0000000000000000000000000000000000000000000000000000000014dc938000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000eb0d8736cc2c47882f112507cc8a3355d37d2413"
        );
        taskRegistry.registerTask(
            "6e9a7ddb-679d-478e-a3d0-9de372857885",
            0x48914C788295b5db23aF2b5F0B3BE775C4eA9440,
            hex"e8eda9df000000000000000000000000eb0d8736cc2c47882f112507cc8a3355d37d2413000000000000000000000000000000000000000000000000000000e8d4a51000000000000000000000000000eb0d8736cc2c47882f112507cc8a3355d37d24130000000000000000000000000000000000000000000000000000000000000000"
        );

        vm.stopBroadcast();

        // Log final state
        console.log(
            "Total policies registered: ",
            policyRegistry.getAllPolicyIds().length
        );
        console.log("Total agents registered: ", agentRegistry.getAgentCount());
    }
}
