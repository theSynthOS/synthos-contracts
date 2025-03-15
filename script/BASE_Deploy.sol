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

interface IGovernance {
    function transferAvsGovernanceMultisig(
        address _newAvsGovernanceMultisig
    ) external;
}

contract DeployScript is Script {
    function run() external {
        uint256 privKey = vm.envUint("PRIV_KEY");
        address deployer = vm.rememberKey(privKey);

        address ATTESTATION_CENTER = 0xcE2c6cd7ab51837E6F0f2313D45D443F79097Dd5;
        address BASE_HYPERLANE_MAILBOX = 0x6966b0E55883d49BFB24539356a2f8A673E02039;
        address SCROLL_POLICY_COORDINATOR = 0x2e22Bc79b58117015bF458045488E09aaa0bB794;
        uint32 SCROLL_DOMAIN_ID = 534351;

        console.log("Deployer: ", deployer);
        console.log("Deployer Nonce: ", vm.getNonce(deployer));

        vm.startBroadcast(deployer);

        // 1. Deploy CrosschainSender
        CrosschainSender crosschainSender = new CrosschainSender(
            BASE_HYPERLANE_MAILBOX,
            SCROLL_DOMAIN_ID,
            SCROLL_POLICY_COORDINATOR,
            ATTESTATION_CENTER
        );

        // 2. Send ETH to the contract to cover Hyperlane fees
        (bool success, ) = address(crosschainSender).call{value: 0.01 ether}(
            ""
        );
        require(success, "Failed to fund CrosschainSender");

        // 3. Register CrosschainSender with AttestationCenter
        IAttestationCenter(ATTESTATION_CENTER).setAvsLogic(
            address(crosschainSender)
        );

        // 4. Test CrosschainSender
        // Create the task data using abi.encode
        bytes memory taskData = abi.encode(
            bytes32(
                0x21dcb7f000000000000000000000000000000000000000000000000000000000
            ), // txUUID
            uint256(0), // agentId
            uint256(1741979632561), // timestamp
            "APPROVED", // status
            "Policy 'AAVE Complete AVS Plugin' authorized transaction" // reason
        );

        // Create the TaskInfo struct
        IAttestationCenter.TaskInfo memory taskInfo = IAttestationCenter
            .TaskInfo({
                proofOfTask: "QmZkk2Y7c9A9wKoWh3FGRPSRkfZPvEmRnnC5DuqHHESpBb",
                data: taskData,
                taskPerformer: address(0),
                taskDefinitionId: 0
            });

        // 5. Test CrosschainSender with real data
        crosschainSender.afterTaskSubmission(
            taskInfo,
            true,
            bytes("0x"),
            [uint256(1), uint256(2)],
            new uint256[](0)
        );

        vm.stopBroadcast();

        // Log final state
        console.log(
            "CrosschainSender deployed at: ",
            address(crosschainSender)
        );
    }
}
