// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";

import "../src/Faucet.sol";

contract FaucetDeploy is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("FAUCET_PRIV_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy Faucet contract
        Faucet faucet = new Faucet();

        // Fund the faucet with initial amount (0.1 ETH)
        (bool success, ) = address(faucet).call{value: 5 ether}("");
        require(success, "Initial funding failed");

        vm.stopBroadcast();

        console.log("Faucet deployed to:", address(faucet));
        console.log("Funded with: 5 ETH");
    }
}
