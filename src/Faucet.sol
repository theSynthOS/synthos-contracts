// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin-contracts-5.2.0/utils/ReentrancyGuard.sol";
import "@openzeppelin-contracts-5.2.0/access/Ownable.sol";

contract Faucet is ReentrancyGuard, Ownable {
    // Maximum amount that can be requested (0.01 ETH)
    uint256 public constant MAX_DRIP = 0.01 ether;

    // Lockdown period of 24 hours in seconds
    uint256 public constant LOCKDOWN_PERIOD = 24 hours;

    // Mapping to track last drip timestamp for each address
    mapping(address => uint256) public lastDripTimestamp;

    // Event emitted when drip is successful
    event Dripped(address indexed recipient, uint256 amount, uint256 timestamp);

    // Event emitted when faucet is funded
    event FaucetFunded(address indexed funder, uint256 amount);

    constructor() Ownable(msg.sender) {}

    /**
     * @notice Request ETH from the faucet
     * @dev Implements nonReentrant modifier to prevent reentrancy attacks
     */
    function requestDrip() external nonReentrant {
        // Check if the sender is eligible for a new drip
        require(
            block.timestamp >= lastDripTimestamp[msg.sender] + LOCKDOWN_PERIOD,
            "Faucet: Please wait for lockdown period to end"
        );

        // Check if the contract has enough balance
        require(
            address(this).balance >= MAX_DRIP,
            "Faucet: Insufficient faucet balance"
        );

        // Update the last drip timestamp before transfer
        lastDripTimestamp[msg.sender] = block.timestamp;

        // Transfer ETH to the requester
        (bool success, ) = payable(msg.sender).call{value: MAX_DRIP}("");
        require(success, "Faucet: Transfer failed");

        emit Dripped(msg.sender, MAX_DRIP, block.timestamp);
    }

    /**
     * @notice Check time remaining until next drip is available
     * @param _address Address to check
     * @return Time in seconds until next drip is available (0 if available now)
     */
    function timeUntilNextDrip(
        address _address
    ) external view returns (uint256) {
        uint256 lastDrip = lastDripTimestamp[_address];
        if (lastDrip == 0 || block.timestamp >= lastDrip + LOCKDOWN_PERIOD) {
            return 0;
        }
        return (lastDrip + LOCKDOWN_PERIOD) - block.timestamp;
    }

    /**
     * @notice Fund the faucet
     */
    function fundFaucet() external payable {
        require(msg.value > 0, "Faucet: Must send ETH");
        emit FaucetFunded(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw funds from the faucet (only owner)
     * @param _amount Amount to withdraw
     */
    function withdraw(uint256 _amount) external onlyOwner {
        require(
            _amount <= address(this).balance,
            "Faucet: Insufficient balance"
        );
        (bool success, ) = payable(owner()).call{value: _amount}("");
        require(success, "Faucet: Withdrawal failed");
    }

    /**
     * @notice Get faucet balance
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    // Allow contract to receive ETH
    receive() external payable {
        emit FaucetFunded(msg.sender, msg.value);
    }
}
