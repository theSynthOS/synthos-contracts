// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IMailbox} from "hyperlane-core-v5.0.0/contracts/interfaces/IMailbox.sol";
import {TypeCasts} from "hyperlane-core-v5.0.0/contracts/libs/TypeCasts.sol";
import {IAvsLogic} from "./interfaces/IAvsLogic.sol";
import {IAttestationCenter} from "./interfaces/IAttestationCenter.sol";

/**
 * @title CrosschainSender
 * @author SynthOS - Verifiable DeFAI Agent Marketplace
 * @notice Acts as AVS Logic hook to forward task validation data to Scroll
 */
contract CrosschainSender is IAvsLogic {
    using TypeCasts for address;

    // Hyperlane mailbox contract
    IMailbox public immutable mailbox;

    // Destination chain ID (Scroll)
    uint32 public immutable destinationDomain;

    // PolicyCoordinator address on Scroll
    address public immutable policyCoordinator;

    // Attestation Center that can call hooks
    address public immutable attestationCenter;

    event CrosschainTaskDataSent(
        string proofOfTask,
        bytes taskData,
        uint256 taskDefinitionId
    );

    error UnauthorizedCaller();

    constructor(
        address _mailbox,
        uint32 _destinationDomain,
        address _policyCoordinator,
        address _attestationCenter
    ) {
        mailbox = IMailbox(_mailbox);
        destinationDomain = _destinationDomain;
        policyCoordinator = _policyCoordinator;
        attestationCenter = _attestationCenter;
    }

    /**
     * @notice Process task after submission and forward to Scroll
     * @dev Forwards the entire task data as received
     */
    function afterTaskSubmission(
        IAttestationCenter.TaskInfo calldata _taskInfo,
        bool _isApproved,
        bytes calldata _tpSignature,
        uint256[2] calldata _taSignature,
        uint256[] calldata _attestersIds
    ) external payable override {
        if (!_isApproved) return; // Only process approved tasks

        // Forward the entire task data to Scroll
        string memory proofOfTask = string(_taskInfo.proofOfTask);
        bytes memory message = abi.encode(
            proofOfTask,
            _taskInfo.data,
            _taskInfo.taskDefinitionId
        );

        uint256 fee = mailbox.quoteDispatch(
            destinationDomain,
            policyCoordinator.addressToBytes32(),
            message
        );

        require(
            address(this).balance >= fee,
            "Insufficient funds for cross-chain message"
        );

        uint256 messageId = uint256(
            mailbox.dispatch{value: fee}(
                destinationDomain,
                policyCoordinator.addressToBytes32(),
                message
            )
        );

        emit CrosschainTaskDataSent(
            proofOfTask,
            _taskInfo.data,
            _taskInfo.taskDefinitionId
        );
    }

    /**
     * @notice No-op for beforeTaskSubmission hook
     */
    function beforeTaskSubmission(
        IAttestationCenter.TaskInfo calldata,
        bool,
        bytes calldata,
        uint256[2] calldata,
        uint256[] calldata
    ) external pure override {}

    // Allow contract to receive ETH for Hyperlane fees
    receive() external payable {}
}
