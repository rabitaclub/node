// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

interface IKOLRegistry {
    function kolProfiles(address)
        external
        view
        returns (
            address wallet,
            string memory socialPlatform,
            string memory socialHandle,
            uint256 fee,
            string memory profileIpfsHash,
            bool verified
        );
}

contract Messaging is ReentrancyGuard, Ownable {
    uint256 public constant MESSAGE_EXPIRATION = 7 days;
    uint256 public constant PLATFORM_FEE_PERCENT = 7;

    enum MessageStatus {
        Pending,
        Responded,
        Expired
    }

    struct Message {
        uint256 id;
        address sender;
        address kol;
        string messageIpfsHash;
        uint256 fee;
        uint256 timestamp;
        uint256 deadline;
        MessageStatus status;
    }

    uint256 public messageCount;
    mapping(uint256 => Message) public messages;
    uint256[] public pendingMessageIds;
    mapping(uint256 => uint256) public pendingMessageIndex;

    IKOLRegistry public kolRegistry;

    address public feeCollector;
    uint256 public accumulatedFees;

    uint256 public feeClaimDelay = 1 weeks;
    uint256 public lastFeeClaimTimestamp;

    event MessageSent(
        uint256 indexed messageId,
        address indexed sender,
        address indexed kol,
        uint256 fee,
        uint256 deadline,
        string messageIpfsHash
    );
    event MessageResponded(
        uint256 indexed messageId,
        address indexed kol,
        string responseIpfsHash
    );
    event MessageTimeoutTriggered(uint256 indexed messageId);
    event FeesClaimed(uint256 amount, uint256 timestamp);

    constructor(address _kolRegistry, address _feeCollector) Ownable(msg.sender) {
        require(_kolRegistry != address(0), "Invalid KOLRegistry address");
        require(_feeCollector != address(0), "Invalid feeCollector address");
        kolRegistry = IKOLRegistry(_kolRegistry);
        feeCollector = _feeCollector;
        lastFeeClaimTimestamp = block.timestamp;
    }

    receive() external payable {}

    function _calculateRespondPayout(uint256 baseFee)
        internal
        pure
        returns (uint256 platformFee, uint256 netPayout)
    {
        platformFee = (baseFee * PLATFORM_FEE_PERCENT) / 100;
        netPayout = baseFee - platformFee;
    }

    function _calculateTimeoutPayout(uint256 baseFee)
        internal
        pure
        returns (
            uint256 platformFee,
            uint256 netPayout,
            uint256 refundAmount
        )
    {
        refundAmount = baseFee / 2;
        uint256 halfFee = baseFee / 2;
        platformFee = (halfFee * PLATFORM_FEE_PERCENT) / 100;
        netPayout = halfFee - platformFee;
    }

    function sendMessage(address _kol, string memory _messageIpfsHash)
        external
        payable
        nonReentrant
    {
        (, , , uint256 fee, , bool verified) = kolRegistry.kolProfiles(_kol);
        require(verified, "Recipient is not a verified KOL");
        require(msg.value == fee, "Incorrect fee amount sent");

        messageCount += 1;
        uint256 deadline = block.timestamp + MESSAGE_EXPIRATION;

        messages[messageCount] = Message({
            id: messageCount,
            sender: msg.sender,
            kol: _kol,
            messageIpfsHash: _messageIpfsHash,
            fee: fee,
            timestamp: block.timestamp,
            deadline: deadline,
            status: MessageStatus.Pending
        });

        pendingMessageIds.push(messageCount);
        pendingMessageIndex[messageCount] = pendingMessageIds.length - 1;

        emit MessageSent(messageCount, msg.sender, _kol, fee, deadline, _messageIpfsHash);
    }

    function respondMessage(uint256 _messageId, string memory _responseIpfsHash)
        external
        nonReentrant
    {
        Message storage msgObj = messages[_messageId];
        require(msgObj.status == MessageStatus.Pending, "Message is not pending");
        require(msg.sender == msgObj.kol, "Only the intended KOL can respond");
        require(block.timestamp <= msgObj.deadline, "Deadline has passed");

        (uint256 platformFee, uint256 netPayout) = _calculateRespondPayout(msgObj.fee);

        msgObj.status = MessageStatus.Responded;
        _removePendingMessage(_messageId);

        accumulatedFees += platformFee;
        (bool payoutSent, ) = msgObj.kol.call{value: netPayout}("");
        require(payoutSent, "Payout to KOL failed");

        emit MessageResponded(_messageId, msg.sender, _responseIpfsHash);
    }

    function triggerTimeout(uint256 _messageId) public nonReentrant {
        Message storage msgObj = messages[_messageId];
        require(msgObj.status == MessageStatus.Pending, "Message is not pending");
        require(block.timestamp > msgObj.deadline, "Deadline not reached");

        msgObj.status = MessageStatus.Expired;
        _removePendingMessage(_messageId);

        (uint256 platformFee, uint256 netPayout, uint256 refundAmount) = _calculateTimeoutPayout(msgObj.fee);

        (bool refundSent, ) = msgObj.sender.call{value: refundAmount}("");
        require(refundSent, "Refund transfer failed");

        accumulatedFees += platformFee;
        (bool payoutSent, ) = msgObj.kol.call{value: netPayout}("");
        require(payoutSent, "Payout to KOL failed");

        emit MessageTimeoutTriggered(_messageId);
    }

    function _removePendingMessage(uint256 _messageId) internal {
        uint256 index = pendingMessageIndex[_messageId];
        uint256 lastIndex = pendingMessageIds.length - 1;
        if (index != lastIndex) {
            uint256 lastMessageId = pendingMessageIds[lastIndex];
            pendingMessageIds[index] = lastMessageId;
            pendingMessageIndex[lastMessageId] = index;
        }
        pendingMessageIds.pop();
        delete pendingMessageIndex[_messageId];
    }

    function checkUpkeep(bytes calldata checkData)
        external
        view
        returns (bool upkeepNeeded, bytes memory performData)
    {
        for (uint256 i = 0; i < pendingMessageIds.length; i++) {
            Message memory msgData = messages[pendingMessageIds[i]];
            if (msgData.status == MessageStatus.Pending && block.timestamp > msgData.deadline) {
                upkeepNeeded = true;
                performData = abi.encode(pendingMessageIds[i]);
                break;
            }
        }
    }

    function performUpkeep(bytes calldata performData) external {
        uint256 messageId = abi.decode(performData, (uint256));
        Message memory msgData = messages[messageId];
        if (msgData.status == MessageStatus.Pending && block.timestamp > msgData.deadline) {
            triggerTimeout(messageId);
        }
    }

    function claimFees() external nonReentrant {
        require(msg.sender == feeCollector, "Only fee collector can claim fees");
        require(block.timestamp >= lastFeeClaimTimestamp + feeClaimDelay, "Fee claim timelock active");
        require(accumulatedFees > 0, "No fees available");

        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        lastFeeClaimTimestamp = block.timestamp;

        (bool sent, ) = feeCollector.call{value: amount}("");
        require(sent, "Fee transfer failed");

        emit FeesClaimed(amount, block.timestamp);
    }
}
