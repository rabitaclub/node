// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

interface IKOLRegistry {
    function kolProfiles(address)
        external
        view
        returns (
            address wallet,
            string memory socialPlatform,
            string memory socialHandle,
            string memory socialName,
            uint256 fee,
            string memory profileIpfsHash,
            bool verified,
            uint256 registeredAt
        );
    function pgpPublicKeys(address) external view returns (bytes memory);
    function pgpNonce(address) external view returns (uint256);
}

error NotVerifiedKOL();
error IncorrectFeeAmount();
error MessageNotPending();
error NotAuthorizedKOL();
error MessageDeadlinePassed();
error DeadlineNotReached();
error PayoutToKOLFailed();
error RefundTransferFailed();
error NotFeeCollector();
error FeeClaimTimelockActive();
error NoFeesAvailable();
error FeeTransferFailed();
error InvalidKOLRegistryAddress();
error InvalidFeeCollectorAddress();
error InvalidEncryptionProof();
error InvalidMessageHash();

contract RabitaMessaging is ReentrancyGuard, Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

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
        uint256 fee;
        uint256 timestamp;
        uint256 deadline;
        string content;
        MessageStatus status;
    }

    struct MessageMetadata {
        bytes senderPGPPublicKey;
        uint256 senderPGPNonce;
        uint256 version;
    }

    uint256 public messageCount;
    mapping(uint256 => Message) public messages;
    mapping(uint256 => MessageMetadata) public messageMetadata;
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
        string content
    );
    event SenderPGPUpdated(
        address indexed sender,
        uint256 indexed messageId,
        bytes pgpPublicKey,
        uint256 pgpNonce
    );
    event MessageResponded(
        uint256 indexed messageId,
        address indexed kol,
        string content
    );
    event MessageTimeoutTriggered(uint256 indexed messageId);
    event FeesClaimed(uint256 amount, uint256 timestamp);

    constructor(address _kolRegistry, address _feeCollector) Ownable(msg.sender) {
        if (_kolRegistry == address(0)) revert InvalidKOLRegistryAddress();
        if (_feeCollector == address(0)) revert InvalidFeeCollectorAddress();
        
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

    function sendEncryptedMessage(
        address _kol,
        bytes memory _senderPGPPublicKey,
        uint256 _senderPGPNonce,
        string memory content
    ) external payable nonReentrant {
        (, , , , uint256 fee, , bool verified, ) = kolRegistry.kolProfiles(_kol);
        if (!verified) revert NotVerifiedKOL();
        if (msg.value != fee) revert IncorrectFeeAmount();

        messageCount += 1;
        uint256 deadline = block.timestamp + MESSAGE_EXPIRATION;

        messages[messageCount] = Message({
            id: messageCount,
            sender: msg.sender,
            kol: _kol,
            fee: fee,
            timestamp: block.timestamp,
            deadline: deadline,
            content: content,
            status: MessageStatus.Pending
        });

        messageMetadata[messageCount] = MessageMetadata({
            senderPGPPublicKey: _senderPGPPublicKey,
            senderPGPNonce: _senderPGPNonce,
            version: 1
        });

        pendingMessageIds.push(messageCount);
        pendingMessageIndex[messageCount] = pendingMessageIds.length - 1;

        emit MessageSent(
            messageCount,
            msg.sender,
            _kol,
            fee,
            deadline,
            content
        );
        emit SenderPGPUpdated(msg.sender, messageCount, _senderPGPPublicKey, _senderPGPNonce);
    }

    function respondToEncryptedMessage(
        uint256 _messageId,
        string memory content
    ) external nonReentrant {
        Message storage msgObj = messages[_messageId];
        if (msgObj.status != MessageStatus.Pending) revert MessageNotPending();
        if (msg.sender != msgObj.kol) revert NotAuthorizedKOL();
        if (block.timestamp > msgObj.deadline) revert MessageDeadlinePassed();

        (uint256 platformFee, uint256 netPayout) = _calculateRespondPayout(msgObj.fee);

        msgObj.status = MessageStatus.Responded;
        _removePendingMessage(_messageId);

        accumulatedFees += platformFee;
        (bool payoutSent, ) = msgObj.kol.call{value: netPayout}("");
        if (!payoutSent) revert PayoutToKOLFailed();

        emit MessageResponded(_messageId, msg.sender, content);
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

    function triggerTimeout(uint256 _messageId) public nonReentrant {
        Message storage msgObj = messages[_messageId];
        if (msgObj.status != MessageStatus.Pending) revert MessageNotPending();
        if (block.timestamp <= msgObj.deadline) revert DeadlineNotReached();

        msgObj.status = MessageStatus.Expired;
        _removePendingMessage(_messageId);

        (uint256 platformFee, uint256 netPayout, uint256 refundAmount) = _calculateTimeoutPayout(msgObj.fee);

        (bool refundSent, ) = msgObj.sender.call{value: refundAmount}("");
        if (!refundSent) revert RefundTransferFailed();

        accumulatedFees += platformFee;
        (bool payoutSent, ) = msgObj.kol.call{value: netPayout}("");
        if (!payoutSent) revert PayoutToKOLFailed();

        emit MessageTimeoutTriggered(_messageId);
    }

    function claimFees() external nonReentrant {
        if (msg.sender != feeCollector) revert NotFeeCollector();
        if (block.timestamp < lastFeeClaimTimestamp + feeClaimDelay) revert FeeClaimTimelockActive();
        if (accumulatedFees == 0) revert NoFeesAvailable();

        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        lastFeeClaimTimestamp = block.timestamp;

        (bool sent, ) = feeCollector.call{value: amount}("");
        if (!sent) revert FeeTransferFailed();

        emit FeesClaimed(amount, block.timestamp);
    }
} 