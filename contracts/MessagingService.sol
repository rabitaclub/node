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
            string memory tags,
            string memory description,
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
    uint256 public constant MAX_BATCH_SIZE = 100;

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

    mapping(uint256 => Message) public messages;
    mapping(uint256 => MessageMetadata) public messageMetadata;    
    mapping(address => mapping(address => uint256)) public userToKolFeesCollected;
    mapping(address => mapping(address => uint256)) public userToKolLatestMessage;
    mapping(address => mapping(address => uint256)) public kolToUserLastReply;
    mapping(address => mapping(address => bool)) public isActivePair;
    mapping(address => mapping(address => uint256)) public activePairIndex;
    
    IKOLRegistry public kolRegistry;
    
    address[] public activeSenders;
    address[] public activeKols;
    uint256 public activePairCount;
    uint256 public messageCount;
    address public feeCollector;
    uint256 public accumulatedFees;
    uint256 public feeClaimDelay = 1 weeks;
    uint256 public lastFeeClaimTimestamp;

    event MessageSentToKOL(
        uint256 indexed messageId,
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
    event MessageSent(
        address indexed sender,
        address indexed receiver,
        string content
    );
    event MessageTimeoutTriggered(uint256 indexed messageId);
    event FeesClaimed(uint256 amount, uint256 timestamp);
    event ActivePairAdded(address indexed sender, address indexed kol);
    event ActivePairRemoved(address indexed sender, address indexed kol);

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
    
    function _addActivePair(address sender, address kol) internal {
        if (!isActivePair[sender][kol]) {
            activeSenders.push(sender);
            activeKols.push(kol);
            activePairIndex[sender][kol] = activePairCount;
            isActivePair[sender][kol] = true;
            activePairCount++;
            
            emit ActivePairAdded(sender, kol);
        }
    }
    
    function _removeActivePair(address sender, address kol) internal {
        if (isActivePair[sender][kol]) {
            uint256 index = activePairIndex[sender][kol];
            uint256 lastIndex = activePairCount - 1;
            
            if (index != lastIndex) {
                address lastSender = activeSenders[lastIndex];
                address lastKol = activeKols[lastIndex];
                
                activeSenders[index] = lastSender;
                activeKols[index] = lastKol;
                activePairIndex[lastSender][lastKol] = index;
            }
            
            activeSenders.pop();
            activeKols.pop();
            
            delete activePairIndex[sender][kol];
            isActivePair[sender][kol] = false;
            activePairCount--;
            
            emit ActivePairRemoved(sender, kol);
        }
    }

    function sendEncryptedMessage(
        address _kol,
        bytes memory _senderPGPPublicKey,
        uint256 _senderPGPNonce,
        string memory content
    ) external payable nonReentrant {
        (, , , , uint256 fee, , , , bool verified, ) = kolRegistry.kolProfiles(_kol);
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

        _addActivePair(msg.sender, _kol);
        
        userToKolLatestMessage[msg.sender][_kol] = messageCount;
        userToKolFeesCollected[msg.sender][_kol] += fee;

        emit MessageSentToKOL(
            messageCount,
            fee,
            deadline,
            content
        );
        emit MessageSent(
            msg.sender,
            _kol,
            content
        );
        emit SenderPGPUpdated(msg.sender, messageCount, _senderPGPPublicKey, _senderPGPNonce);
    }

    function respondToMessage(
        address _user,
        string memory content
    ) external nonReentrant {
        Message storage msgObj = messages[userToKolLatestMessage[_user][msg.sender]];
        // if (msgObj.status != MessageStatus.Pending) revert MessageNotPending();
        if (msg.sender != msgObj.kol) revert NotAuthorizedKOL();
        if (block.timestamp > msgObj.deadline) revert MessageDeadlinePassed();

        uint256 fee = userToKolFeesCollected[_user][msgObj.kol];

        if (fee != 0) {
            msgObj.status = MessageStatus.Responded;
            kolToUserLastReply[msgObj.kol][msgObj.sender] = block.timestamp;
            _removeActivePair(msgObj.sender, msgObj.kol);

            (uint256 platformFee, uint256 netPayout) = _calculateRespondPayout(fee);
            accumulatedFees += platformFee;
            (bool payoutSent, ) = msgObj.kol.call{value: netPayout}("");

            if (!payoutSent) revert PayoutToKOLFailed();
            userToKolLatestMessage[_user][msgObj.kol] = 0;
            userToKolFeesCollected[_user][msgObj.kol] = 0;
        }


        emit MessageSent(
            msgObj.sender,
            msgObj.kol,
            content
        );
    }

    function checkUpkeep(bytes calldata checkData)
        external
        view
        returns (bool upkeepNeeded, bytes memory performData)
    {
        uint256 processedPairs = 0;
        
        address[] memory processableSenders = new address[](MAX_BATCH_SIZE);
        address[] memory processableKols = new address[](MAX_BATCH_SIZE);
        
        for (uint256 i = 0; i < activePairCount && processedPairs < MAX_BATCH_SIZE; i++) {
            address sender = activeSenders[i];
            address kol = activeKols[i];
            
            uint256 fee = userToKolFeesCollected[sender][kol];
            
            if (fee == 0) continue;
            
            Message memory msgData = messages[userToKolLatestMessage[sender][kol]];
            
            if (kolToUserLastReply[kol][sender] < msgData.timestamp) {
                processableSenders[processedPairs] = sender;
                processableKols[processedPairs] = kol;
                processedPairs++;
                upkeepNeeded = true;
            }
        }
        
        if (upkeepNeeded) {
            address[] memory resultSenders = new address[](processedPairs);
            address[] memory resultKols = new address[](processedPairs);
            
            for (uint256 i = 0; i < processedPairs; i++) {
                resultSenders[i] = processableSenders[i];
                resultKols[i] = processableKols[i];
            }
            
            performData = abi.encode(resultSenders, resultKols);
        }
    }

    function performUpkeep(bytes calldata performData) external {
        (address[] memory senders, address[] memory kols) = abi.decode(performData, (address[], address[]));
        
        for (uint256 i = 0; i < senders.length; i++) {
            address sender = senders[i];
            address kol = kols[i];
            
            uint256 fee = userToKolFeesCollected[sender][kol];
            if (fee == 0) continue;
            
            Message memory msgData = messages[userToKolLatestMessage[sender][kol]];
            
            if (kolToUserLastReply[kol][sender] < msgData.timestamp) {
                triggerTimeout(sender, kol);
            }
        }
    }

    function triggerTimeout(address sender, address kol) public nonReentrant {
        Message storage msgObj = messages[userToKolLatestMessage[sender][kol]];
        if (msgObj.status != MessageStatus.Pending) revert MessageNotPending();
        if (block.timestamp <= msgObj.deadline) revert DeadlineNotReached();

        uint256 fee = userToKolFeesCollected[sender][kol];
        if (fee == 0) revert NoFeesAvailable();

        msgObj.status = MessageStatus.Expired;
        _removeActivePair(sender, kol);
        
        (uint256 platformFee, uint256 netPayout, uint256 refundAmount) = _calculateTimeoutPayout(fee);
        (bool refundSent, ) = sender.call{value: refundAmount}("");
        if (!refundSent) revert RefundTransferFailed();
        accumulatedFees += platformFee;
        (bool payoutSent, ) = kol.call{value: netPayout}("");
        if (!payoutSent) revert PayoutToKOLFailed();

        userToKolLatestMessage[sender][kol] = 0;
        userToKolFeesCollected[sender][kol] = 0;
        
        emit MessageTimeoutTriggered(userToKolLatestMessage[sender][kol]);
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
    
    function getActivePairCount() external view returns (uint256) {
        return activePairCount;
    }
} 