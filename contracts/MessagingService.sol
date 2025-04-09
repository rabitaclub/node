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
error InvalidKOLRegistryAddress();
error InvalidAddress();
error InvalidEncryptionProof();
error InvalidMessageHash();
error FeeTransferFailed();
error NoFeesAvailable();
error InvalidRefundPercentage();
error InvalidPayoutAmount();
error InvalidBatchSize(uint256 size);
error EmptyContent();
error InvalidPGPKey();
error InvalidMessageLength(uint256 length);
error InvalidFeeCalculation(uint256 expected, uint256 provided);

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
        bytes32 senderPGPPublicKeyHash;
        uint256 senderPGPNonce;
        uint256 version;
    }

    struct PayoutResult {
        uint256 platformFee;
        uint256 receiverAmount;
    }

    mapping(uint256 => Message) public messages;
    mapping(uint256 => MessageMetadata) public messageMetadata;
    mapping(address => uint256) public kolEarnedFees;
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
    address public devAddress;
    uint256 public timeoutRefundPercent = 45;

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
    event KOLPaid(address indexed kol, address indexed sender, uint256 amount);
    event DevAddressUpdated(address indexed oldDevAddress, address indexed newDevAddress);
    event FeesTransferred(uint256 amount, address devAddress);
    event RefundSent(address indexed receiver, uint256 amount);
    event ActivePairAdded(address indexed sender, address indexed kol);
    event ActivePairRemoved(address indexed sender, address indexed kol);
    event TimeoutRefundPercentUpdated(uint256 oldPercent, uint256 newPercent);

    constructor(address _kolRegistry, address _devAddress) Ownable(msg.sender) {
        if (_kolRegistry == address(0)) revert InvalidKOLRegistryAddress();
        if (_devAddress == address(0)) revert InvalidAddress();
        
        kolRegistry = IKOLRegistry(_kolRegistry);
        devAddress = _devAddress;
    }

    receive() external payable {}

    function setTimeoutRefundPercent(uint256 _percent) external onlyOwner {
        if (_percent > 100) revert InvalidRefundPercentage();
        
        uint256 oldPercent = timeoutRefundPercent;
        timeoutRefundPercent = _percent;
        
        emit TimeoutRefundPercentUpdated(oldPercent, _percent);
    }

    function setDevAddress(address _devAddress) external onlyOwner {
        if (_devAddress == address(0)) revert InvalidAddress();
        address oldDevAddress = devAddress;
        devAddress = _devAddress;
        emit DevAddressUpdated(oldDevAddress, _devAddress);
    }

    function _processPayout(
        uint256 amount,
        address receiver,
        address sender,
        bool isRefund
    ) internal returns (PayoutResult memory result) {
        if (amount == 0) revert InvalidPayoutAmount();

        if (isRefund) {
            result.receiverAmount = amount;
            result.platformFee = 0;
        } else {
            result.platformFee = (amount * PLATFORM_FEE_PERCENT) / 100;
            result.receiverAmount = amount - result.platformFee;
            
            if (result.receiverAmount > 0 && sender != address(0)) {
                kolEarnedFees[receiver] += result.receiverAmount;
            }
        }

        if (isRefund) {
            (bool sent, ) = receiver.call{value: amount}("");
            if (!sent) revert RefundTransferFailed();
            emit RefundSent(receiver, amount);
        } else {
            if (result.platformFee > 0) {
                (bool feeSent, ) = devAddress.call{value: result.platformFee}("");
                if (!feeSent) revert FeeTransferFailed();
                emit FeesTransferred(result.platformFee, devAddress);
            }
            
            if (result.receiverAmount > 0) {
                if (receiver == address(0)) revert InvalidAddress();
                (bool payoutSent, ) = receiver.call{value: result.receiverAmount}("");
                if (!payoutSent) revert PayoutToKOLFailed();
                
                if (sender != address(0)) {
                    emit KOLPaid(receiver, sender, result.receiverAmount);
                }
            }
        }
        
        return result;
    }

    function _calculateRespondPayout(uint256 baseFee)
        internal
        view
        returns (uint256 remainingFee)
    {
        uint256 minimumPayout = (baseFee * (100 - timeoutRefundPercent)) / 100;
        remainingFee = baseFee - minimumPayout;
        return remainingFee;
    }
    
    function _addActivePair(address sender, address kol) internal {
        if (!isActivePair[sender][kol]) {
            activeSenders.push(sender);
            activeKols.push(kol);
            activePairIndex[sender][kol] = activePairCount;
            isActivePair[sender][kol] = true;
            unchecked {
                activePairCount++;
            }
            
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
        if (_kol == address(0)) revert InvalidAddress();
        if (_senderPGPPublicKey.length == 0) revert InvalidPGPKey();
        if (bytes(content).length == 0) revert EmptyContent();
        
        (, , , , uint256 fee, , , , bool verified, ) = kolRegistry.kolProfiles(_kol);
        if (!verified) revert NotVerifiedKOL();
        if (msg.value != fee) revert IncorrectFeeAmount();

        unchecked {
            messageCount++;
        }
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
            senderPGPPublicKeyHash: keccak256(_senderPGPPublicKey),
            senderPGPNonce: _senderPGPNonce,
            version: 1
        });
        _addActivePair(msg.sender, _kol);
        uint256 minimumPayout = (fee * (100 - timeoutRefundPercent)) / 100;
        uint256 remainingFee = fee - minimumPayout;

        userToKolLatestMessage[msg.sender][_kol] = messageCount;
        userToKolFeesCollected[msg.sender][_kol] = remainingFee;
        _processPayout(minimumPayout, _kol, msg.sender, false);

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
        if (msg.sender != msgObj.kol) revert NotAuthorizedKOL();

        uint256 remainingFee = userToKolFeesCollected[_user][msgObj.kol];
        if (remainingFee > 0) {
            msgObj.status = MessageStatus.Responded;
            kolToUserLastReply[msgObj.kol][msgObj.sender] = block.timestamp;
            userToKolFeesCollected[_user][msgObj.kol] = 0;
            _removeActivePair(msgObj.sender, msgObj.kol);

            if (remainingFee > 0) {
                _processPayout(remainingFee, msgObj.kol, msgObj.sender, false);
            }
        }

        emit MessageSent(
            msgObj.kol,
            msgObj.sender,
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
        
        uint256 length = activePairCount;
        for (uint256 i; i < length && processedPairs < MAX_BATCH_SIZE;) {
            address sender = activeSenders[i];
            address kol = activeKols[i];
            
            uint256 fee = userToKolFeesCollected[sender][kol];
            
            if (fee > 0) {
                Message memory msgData = messages[userToKolLatestMessage[sender][kol]];
                
                if (kolToUserLastReply[kol][sender] < msgData.timestamp) {
                    processableSenders[processedPairs] = sender;
                    processableKols[processedPairs] = kol;
                    unchecked {
                        processedPairs++;
                    }
                    upkeepNeeded = true;
                }
            }
            
            unchecked {
                ++i;
            }
        }
        
        if (upkeepNeeded) {
            address[] memory resultSenders = new address[](processedPairs);
            address[] memory resultKols = new address[](processedPairs);
            
            for (uint256 i; i < processedPairs;) {
                resultSenders[i] = processableSenders[i];
                resultKols[i] = processableKols[i];
                unchecked {
                    ++i;
                }
            }
            
            performData = abi.encode(resultSenders, resultKols);
        }
    }

    function performUpkeep(bytes calldata performData) external {
        if (performData.length == 0) revert InvalidBatchSize(0);
        
        (address[] memory senders, address[] memory kols) = abi.decode(performData, (address[], address[]));
        if (senders.length != kols.length) revert InvalidBatchSize(senders.length);
        if (senders.length > MAX_BATCH_SIZE) revert InvalidBatchSize(senders.length);
        
        uint256 length = senders.length;
        for (uint256 i; i < length;) {
            address sender = senders[i];
            address kol = kols[i];
            
            uint256 fee = userToKolFeesCollected[sender][kol];
            if (fee > 0) {
                Message memory msgData = messages[userToKolLatestMessage[sender][kol]];
                
                if (kolToUserLastReply[kol][sender] < msgData.timestamp) {
                    triggerTimeout(sender, kol);
                }
            }
            
            unchecked {
                ++i;
            }
        }
    }

    function triggerTimeout(address sender, address kol) public nonReentrant {
        Message storage msgObj = messages[userToKolLatestMessage[sender][kol]];
        if (msgObj.status != MessageStatus.Pending) revert MessageNotPending();
        if (block.timestamp <= msgObj.deadline) revert DeadlineNotReached();

        uint256 remainingFee = userToKolFeesCollected[sender][kol];
        if (remainingFee == 0) revert NoFeesAvailable();

        msgObj.status = MessageStatus.Expired;
        userToKolLatestMessage[sender][kol] = 0;
        userToKolFeesCollected[sender][kol] = 0;
        _removeActivePair(sender, kol);
        _processPayout(remainingFee, sender, address(0), true);
        
        emit MessageTimeoutTriggered(userToKolLatestMessage[sender][kol]);
    }
    
    function getActivePairCount() external view returns (uint256) {
        return activePairCount;
    }
} 