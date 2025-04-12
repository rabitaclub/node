// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title RabitaRegistry
 * @dev Registry for Key Opinion Leaders (KOLs) with EIP-712 signature verification
 */
contract RabitaRegistry is Ownable, EIP712, ReentrancyGuard {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    enum DAYS {
        MONDAY,
        TUESDAY,
        WEDNESDAY,
        THURSDAY,
        FRIDAY,
        SATURDAY,
        SUNDAY
    }
    struct KOLProfile {
        address wallet;
        string socialPlatform;
        string socialHandle;
        string socialName;
        uint256 fee;
        string profileIpfsHash;
        string tags;
        string description;
        bool verified;
        uint256 registeredAt;
    }

    mapping(address => KOLProfile) public kolProfiles;
    mapping(address => mapping(DAYS => bool)) public kolActiveDays;
    mapping(address => uint256) public kolActiveTime;
    mapping(address => uint256) public kolInactiveTime;

    mapping(string => mapping(string => KOLProfile)) public socialHandleToKOLProfile;
    mapping(bytes32 => bool) public usedNonces;
    mapping(address => bool) public isVerifier;
    mapping(address => bytes) public pgpPublicKeys;
    mapping(address => uint256) public pgpNonce;

    string private constant DOMAIN_NAME = "Rabita Social Verification";
    string private constant DOMAIN_VERSION = "1";
    
    bytes32 private constant VERIFIER_TYPEHASH = keccak256(
        "VerifierData(address walletAddress,string twitterUsername,bytes32 salt,string platform,bytes16 nonce,uint256 timestamp,string domain,uint256 expiresAt)"
    );
    
    bytes32 private constant USER_TYPEHASH = keccak256(
        "SocialVerification(address walletAddress,string platform,string username,bytes32 salt,bytes16 nonce,uint256 timestamp,string domain,uint256 expiresAt,bytes signature)"
    );

    bytes32 private constant PGP_TYPEHASH = keccak256(
        "PGPSignature(address walletAddress,bytes pgpPublicKey,uint256 pgpNonce)"
    );

    bytes32 public domainSeparatorV4;

    event KOLRegistered(
        address indexed wallet,
        string platform,
        string handle,
        string name,
        uint256 fee
    );
    event KOLData(
        address indexed wallet,
        string profileIpfsHash,
        string tags,
        string description
    );
    event PGPKeyUpdated(address indexed wallet, bytes pgpPublicKey, uint pgpNonce);
    event KOLFeeUpdated(address indexed wallet, uint256 fee);

    event KOLActiveDaysUpdated(address indexed wallet, DAYS day, bool active);
    event KOLActiveTimeUpdated(address indexed wallet, uint256 startTime, uint256 endTime);
    event KOLInactiveTimeUpdated(address indexed wallet, uint256 startTime, uint256 endTime);

    event VerifierAdded(address indexed verifier);
    event VerifierRemoved(address indexed verifier);
    event KOLUnregistered(address indexed wallet);
    
    constructor(address _verifier) Ownable(msg.sender) EIP712(DOMAIN_NAME, DOMAIN_VERSION) {
        require(_verifier != address(0), "Invalid verifier address");
        isVerifier[_verifier] = true;
        domainSeparatorV4 = _domainSeparatorV4();
        emit VerifierAdded(_verifier);
    }

    function verifyVerifierSignature(
        address _wallet,
        string memory _twitterUsername,
        bytes32 _salt,
        string memory _platform,
        bytes16 _nonce,
        uint256 _timestamp,
        string memory _domain,
        uint256 _expiresAt,
        bytes memory _verifierSignature
    ) internal view returns (bool, address) {
        bytes32 verifierHash = keccak256(abi.encode(
            _wallet,
            _twitterUsername,
            _salt,
            _platform,
            _nonce,
            _timestamp,
            _domain,
            _expiresAt
        ));

        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(verifierHash);
        address recoveredVerifier = ECDSA.recover(ethSignedMessageHash, _verifierSignature);
        return (isVerifier[recoveredVerifier], recoveredVerifier);
    }

    function verifyUserSignature(
        address _wallet,
        string memory _platform,
        string memory _username,
        bytes32 _salt,
        bytes16 _nonce,
        uint256 _timestamp,
        string memory _domain,
        uint256 _expiresAt,
        bytes memory _verifierSignature,
        bytes memory _userSignature
    ) internal view returns (bool, address) {
        bytes32 structHash = keccak256(abi.encode(
            USER_TYPEHASH,
            _wallet,
            keccak256(abi.encodePacked(_platform)),
            keccak256(abi.encodePacked(_username)),
            _salt,
            _nonce,
            _timestamp,
            keccak256(abi.encodePacked(_domain)),
            _expiresAt,
            keccak256(abi.encodePacked(_verifierSignature))
        ));
        
        bytes32 digest = _hashTypedDataV4(structHash);
        address recoveredUser = ECDSA.recover(digest, _userSignature);
        
        return ((recoveredUser == _wallet), recoveredUser);
    }

    function verifyPGPSignature(
        address _wallet,
        bytes memory _pgpPublicKey,
        uint256 _pgpNonce,
        bytes memory _pgpSignature
    ) internal view returns (bool, address) {
        bytes32 pgpHash = keccak256(abi.encodePacked(
            PGP_TYPEHASH,
            _wallet,
            _pgpPublicKey,
            _pgpNonce
        ));
        
        bytes32 digest = _hashTypedDataV4(pgpHash);
        address recoveredPGP = ECDSA.recover(digest, _pgpSignature);
        return (recoveredPGP == _wallet, recoveredPGP);
    }

    function registerKOL(
        // Social media data
        string memory _platform,
        string memory _username,
        string memory _name,
        // KOL data
        uint256 _fee,
        string memory _profileIpfsHash,
        string memory _tags,
        string memory _description,
        // Verification data
        bytes32 _salt,
        bytes16 _nonce,
        uint256 _timestamp,
        string memory _domain,
        uint256 _expiresAt,
        // Signatures
        bytes memory _verifierSignature,
        bytes memory _userSignature,
        bytes memory _pgpPublicKey
    ) external nonReentrant {
        require(!kolProfiles[msg.sender].verified, "KOL already registered");
        require(socialHandleToKOLProfile[_platform][_username].wallet == address(0), "Social handle already registered");
        require(block.timestamp < _expiresAt, "Verification expired");
        
        bytes32 compositeNonce = keccak256(abi.encodePacked(
            msg.sender,
            _username,
            _nonce,
            _timestamp
        ));
        require(!usedNonces[compositeNonce], "Nonce already used");

        (bool isVerifierValid, ) = verifyVerifierSignature(
            msg.sender, 
            _username, 
            _salt, 
            _platform, 
            _nonce, 
            _timestamp, 
            _domain, 
            _expiresAt, 
            _verifierSignature
        );
        require(isVerifierValid, "Invalid verifier signature");
        
        (bool isUserSignatureValid, ) = verifyUserSignature(
            msg.sender,
            _platform,
            _username,
            _salt,
            _nonce,
            _timestamp,
            _domain,
            _expiresAt,
            _verifierSignature,
            _userSignature
        );
        
        require(isUserSignatureValid, "Invalid user signature");
        
        usedNonces[compositeNonce] = true;
        
        kolProfiles[msg.sender] = KOLProfile({
            wallet: msg.sender,
            socialPlatform: _platform,
            socialHandle: _username,
            socialName: _name,
            fee: _fee,
            profileIpfsHash: _profileIpfsHash,
            tags: _tags,
            description: _description,
            verified: true,
            registeredAt: block.timestamp
        });

        pgpPublicKeys[msg.sender] = _pgpPublicKey;
        pgpNonce[msg.sender]++;
        
        socialHandleToKOLProfile[_platform][_username] = kolProfiles[msg.sender];
        setAllActiveDays();
        setDefaultTimeSlot();
        
        emit KOLRegistered(msg.sender, _platform, _username, _name, _fee);
        emit PGPKeyUpdated(msg.sender, _pgpPublicKey, pgpNonce[msg.sender]);
        emit KOLData(msg.sender, _profileIpfsHash, _tags, _description);
    }

    function setAllActiveDays() internal {
        for (uint256 i = 0; i < 7; i++) {
            kolActiveDays[msg.sender][DAYS(i)] = true;
            emit KOLActiveDaysUpdated(msg.sender, DAYS(i), true);
        }
    }

    function setDefaultTimeSlot() internal {
        kolActiveTime[msg.sender] = 0;
        kolInactiveTime[msg.sender] = 86399;
        emit KOLActiveTimeUpdated(msg.sender, 0, 86399);
        emit KOLInactiveTimeUpdated(msg.sender, 0, 86399);
    }

    function isSocialHandleRegistered(string memory _platform, string memory _handle) external view returns (bool) {
        return socialHandleToKOLProfile[_platform][_handle].wallet != address(0);
    }
    
    function getKOLAddressBySocialHandle(string memory _platform, string memory _handle) external view returns (address) {
        return socialHandleToKOLProfile[_platform][_handle].wallet;
    }

    function updateVerifier(address _verifier) external onlyOwner {
        require(_verifier != address(0), "Invalid verifier address");
        isVerifier[_verifier] = true;
        emit VerifierAdded(_verifier);
    }

    function removeVerifier(address _verifier) external onlyOwner {
        require(_verifier != address(0), "Invalid verifier address");
        isVerifier[_verifier] = false;
        emit VerifierRemoved(_verifier);
    }

    function updatePGPKey(bytes memory _pgpPublicKey, bytes memory _pgpSignature) external nonReentrant {
        require(kolProfiles[msg.sender].verified, "KOL not registered");
        pgpPublicKeys[msg.sender] = _pgpPublicKey;
        pgpNonce[msg.sender]++;

        (bool isPGPSignatureValid, ) = verifyPGPSignature(
            msg.sender,
            _pgpPublicKey,
            pgpNonce[msg.sender],
            _pgpSignature
        );
        require(isPGPSignatureValid, "Invalid PGP signature");
        emit PGPKeyUpdated(msg.sender, _pgpPublicKey, pgpNonce[msg.sender]);
    }

    function updateKOLFee(uint256 _fee) external nonReentrant {
        require(kolProfiles[msg.sender].verified, "KOL not registered");
        require(_fee > 0, "Fee must be greater than 0");
        kolProfiles[msg.sender].fee = _fee;
        emit KOLFeeUpdated(msg.sender, _fee);
    }

    function updateKOLActiveDays(DAYS[] memory _days, bool[] memory _active) external nonReentrant {
        require(kolProfiles[msg.sender].verified, "KOL not registered");
        require(_days.length == _active.length, "Days and active array must be the same length");
        for (uint256 i = 0; i < _days.length; i++) {
            kolActiveDays[msg.sender][_days[i]] = _active[i];
            emit KOLActiveDaysUpdated(msg.sender, _days[i], _active[i]);
        }
    }

    function updateKOLActiveTime(uint256 _startTime, uint256 _endTime) external nonReentrant {
        require(kolProfiles[msg.sender].verified, "KOL not registered");
        kolActiveTime[msg.sender] = _startTime;
        kolInactiveTime[msg.sender] = _endTime;
        emit KOLActiveTimeUpdated(msg.sender, _startTime, _endTime);
        emit KOLInactiveTimeUpdated(msg.sender, _startTime, _endTime);
    }

    function getDayAndTimeUsingTimestamp() external view returns (DAYS, uint256) {
        uint256 currentTime = block.timestamp;
        
        uint256 daysSinceEpoch = currentTime / 86400;
        uint256 dayOfWeek = ((daysSinceEpoch + 3) % 7);
        
        uint256 timeOfDay = currentTime % 86400;

        return (DAYS(dayOfWeek), timeOfDay);
    }

    function isKOLActive(address _wallet) external view returns (bool) {
        require(kolProfiles[_wallet].verified, "KOL not registered");
        uint256 currentTime = block.timestamp;
        uint256 daysSinceEpoch = currentTime / 86400;
        uint256 dayOfWeek = ((daysSinceEpoch + 3) % 7);
        DAYS currentDay = DAYS(dayOfWeek);
        if (!kolActiveDays[_wallet][currentDay]) {
            return false;
        }
        uint256 timeOfDay = currentTime % 86400;
        uint256 activeStart = kolActiveTime[_wallet];
        uint256 activeEnd = kolInactiveTime[_wallet];
        
        activeStart = activeStart % 86400;
        activeEnd = activeEnd % 86400;
        
        if (activeStart <= activeEnd) {
            return (timeOfDay >= activeStart && timeOfDay < activeEnd);
        } else {
            return (timeOfDay >= activeStart || timeOfDay < activeEnd);
        }
    }

    function updateKOLData(
        string memory _value,
        string memory _key
    ) external nonReentrant {
        require(kolProfiles[msg.sender].verified, "KOL not registered");
        if (keccak256(abi.encodePacked(_key)) == keccak256(abi.encodePacked("profileIpfsHash"))) {
            kolProfiles[msg.sender].profileIpfsHash = _value;
        } else if (keccak256(abi.encodePacked(_key)) == keccak256(abi.encodePacked("tags"))) {
            kolProfiles[msg.sender].tags = _value;
        } else if (keccak256(abi.encodePacked(_key)) == keccak256(abi.encodePacked("description"))) {
            kolProfiles[msg.sender].description = _value;
        } else {
            revert("Invalid key");
        }
        emit KOLData(msg.sender, kolProfiles[msg.sender].profileIpfsHash, kolProfiles[msg.sender].tags, kolProfiles[msg.sender].description);
    }

    function unregisterKOL() external nonReentrant {
        require(kolProfiles[msg.sender].verified, "KOL not registered");
        delete socialHandleToKOLProfile[kolProfiles[msg.sender].socialPlatform][kolProfiles[msg.sender].socialHandle];
        delete pgpPublicKeys[msg.sender];
        delete kolProfiles[msg.sender];

        emit KOLUnregistered(msg.sender);
    }
}
