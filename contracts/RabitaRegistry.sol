// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract RabitaRegistry is Ownable {
    using ECDSA for bytes32;

    struct KOLProfile {
        address wallet;
        string socialPlatform;
        string socialHandle;
        uint256 fee;
        string profileIpfsHash;
        bool verified;
    }

    mapping(address => KOLProfile) public kolProfiles;
    mapping(string => KOLProfile) public socialHandleToKOLProfile;

    address public verifier;

    event KOLRegistered(
        address indexed wallet,
        string socialPlatform,
        string socialHandle,
        uint256 fee,
        string profileIpfsHash
    );

    constructor(address _verifier) Ownable(msg.sender) {
        require(_verifier != address(0), "Invalid verifier address");
        verifier = _verifier;
    }

    function registerKOL(
        string memory _socialPlatform,
        string memory _socialHandle,
        uint256 _fee,
        string memory _profileIpfsHash,
        string memory _salt,
        bytes memory _signature
    ) external {
        require(!kolProfiles[msg.sender].verified, "KOL already registered");
        require(socialHandleToKOLProfile[_socialHandle].wallet == address(0), "Social handle already registered");

        bytes32 messageHash = keccak256(
            abi.encodePacked(msg.sender, _socialPlatform, _socialHandle, _salt)
        );
        
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address recoveredSigner = ECDSA.recover(ethSignedMessageHash, _signature);
        require(recoveredSigner == verifier, "Invalid signature");

        kolProfiles[msg.sender] = KOLProfile({
            wallet: msg.sender,
            socialPlatform: _socialPlatform,
            socialHandle: _socialHandle,
            fee: _fee,
            profileIpfsHash: _profileIpfsHash,
            verified: true
        });

        socialHandleToKOLProfile[_socialHandle] = kolProfiles[msg.sender];

        emit KOLRegistered(msg.sender, _socialPlatform, _socialHandle, _fee, _profileIpfsHash);
    }

    function updateVerifier(address _verifier) external onlyOwner {
        require(_verifier != address(0), "Invalid verifier address");
        verifier = _verifier;
    }
}
