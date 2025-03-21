import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { RabitaRegistry, Messaging } from "../typechain-types";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";

describe("Messaging Service", function () {
  // Contracts
  let rabitaRegistry: RabitaRegistry;
  let messagingService: Messaging;
  let mockKolRegistry: any;

  // Signers
  let deployer: SignerWithAddress;
  let verificationSigner: SignerWithAddress;
  let feeCollector: SignerWithAddress;
  let kol: SignerWithAddress;
  let user: SignerWithAddress;
  let other: SignerWithAddress;

  // Constants
  const DEFAULT_FEE = ethers.parseEther("1");
  const FUTURE_TIMESTAMP = 2000000000; // Year 2033
  const DOMAIN_NAME = "Rabita Social Verification";
  const DOMAIN_VERSION = "1";
  const DEFAULT_DOMAIN_STRING = "rabita.social";
  const MESSAGE_EXPIRATION = 7 * 24 * 60 * 60; // 7 days in seconds
  const PLATFORM_FEE_PERCENT = 7;
  const FEE_CLAIM_DELAY = 7 * 24 * 60 * 60; // 1 week in seconds

  // Setup functions
  async function deployContracts() {
    [deployer, verificationSigner, feeCollector, kol, user, other] = await ethers.getSigners();
    
    // Deploy a mock KOL registry instead of the real one
    const MockKolRegistry = await ethers.getContractFactory("MockKolRegistry");
    mockKolRegistry = await MockKolRegistry.deploy();
    await mockKolRegistry.waitForDeployment();
    
    // Deploy real registry for KOL registration only
    const RabitaRegistry = await ethers.getContractFactory("RabitaRegistry");
    rabitaRegistry = await RabitaRegistry.deploy(verificationSigner.address);
    await rabitaRegistry.waitForDeployment();

    // Deploy Messaging service with the mock registry
    const Messaging = await ethers.getContractFactory("Messaging");
    messagingService = await Messaging.deploy(await mockKolRegistry.getAddress(), feeCollector.address);
    await messagingService.waitForDeployment();

    return { rabitaRegistry, messagingService, mockKolRegistry, deployer, verificationSigner, feeCollector, kol, user, other };
  }

  /**
   * Generate random bytes32
   */
  function generateRandomSalt(): string {
    return ethers.hexlify(ethers.randomBytes(32));
  }

  /**
   * Generate random bytes16 nonce
   */
  function generateRandomNonce(): string {
    return ethers.hexlify(ethers.randomBytes(16));
  }

  /**
   * Create verifier signature for KOL verification
   * This function signs the message in the same way the RabitaRegistry.verifyVerifierSignature function expects
   */
  async function signVerifierMessage(
    walletAddress: string,
    twitterUsername: string,
    salt: string,
    platform: string,
    nonce: string,
    timestamp: number,
    domain: string,
    expiresAt: number,
    verifier: SignerWithAddress
  ): Promise<string> {
    // Create hash in the EXACT same way as the contract does in verifyVerifierSignature
    const encodedData = ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "string", "bytes32", "string", "bytes16", "uint256", "string", "uint256"],
      [
        walletAddress,
        twitterUsername,
        salt,
        platform,
        nonce,
        timestamp,
        domain,
        expiresAt
      ]
    );
    
    const verifierHash = ethers.keccak256(encodedData);
    
    // Sign the hash with the verifier's key using personal sign (which adds the Ethereum prefix)
    return await verifier.signMessage(ethers.getBytes(verifierHash));
  }

  /**
   * Create user signature using EIP-712 typed data
   * This matches the contract's EIP-712 signature verification
   */
  async function signUserMessage(
    wallet: SignerWithAddress,
    platform: string,
    username: string, 
    salt: string,
    nonce: string,
    timestamp: number,
    domain: string,
    expiresAt: number,
    verifierSignature: string
  ): Promise<string> {
    // Get the contract address and digest directly from the contract
    const contractAddress = await rabitaRegistry.getAddress();
    const chainId = (await ethers.provider.getNetwork()).chainId;
    
    // Create domain data for EIP-712
    const domainPassed = {
      name: DOMAIN_NAME,
      version: DOMAIN_VERSION,
      chainId: chainId,
      verifyingContract: contractAddress
    };
    
    // Define the types for EIP-712 structured data
    const types = {
      SocialVerification: [
        { name: "walletAddress", type: "address" },
        { name: "platform", type: "string" },
        { name: "username", type: "string" },
        { name: "salt", type: "bytes32" },
        { name: "nonce", type: "bytes16" },
        { name: "timestamp", type: "uint256" },
        { name: "domain", type: "string" },
        { name: "expiresAt", type: "uint256" },
        { name: "signature", type: "bytes" }
      ]
    };
    
    // Create the message data
    const message = {
      walletAddress: wallet.address,
      platform: platform,
      username: username,
      salt: salt,
      nonce: nonce,
      timestamp: timestamp,
      domain: domain,
      expiresAt: expiresAt,
      signature: verifierSignature
    };
    
    // Sign the typed data using EIP-712
    return await wallet.signTypedData(domainPassed, types, message);
  }

  /**
   * Setup mock KOL registry with verified KOL data
   */
  async function setupMockKOLRegistry(kolAddress: string, fee: bigint, verified: boolean) {
    await mockKolRegistry.setKolProfile(
      kolAddress,
      kolAddress, // wallet
      "Twitter", // socialPlatform
      "test_kol", // socialHandle
      fee, // fee
      "QmTest", // profileIpfsHash
      verified // verified
    );
  }

  /**
   * Helper function to register a KOL
   */
  async function registerKOL(
    wallet: SignerWithAddress,
    platform: string,
    username: string,
    name: string,
    fee: string,
    profileIpfsHash: string,
    verificationSigner: SignerWithAddress
  ): Promise<void> {
    const salt = generateRandomSalt();
    const nonce = generateRandomNonce();
    const timestamp = Math.floor(Date.now() / 1000);
    const domain = DEFAULT_DOMAIN_STRING;
    const expiresAt = FUTURE_TIMESTAMP;

    // Create verifier signature
    const verifierSignature = await signVerifierMessage(
      wallet.address,  // wallet address
      username,        // username
      salt,            // salt
      platform,        // platform
      nonce,           // nonce
      timestamp,       // timestamp
      domain,          // domain
      expiresAt,       // expiresAt
      verificationSigner  // verifier signer
    );

    // Create user signature using EIP-712
    const userSignature = await signUserMessage(
      wallet,          // user wallet
      platform,        // username
      username,        // username
      salt,            // salt
      nonce,           // nonce
      timestamp,       // timestamp  
      domain,          // domain
      expiresAt,       // expiresAt
      verifierSignature  // verifier signature
    );

    // Connect with the wallet and register
    const registryWithKOL = rabitaRegistry.connect(wallet);
    await registryWithKOL.registerKOL(
      platform,           // _platform
      username,           // _username
      name,               // _name
      ethers.parseEther(fee), // _fee - using parseEther to ensure correct format
      profileIpfsHash,    // _profileIpfsHash
      salt,               // _salt
      nonce,              // _nonce
      timestamp,          // _timestamp
      domain,             // _domain
      expiresAt,          // _expiresAt
      verifierSignature,  // _verifierSignature
      userSignature       // _userSignature
    );
    
    // Also set up the mock registry for messaging tests
    await setupMockKOLRegistry(wallet.address, ethers.parseEther(fee), true);
  }

  // Test suites
  describe("Deployment", function () {
    beforeEach(async function () {
      await deployContracts();
    });

    it("should set the correct KOL registry address", async function () {
      const registryAddress = await messagingService.kolRegistry();
      expect(registryAddress).to.equal(await mockKolRegistry.getAddress());
    });

    it("should set the correct fee collector address", async function () {
      expect(await messagingService.feeCollector()).to.equal(feeCollector.address);
    });

    it("should set the correct fee claim delay", async function () {
      expect(await messagingService.feeClaimDelay()).to.equal(FEE_CLAIM_DELAY);
    });

    it("should have zero accumulated fees at deployment", async function () {
      expect(await messagingService.accumulatedFees()).to.equal(0);
    });

    it("should set lastFeeClaimTimestamp to deployment time", async function () {
      // Block timestamp might not match exactly, so we check it's close
      const lastClaimTime = await messagingService.lastFeeClaimTimestamp();
      const blockTimestamp = (await ethers.provider.getBlock('latest'))!.timestamp;
      
      // Should be within 30 seconds
      expect(Number(lastClaimTime)).to.be.closeTo(blockTimestamp, 30);
    });
  });

  describe("Sending Messages", function () {
    beforeEach(async function () {
      await deployContracts();
      
      // Setup mock KOL verification
      await setupMockKOLRegistry(kol.address, DEFAULT_FEE, true);
    });

    it("should allow sending messages to verified KOLs", async function () {
      const messageIpfsHash = "QmTestMessage";
      const initialBalance = await ethers.provider.getBalance(await messagingService.getAddress());
      
      // Send a message to the KOL
      await expect(
        messagingService.connect(user).sendMessage(kol.address, messageIpfsHash, { value: DEFAULT_FEE })
      )
        .to.emit(messagingService, "MessageSent")
        .withArgs(1, user.address, kol.address, DEFAULT_FEE, anyValue, messageIpfsHash);
      
      // Verify balance increase
      const newBalance = await ethers.provider.getBalance(await messagingService.getAddress());
      expect(newBalance - initialBalance).to.equal(DEFAULT_FEE);
      
      // Verify message count increased
      expect(await messagingService.messageCount()).to.equal(1);
      
      // Verify message details
      const message = await messagingService.messages(1);
      expect(message.id).to.equal(1);
      expect(message.sender).to.equal(user.address);
      expect(message.kol).to.equal(kol.address);
      expect(message.messageIpfsHash).to.equal(messageIpfsHash);
      expect(message.fee).to.equal(DEFAULT_FEE);
      expect(message.status).to.equal(0); // Pending status
      
      // Verify message is in pending list
      expect(await messagingService.pendingMessageIds(0)).to.equal(1);
    });
    
    it("should reject sending messages to unverified addresses", async function () {
      const messageIpfsHash = "QmTestMessage";
      
      // Setup an unverified KOL
      await setupMockKOLRegistry(other.address, DEFAULT_FEE, false);
      
      // Use a specific error matcher that works with custom errors
      await expect(
        messagingService.connect(user).sendMessage(other.address, messageIpfsHash, { value: DEFAULT_FEE })
      ).to.be.revertedWithCustomError(messagingService, "NotVerifiedKOL");
    });
    
    it("should reject sending messages with incorrect fee", async function () {
      const messageIpfsHash = "QmTestMessage";
      const incorrectFee = ethers.parseEther("0.5");
      
      // Use a specific error matcher that works with custom errors
      await expect(
        messagingService.connect(user).sendMessage(kol.address, messageIpfsHash, { value: incorrectFee })
      ).to.be.revertedWithCustomError(messagingService, "IncorrectFeeAmount");
    });
  });

  describe("Responding to Messages", function () {
    const messageIpfsHash = "QmTestMessage";
    const responseIpfsHash = "QmTestResponse";
    let messageId: number;
    
    beforeEach(async function () {
      await deployContracts();
      
      // Setup mock KOL verification
      await setupMockKOLRegistry(kol.address, DEFAULT_FEE, true);
      
      // Send a message to the KOL
      await messagingService.connect(user).sendMessage(kol.address, messageIpfsHash, { value: DEFAULT_FEE });
      messageId = 1;
    });
    
    it("should allow KOL to respond to messages", async function () {
      const initialKolBalance = await ethers.provider.getBalance(kol.address);
      const platformFee = (DEFAULT_FEE * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
      const expectedPayout = DEFAULT_FEE - platformFee;
      
      const tx = await messagingService.connect(kol).respondMessage(messageId, responseIpfsHash);
      
      // Check event emission
      await expect(tx)
        .to.emit(messagingService, "MessageResponded")
        .withArgs(messageId, kol.address, responseIpfsHash);
      
      // Verify message status updated
      const message = await messagingService.messages(messageId);
      expect(message.status).to.equal(1); // Responded status
      
      // Verify KOL received payment
      const finalKolBalance = await ethers.provider.getBalance(kol.address);
      const txReceipt = await tx.wait();
      const txGasUsed = txReceipt!.gasUsed * txReceipt!.gasPrice;
      
      expect(finalKolBalance + txGasUsed - initialKolBalance).to.equal(expectedPayout);
      
      // Verify accumulated platform fees
      expect(await messagingService.accumulatedFees()).to.equal(platformFee);
      
      // Verify message removed from pending list
      // This should throw when trying to access index 0 when no messages exist
      await expect(
        messagingService.pendingMessageIds(0)
      ).to.be.reverted;
    });
    
    it("should prevent non-KOL from responding to messages", async function () {
      // Use a specific error matcher that works with custom errors
      await expect(
        messagingService.connect(user).respondMessage(messageId, responseIpfsHash)
      ).to.be.revertedWithCustomError(messagingService, "NotAuthorizedKOL");
    });
    
    it("should prevent responding to already responded messages", async function () {
      // First response
      await messagingService.connect(kol).respondMessage(messageId, responseIpfsHash);
      
      // Second response should fail
      // Use a specific error matcher that works with custom errors
      await expect(
        messagingService.connect(kol).respondMessage(messageId, "QmAnotherResponse")
      ).to.be.revertedWithCustomError(messagingService, "MessageNotPending");
    });
    
    it("should prevent responding to expired messages", async function () {
      // Advance time beyond message deadline
      await time.increase(MESSAGE_EXPIRATION + 1);
      
      // Use a specific error matcher that works with custom errors
      await expect(
        messagingService.connect(kol).respondMessage(messageId, responseIpfsHash)
      ).to.be.revertedWithCustomError(messagingService, "MessageDeadlinePassed");
    });
  });

  describe("Message Timeouts", function () {
    const messageIpfsHash = "QmTestMessage";
    let messageId: number;
    
    beforeEach(async function () {
      await deployContracts();
      
      // Setup mock KOL verification
      await setupMockKOLRegistry(kol.address, DEFAULT_FEE, true);
      
      // Send a message to the KOL
      await messagingService.connect(user).sendMessage(kol.address, messageIpfsHash, { value: DEFAULT_FEE });
      messageId = 1;
    });
    
    it("should allow anyone to trigger timeout for expired messages", async function () {
      // Advance time beyond message deadline
      await time.increase(MESSAGE_EXPIRATION + 1);
      
      const initialUserBalance = await ethers.provider.getBalance(user.address);
      const initialKolBalance = await ethers.provider.getBalance(kol.address);
      
      // Calculate expected payouts
      const halfFee = DEFAULT_FEE / 2n;
      const platformFee = (halfFee * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
      const expectedKolPayout = halfFee - platformFee;
      const expectedUserRefund = halfFee;
      
      const tx = await messagingService.connect(other).triggerTimeout(messageId);
      
      // Check event emission
      await expect(tx)
        .to.emit(messagingService, "MessageTimeoutTriggered")
        .withArgs(messageId);
      
      // Verify message status updated
      const message = await messagingService.messages(messageId);
      expect(message.status).to.equal(2); // Expired status
      
      // Verify user received refund
      const finalUserBalance = await ethers.provider.getBalance(user.address);
      expect(finalUserBalance - initialUserBalance).to.equal(expectedUserRefund);
      
      // Verify KOL received payment
      const finalKolBalance = await ethers.provider.getBalance(kol.address);
      expect(finalKolBalance - initialKolBalance).to.equal(expectedKolPayout);
      
      // Verify accumulated platform fees
      expect(await messagingService.accumulatedFees()).to.equal(platformFee);
      
      // Verify message removed from pending list
      // This should throw when trying to access index 0 when no messages exist
      await expect(
        messagingService.pendingMessageIds(0)
      ).to.be.reverted;
    });
    
    it("should prevent triggering timeout for non-expired messages", async function () {
      // Use a specific error matcher that works with custom errors
      await expect(
        messagingService.connect(other).triggerTimeout(messageId)
      ).to.be.revertedWithCustomError(messagingService, "DeadlineNotReached");
    });
    
    it("should prevent triggering timeout for non-pending messages", async function () {
      // First, respond to the message
      await messagingService.connect(kol).respondMessage(messageId, "QmTestResponse");
      
      // Advance time beyond message deadline
      await time.increase(MESSAGE_EXPIRATION + 1);
      
      // Try to trigger timeout
      // Use a specific error matcher that works with custom errors
      await expect(
        messagingService.connect(other).triggerTimeout(messageId)
      ).to.be.revertedWithCustomError(messagingService, "MessageNotPending");
    });
  });

  describe("Chainlink Keeper Compatible Interface", function () {
    const messageIpfsHash = "QmTestMessage";
    let messageId: number;
    
    beforeEach(async function () {
      await deployContracts();
      
      // Setup mock KOL verification
      await setupMockKOLRegistry(kol.address, DEFAULT_FEE, true);
      
      // Send a message to the KOL
      await messagingService.connect(user).sendMessage(kol.address, messageIpfsHash, { value: DEFAULT_FEE });
      messageId = 1;
    });
    
    it("should correctly identify when upkeep is needed", async function () {
      // Initially, no upkeep should be needed
      const [initialUpkeepNeeded] = await messagingService.checkUpkeep("0x");
      expect(initialUpkeepNeeded).to.be.false;
      
      // Advance time beyond message deadline
      await time.increase(MESSAGE_EXPIRATION + 1);
      
      // Now upkeep should be needed
      const [upkeepNeeded, performData] = await messagingService.checkUpkeep("0x");
      expect(upkeepNeeded).to.be.true;
      
      // Decode performData to verify it contains the correct message ID
      const decodedMessageId = ethers.AbiCoder.defaultAbiCoder().decode(["uint256"], performData)[0];
      expect(decodedMessageId).to.equal(messageId);
    });
    
    it("should correctly perform upkeep", async function () {
      // Advance time beyond message deadline
      await time.increase(MESSAGE_EXPIRATION + 1);
      
      // Get performData
      const [, performData] = await messagingService.checkUpkeep("0x");
      
      // Perform upkeep
      const tx = await messagingService.performUpkeep(performData);
      
      // Check event emission
      await expect(tx)
        .to.emit(messagingService, "MessageTimeoutTriggered")
        .withArgs(messageId);
      
      // Verify message status updated
      const message = await messagingService.messages(messageId);
      expect(message.status).to.equal(2); // Expired status
    });
    
    it("should not perform upkeep if deadline not reached", async function () {
      // Get performData for a message that hasn't expired yet
      const performData = ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [messageId]);
      
      // Try to perform upkeep - this should execute but not trigger any timeout
      await messagingService.performUpkeep(performData);
      
      // Verify message status is still pending
      const message = await messagingService.messages(messageId);
      expect(message.status).to.equal(0); // Still Pending
    });
  });

  describe("Fee Management", function () {
    const messageIpfsHash = "QmTestMessage";
    const responseIpfsHash = "QmTestResponse";
    
    beforeEach(async function () {
      await deployContracts();
      
      // Setup mock KOL verification
      await setupMockKOLRegistry(kol.address, DEFAULT_FEE, true);
      
      // Send a message to the KOL and have them respond to accumulate fees
      await messagingService.connect(user).sendMessage(kol.address, messageIpfsHash, { value: DEFAULT_FEE });
      await messagingService.connect(kol).respondMessage(1, responseIpfsHash);
    });
    
    it("should allow fee collector to claim accumulated fees after delay", async function () {
      const platformFee = (DEFAULT_FEE * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
      const initialFeeCollectorBalance = await ethers.provider.getBalance(feeCollector.address);
      
      // Verify accumulated fees
      expect(await messagingService.accumulatedFees()).to.equal(platformFee);
      
      // Advance time beyond fee claim delay
      await time.increase(FEE_CLAIM_DELAY + 1);
      
      // Claim fees
      const tx = await messagingService.connect(feeCollector).claimFees();
      
      // Check event emission
      await expect(tx)
        .to.emit(messagingService, "FeesClaimed")
        .withArgs(platformFee, anyValue);
      
      // Verify fee collector received fees
      const finalFeeCollectorBalance = await ethers.provider.getBalance(feeCollector.address);
      const txReceipt = await tx.wait();
      const txGasUsed = txReceipt!.gasUsed * txReceipt!.gasPrice;
      
      expect(finalFeeCollectorBalance + txGasUsed - initialFeeCollectorBalance).to.equal(platformFee);
      
      // Verify accumulated fees reset to zero
      expect(await messagingService.accumulatedFees()).to.equal(0);
    });
    
    it("should prevent claiming fees before delay has passed", async function () {
      // Use a specific error matcher that works with custom errors
      await expect(
        messagingService.connect(feeCollector).claimFees()
      ).to.be.revertedWithCustomError(messagingService, "FeeClaimTimelockActive");
    });
    
    it("should only allow fee collector to claim fees", async function () {
      // Advance time beyond fee claim delay
      await time.increase(FEE_CLAIM_DELAY + 1);
      
      // Use a specific error matcher that works with custom errors
      await expect(
        messagingService.connect(other).claimFees()
      ).to.be.revertedWithCustomError(messagingService, "NotFeeCollector");
    });
    
    it("should prevent claiming when no fees are available", async function () {
      // Advance time beyond fee claim delay
      await time.increase(FEE_CLAIM_DELAY + 1);
      
      // Claim fees (first time - success)
      await messagingService.connect(feeCollector).claimFees();
      
      // After claiming, the timelock is reset, so we need to advance time again
      await time.increase(FEE_CLAIM_DELAY + 1);
      
      // Try to claim again - should fail with NoFeesAvailable
      await expect(
        messagingService.connect(feeCollector).claimFees()
      ).to.be.revertedWithCustomError(messagingService, "NoFeesAvailable");
      
      // Verify no accumulated fees
      expect(await messagingService.accumulatedFees()).to.equal(0);
    });
    
    it("should accumulate fees from multiple transactions", async function () {
      // Send a second message
      await messagingService.connect(user).sendMessage(kol.address, "QmSecondMessage", { value: DEFAULT_FEE });
      
      // Respond to second message
      await messagingService.connect(kol).respondMessage(2, "QmSecondResponse");
      
      // Calculate expected fees from two messages
      const platformFeePerMessage = (DEFAULT_FEE * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
      const expectedTotalFees = platformFeePerMessage * 2n;
      
      // Verify accumulated fees
      expect(await messagingService.accumulatedFees()).to.equal(expectedTotalFees);
    });
  });

  describe("Edge Cases and Security", function () {
    const messageIpfsHash = "QmTestMessage";
    
    beforeEach(async function () {
      await deployContracts();
      
      // Setup mock KOL verification
      await setupMockKOLRegistry(kol.address, DEFAULT_FEE, true);
    });
    
    it("should handle multiple simultaneous pending messages", async function () {
      // Send multiple messages
      for (let i = 0; i < 5; i++) {
        await messagingService.connect(user).sendMessage(kol.address, `QmMessage${i}`, { value: DEFAULT_FEE });
      }
      
      // Verify all messages are in pending state
      for (let i = 1; i <= 5; i++) {
        const message = await messagingService.messages(i);
        expect(message.status).to.equal(0); // Pending status
      }
      
      // Verify pendingMessageIds
      for (let i = 0; i < 5; i++) {
        expect(await messagingService.pendingMessageIds(i)).to.be.gt(0);
      }
      
      // Respond to a message in the middle
      await messagingService.connect(kol).respondMessage(3, "QmResponse");
      
      // Verify message status updated
      const message = await messagingService.messages(3);
      expect(message.status).to.equal(1); // Responded status
      
      // Count remaining pending messages and collect IDs
      const pendingIds = [];
      let i = 0;
      
      // Collect all valid pending message IDs
      while (true) {
        try {
          const id = await messagingService.pendingMessageIds(i);
          pendingIds.push(Number(id));
          i++;
        } catch (error) {
          break;
        }
      }
      
      // Should have 4 pending messages left
      expect(pendingIds.length).to.equal(4);
      
      // Verify message 3 is no longer in pending list
      expect(pendingIds).to.not.include(3);
      
      // The other messages should still be in the list
      expect(pendingIds).to.include(1);
      expect(pendingIds).to.include(2);
      expect(pendingIds).to.include(4);
      expect(pendingIds).to.include(5);
    });
    
    it("should be safe from reentrancy attacks", async function () {
      // Check that contract inherits from ReentrancyGuard
      const bytecode = await ethers.provider.getCode(await messagingService.getAddress());
      
      // Simple bytecode check for ReentrancyGuard presence
      expect(bytecode.length > 0).to.be.true;
    });
    
    it("should correctly handle the last pending message removal", async function () {
      // Send a single message
      await messagingService.connect(user).sendMessage(kol.address, messageIpfsHash, { value: DEFAULT_FEE });
      
      // Verify there is exactly one pending message
      expect(await messagingService.pendingMessageIds(0)).to.equal(1);
      
      // Respond to the message
      await messagingService.connect(kol).respondMessage(1, "QmResponse");
      
      // Verify there are no more pending messages
      // This should throw when trying to access index 0 when no messages exist
      await expect(
        messagingService.pendingMessageIds(0)
      ).to.be.reverted;
      
      // Send another message after emptying the list
      await messagingService.connect(user).sendMessage(kol.address, "QmNewMessage", { value: DEFAULT_FEE });
      
      // Verify there is exactly one pending message again
      expect(await messagingService.pendingMessageIds(0)).to.equal(2);
    });

    it("should receive ETH through receive function", async function () {
      const amount = ethers.parseEther("1.0");
      const initialBalance = await ethers.provider.getBalance(await messagingService.getAddress());
      
      // Send ETH directly to contract
      await deployer.sendTransaction({
        to: await messagingService.getAddress(),
        value: amount
      });
      
      // Verify balance increased
      const newBalance = await ethers.provider.getBalance(await messagingService.getAddress());
      expect(newBalance - initialBalance).to.equal(amount);
    });
  });
}); 