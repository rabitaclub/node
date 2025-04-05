import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { RabitaMessaging, MockKolRegistry } from "../typechain-types";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { randomBytes } from "crypto";

describe("RabitaMessaging", function () {
  // Constants
  const MESSAGE_EXPIRATION = 7 * 24 * 60 * 60; // 7 days in seconds
  const PLATFORM_FEE_PERCENT = 7;
  const DEFAULT_FEE = ethers.parseEther("0.1");
  const FEE_CLAIM_DELAY = 7 * 24 * 60 * 60; // 1 week in seconds
  const MAX_BATCH_SIZE = 100; // Updated batch size

  // Contracts
  let messagingService: RabitaMessaging;
  let mockKolRegistry: MockKolRegistry;

  // Signers
  let deployer: SignerWithAddress;
  let feeCollector: SignerWithAddress;
  let kols: SignerWithAddress[] = [];
  let users: SignerWithAddress[] = [];
  let other: SignerWithAddress;

  // Helper functions
  function generateRandomBytes(): Uint8Array {
    return randomBytes(32);
  }

  function generateRandomUint256(): bigint {
    // Generate a random number within uint256 range
    return ethers.toBigInt("0x" + randomBytes(32).toString("hex"));
  }

  async function setupMockKOLProfile(
    kolAddress: string,
    fee: bigint = DEFAULT_FEE,
    verified: boolean = true
  ): Promise<void> {
    await mockKolRegistry.setKolProfile(
      kolAddress,
      kolAddress, // wallet is same as kolAddress
      "twitter",
      "testhandle",
      "testname", // Adding socialName
      fee,
      "ipfs://test",
      verified
    );
    
    // Set a PGP public key for the KOL
    await mockKolRegistry.setPgpPublicKey(kolAddress, generateRandomBytes());
  }

  beforeEach(async function () {
    const signers = await ethers.getSigners();
    deployer = signers[0];
    feeCollector = signers[1];
    
    // Set up multiple KOLs and users for testing
    kols = signers.slice(2, 7); // 5 KOLs
    users = signers.slice(7, 12); // 5 users
    other = signers[12];

    // Deploy mock KOL registry
    const MockKolRegistry = await ethers.getContractFactory("MockKolRegistry");
    mockKolRegistry = await MockKolRegistry.deploy();

    // Deploy messaging service
    const RabitaMessaging = await ethers.getContractFactory("RabitaMessaging");
    messagingService = await RabitaMessaging.deploy(
      await mockKolRegistry.getAddress(),
      feeCollector.address
    );

    // Setup default KOL profiles
    for (const kol of kols) {
      await setupMockKOLProfile(kol.address);
    }
  });

  describe("Deployment", function () {
    it("Should set the correct owner", async function () {
      expect(await messagingService.owner()).to.equal(deployer.address);
    });

    it("Should set the correct KOL registry", async function () {
      expect(await messagingService.kolRegistry()).to.equal(
        await mockKolRegistry.getAddress()
      );
    });

    it("Should set the correct fee collector", async function () {
      expect(await messagingService.feeCollector()).to.equal(feeCollector.address);
    });
  });

  describe("Sending Messages", function () {
    const testContent = "Test message content";
    let senderPGPPublicKey: Uint8Array;
    let senderPGPNonce: bigint;

    beforeEach(async function () {
      senderPGPPublicKey = generateRandomBytes();
      senderPGPNonce = generateRandomUint256();
    });

    it("Should allow sending message to verified KOL", async function () {
      const tx = await messagingService.connect(users[0]).sendEncryptedMessage(
        kols[0].address,
        senderPGPPublicKey,
        senderPGPNonce,
        testContent,
        { value: DEFAULT_FEE }
      );

      await expect(tx)
        .to.emit(messagingService, "MessageSentToKOL")
        .withArgs(
          1, // messageId
          DEFAULT_FEE,
          anyValue, // deadline
          testContent
        );

      await expect(tx)
        .to.emit(messagingService, "MessageSent")
        .withArgs(
          users[0].address,
          kols[0].address,
          testContent
        );

      await expect(tx)
        .to.emit(messagingService, "SenderPGPUpdated")
        .withArgs(
          users[0].address,
          1, // messageId
          ethers.hexlify(senderPGPPublicKey),
          senderPGPNonce
        );

      const message = await messagingService.messages(1);
      expect(message.sender).to.equal(users[0].address);
      expect(message.kol).to.equal(kols[0].address);
      expect(message.fee).to.equal(DEFAULT_FEE);
      expect(message.content).to.equal(testContent);
      expect(message.status).to.equal(0); // Pending

      const metadata = await messagingService.messageMetadata(1);
      expect(metadata.senderPGPPublicKey).to.equal(ethers.hexlify(senderPGPPublicKey));
      expect(metadata.senderPGPNonce).to.equal(senderPGPNonce);
      expect(metadata.version).to.equal(1);

      // Check that active pair was added
      expect(await messagingService.isActivePair(users[0].address, kols[0].address)).to.be.true;
      expect(await messagingService.activePairCount()).to.equal(1);
      expect(await messagingService.userToKolLatestMessage(users[0].address, kols[0].address)).to.equal(1);
      
      // Check fees were tracked correctly
      expect(await messagingService.userToKolFeesCollected(users[0].address, kols[0].address)).to.equal(DEFAULT_FEE);
    });

    it("Should revert when sending to unverified KOL", async function () {
      await setupMockKOLProfile(kols[0].address, DEFAULT_FEE, false);

      await expect(
        messagingService.connect(users[0]).sendEncryptedMessage(
          kols[0].address,
          senderPGPPublicKey,
          senderPGPNonce,
          testContent,
          { value: DEFAULT_FEE }
        )
      ).to.be.revertedWithCustomError(messagingService, "NotVerifiedKOL");
    });

    it("Should revert when sending with incorrect fee", async function () {
      await expect(
        messagingService.connect(users[0]).sendEncryptedMessage(
          kols[0].address,
          senderPGPPublicKey,
          senderPGPNonce,
          testContent,
          { value: 0 }
        )
      ).to.be.revertedWithCustomError(messagingService, "IncorrectFeeAmount");
    });
  });

  describe("Responding to Messages", function () {
    const testContent = "Test message content";
    const responseContent = "Test response content";
    let messageId: bigint;
    let senderPGPPublicKey: Uint8Array;
    let senderPGPNonce: bigint;

    beforeEach(async function () {
      senderPGPPublicKey = generateRandomBytes();
      senderPGPNonce = generateRandomUint256();

      await messagingService.connect(users[0]).sendEncryptedMessage(
        kols[0].address,
        senderPGPPublicKey,
        senderPGPNonce,
        testContent,
        { value: DEFAULT_FEE }
      );
      messageId = 1n;
    });

    it("Should allow KOL to respond to message", async function () {
      const tx = await messagingService
        .connect(kols[0])
        .respondToMessage(users[0].address, responseContent);

      await expect(tx)
        .to.emit(messagingService, "MessageSent")
        .withArgs(users[0].address, kols[0].address, responseContent);

      const message = await messagingService.messages(messageId);
      expect(message.status).to.equal(1); // Responded

      // Check platform fee calculation
      const platformFee = (DEFAULT_FEE * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
      const netPayout = DEFAULT_FEE - platformFee;

      expect(await messagingService.accumulatedFees()).to.equal(platformFee);

      // Check active pair was removed and relationship was reset
      expect(await messagingService.isActivePair(users[0].address, kols[0].address)).to.be.false;
      expect(await messagingService.activePairCount()).to.equal(0);
      expect(await messagingService.userToKolLatestMessage(users[0].address, kols[0].address)).to.equal(0);
      
      // Check that kolToUserLastReply was updated
      expect(await messagingService.kolToUserLastReply(kols[0].address, users[0].address)).to.be.greaterThan(0);
    });

    it("Should revert when non-KOL tries to respond", async function () {
      await expect(
        messagingService
          .connect(other)
          .respondToMessage(users[0].address, responseContent)
      ).to.be.revertedWithCustomError(messagingService, "NotAuthorizedKOL");
    });

    it("Should revert when message has expired", async function () {
      await time.increase(MESSAGE_EXPIRATION + 1);

      await expect(
        messagingService
          .connect(kols[0])
          .respondToMessage(users[0].address, responseContent)
      ).to.be.revertedWithCustomError(messagingService, "MessageDeadlinePassed");
    });
  });

  describe("Message Timeout", function () {
    const testContent = "Test message content";
    let messageId: bigint;
    let senderPGPPublicKey: Uint8Array;
    let senderPGPNonce: bigint;

    beforeEach(async function () {
      senderPGPPublicKey = generateRandomBytes();
      senderPGPNonce = generateRandomUint256();

      await messagingService.connect(users[0]).sendEncryptedMessage(
        kols[0].address,
        senderPGPPublicKey,
        senderPGPNonce,
        testContent,
        { value: DEFAULT_FEE }
      );
      messageId = 1n;
    });

    it("Should allow triggering timeout after deadline", async function () {
      await time.increase(MESSAGE_EXPIRATION + 1);

      const tx = await messagingService.triggerTimeout(users[0].address, kols[0].address);

      await expect(tx)
        .to.emit(messagingService, "MessageTimeoutTriggered")
        .withArgs(0); // Now returns 0 because userToKolLatestMessage is reset to 0

      const message = await messagingService.messages(messageId);
      expect(message.status).to.equal(2); // Expired

      // Check refund and fee calculations
      const refundAmount = DEFAULT_FEE / 2n;
      const remainingAmount = DEFAULT_FEE / 2n;
      const platformFee = (remainingAmount * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
      const netPayout = remainingAmount - platformFee;

      expect(await messagingService.accumulatedFees()).to.equal(platformFee);
      
      // Check active pair was removed and relationship was reset
      expect(await messagingService.isActivePair(users[0].address, kols[0].address)).to.be.false;
      expect(await messagingService.activePairCount()).to.equal(0);
      expect(await messagingService.userToKolLatestMessage(users[0].address, kols[0].address)).to.equal(0);
    });

    it("Should refund exactly half of the fee to the sender on timeout", async function () {
      // Get initial balances before triggering timeout
      const initialSenderBalance = await ethers.provider.getBalance(users[0].address);
      const initialKolBalance = await ethers.provider.getBalance(kols[0].address);
      const initialContractBalance = await ethers.provider.getBalance(await messagingService.getAddress());
      
      // Let the message expire
      await time.increase(MESSAGE_EXPIRATION + 1);
      
      // Trigger timeout - we'll use a different account to avoid gas cost complexity
      const timeoutTx = await messagingService.connect(other).triggerTimeout(users[0].address, kols[0].address);
      const timeoutReceipt = await timeoutTx.wait();
      
      // Calculate expected distributions
      const halfFee = DEFAULT_FEE / 2n;
      const platformFee = (halfFee * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
      const kolPayout = halfFee - platformFee;
      
      // Get final balances
      const finalSenderBalance = await ethers.provider.getBalance(users[0].address);
      const finalKolBalance = await ethers.provider.getBalance(kols[0].address);
      const finalContractBalance = await ethers.provider.getBalance(await messagingService.getAddress());
      
      // Verify sender received exactly half the fee
      expect(finalSenderBalance).to.equal(initialSenderBalance + halfFee);
      
      // Verify KOL received their portion
      expect(finalKolBalance).to.equal(initialKolBalance + kolPayout);
      
      // Verify contract retained the platform fee
      expect(finalContractBalance).to.equal(initialContractBalance - halfFee - kolPayout);
      
      // Verify platform fee was accumulated correctly
      expect(await messagingService.accumulatedFees()).to.equal(platformFee);
      
      // Verify the message is marked as expired
      const message = await messagingService.messages(messageId);
      expect(message.status).to.equal(2); // Expired
      
      // Log the actual amounts for verification
      console.log(`Original fee: ${ethers.formatEther(DEFAULT_FEE)} ETH`);
      console.log(`Sender refund: ${ethers.formatEther(halfFee)} ETH`);
      console.log(`KOL payout: ${ethers.formatEther(kolPayout)} ETH`);
      console.log(`Platform fee: ${ethers.formatEther(platformFee)} ETH`);
    });

    it("Should revert timeout trigger before deadline", async function () {
      await expect(
        messagingService.triggerTimeout(users[0].address, kols[0].address)
      ).to.be.revertedWithCustomError(messagingService, "DeadlineNotReached");
    });
  });

  describe("Fee Collection", function () {
    const testContent = "Test message content";
    let senderPGPPublicKey: Uint8Array;
    let senderPGPNonce: bigint;

    beforeEach(async function () {
      senderPGPPublicKey = generateRandomBytes();
      senderPGPNonce = generateRandomUint256();

      // Send and respond to a message to accumulate fees
      await messagingService.connect(users[0]).sendEncryptedMessage(
        kols[0].address,
        senderPGPPublicKey,
        senderPGPNonce,
        testContent,
        { value: DEFAULT_FEE }
      );

      await messagingService
        .connect(kols[0])
        .respondToMessage(users[0].address, "Response");
    });

    it("Should allow fee collector to claim fees after delay", async function () {
      await time.increase(FEE_CLAIM_DELAY + 1);

      const accumulatedFees = await messagingService.accumulatedFees();
      
      // Get initial balances
      const initialContractBalance = await ethers.provider.getBalance(await messagingService.getAddress());
      const initialCollectorBalance = await ethers.provider.getBalance(feeCollector.address);

      const tx = await messagingService.connect(feeCollector).claimFees();
      const receipt = await tx.wait();
      
      // Calculate gas costs
      const gasCost = receipt!.gasUsed * receipt!.gasPrice;

      await expect(tx)
        .to.emit(messagingService, "FeesClaimed")
        .withArgs(accumulatedFees, anyValue);

      // Check contract balance is reduced by accumulated fees
      expect(await ethers.provider.getBalance(await messagingService.getAddress()))
        .to.equal(initialContractBalance - accumulatedFees);

      // Check fee collector received the fees (accounting for gas costs)
      expect(await ethers.provider.getBalance(feeCollector.address))
        .to.equal(initialCollectorBalance + accumulatedFees - gasCost);

      // Check accumulated fees are reset
      expect(await messagingService.accumulatedFees()).to.equal(0);
    });

    it("Should revert fee claim before delay period", async function () {
      await expect(
        messagingService.connect(feeCollector).claimFees()
      ).to.be.revertedWithCustomError(messagingService, "FeeClaimTimelockActive");
    });

    it("Should revert fee claim from non-collector", async function () {
      await time.increase(FEE_CLAIM_DELAY + 1);

      await expect(
        messagingService.connect(other).claimFees()
      ).to.be.revertedWithCustomError(messagingService, "NotFeeCollector");
    });
  });

  describe("Active Pair Management", function () {
    const testContent = "Test message content";
    let senderPGPPublicKey: Uint8Array;
    let senderPGPNonce: bigint;
    
    beforeEach(async function () {
      senderPGPPublicKey = generateRandomBytes();
      senderPGPNonce = generateRandomUint256();
    });
    
    it("Should track active pairs correctly when adding", async function () {
      // Send multiple messages from different users to different KOLs
      for (let i = 0; i < 3; i++) {
        await messagingService.connect(users[i]).sendEncryptedMessage(
          kols[i].address,
          senderPGPPublicKey,
          senderPGPNonce,
          testContent,
          { value: DEFAULT_FEE }
        );
        
        expect(await messagingService.isActivePair(users[i].address, kols[i].address)).to.be.true;
      }
      
      expect(await messagingService.activePairCount()).to.equal(3);
      
      // Verify activeSenders and activeKols arrays
      for (let i = 0; i < 3; i++) {
        expect(await messagingService.activeSenders(i)).to.equal(users[i].address);
        expect(await messagingService.activeKols(i)).to.equal(kols[i].address);
      }
    });
    
    it("Should handle active pairs correctly when removing", async function () {
      // Create 3 active pairs
      for (let i = 0; i < 3; i++) {
        await messagingService.connect(users[i]).sendEncryptedMessage(
          kols[i].address,
          senderPGPPublicKey,
          senderPGPNonce,
          testContent,
          { value: DEFAULT_FEE }
        );
      }
      
      expect(await messagingService.activePairCount()).to.equal(3);
      
      // Respond to the middle message (should remove the middle pair)
      await messagingService.connect(kols[1]).respondToMessage(users[1].address, "Response");
      
      expect(await messagingService.activePairCount()).to.equal(2);
      expect(await messagingService.isActivePair(users[1].address, kols[1].address)).to.be.false;
    });
    
    it("Should not add duplicate active pairs", async function () {
      // Send two messages from the same user to the same KOL
      await messagingService.connect(users[0]).sendEncryptedMessage(
        kols[0].address,
        senderPGPPublicKey,
        senderPGPNonce,
        "First message",
        { value: DEFAULT_FEE }
      );
      
      await messagingService.connect(users[0]).sendEncryptedMessage(
        kols[0].address,
        senderPGPPublicKey,
        senderPGPNonce,
        "Second message",
        { value: DEFAULT_FEE }
      );
      
      // Should only count as one active pair
      expect(await messagingService.activePairCount()).to.equal(1);
      expect(await messagingService.userToKolLatestMessage(users[0].address, kols[0].address)).to.equal(2);
      
      // Should accumulate fees
      expect(await messagingService.userToKolFeesCollected(users[0].address, kols[0].address)).to.equal(DEFAULT_FEE * 2n);
    });
  });
  
  describe("Multiple Interactions and Refund Scenarios", function () {
    const testContent = "Test message content";
    let senderPGPPublicKey: Uint8Array;
    let senderPGPNonce: bigint;
    
    beforeEach(async function () {
      senderPGPPublicKey = generateRandomBytes();
      senderPGPNonce = generateRandomUint256();
    });
    
    it("Should refund only unanswered messages when a user has both answered and unanswered messages", async function () {
      // Setup: One user sending multiple batches of messages to one KOL
      const user = users[0];
      const kol = kols[0];
      
      // First batch: 5 messages, which will get answered
      console.log("\nSending first batch of messages...");
      
      for (let i = 0; i < 5; i++) {
        await messagingService.connect(user).sendEncryptedMessage(
          kol.address,
          senderPGPPublicKey,
          senderPGPNonce,
          `First batch message ${i}`,
          { value: DEFAULT_FEE }
        );
      }
      
      // Total fees paid for first batch
      const firstBatchFees = DEFAULT_FEE * 5n;
      expect(await messagingService.userToKolFeesCollected(user.address, kol.address)).to.equal(firstBatchFees);
      
      // Clear accumulated fees before first response (to make calculations cleaner)
      const initialAccumulatedFees = await messagingService.accumulatedFees();
      if (initialAccumulatedFees > 0) {
        await time.increase(FEE_CLAIM_DELAY + 1);
        await messagingService.connect(feeCollector).claimFees();
      }
      
      // KOL responds to all messages in the first batch
      console.log("KOL responding to all messages in first batch...");
      await messagingService.connect(kol).respondToMessage(user.address, "Response to all messages");
      
      // Calculate first batch platform fees
      const platformFeeFirstBatch = (firstBatchFees * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
      expect(await messagingService.accumulatedFees()).to.equal(platformFeeFirstBatch);
      
      // After response, userToKolFeesCollected should be reset to 0
      expect(await messagingService.userToKolFeesCollected(user.address, kol.address)).to.equal(0n);
      expect(await messagingService.userToKolLatestMessage(user.address, kol.address)).to.equal(0);
      
      // Second batch: 3 new messages that will go unanswered and timeout
      console.log("\nSending second batch of messages...");
      
      // Record the initial balance before sending the second batch
      const initialSenderBalance = await ethers.provider.getBalance(user.address);
      let totalGasSpent = 0n;
      
      for (let i = 0; i < 3; i++) {
        const tx = await messagingService.connect(user).sendEncryptedMessage(
          kol.address,
          senderPGPPublicKey,
          senderPGPNonce,
          `Second batch message ${i}`,
          { value: DEFAULT_FEE }
        );
        
        const receipt = await tx.wait();
        totalGasSpent += receipt!.gasUsed * receipt!.gasPrice;
      }
      
      // Total fees paid for second batch (only second batch, since first batch was reset)
      const secondBatchFees = DEFAULT_FEE * 3n;
      expect(await messagingService.userToKolFeesCollected(user.address, kol.address)).to.equal(secondBatchFees);
      
      // Let messages expire
      console.log("Advancing time past message deadline...");
      await time.increase(MESSAGE_EXPIRATION + 1);
      
      // Trigger timeout - use a different account to avoid gas cost complexity
      console.log("Triggering timeout for second batch...");
      await messagingService.connect(other).triggerTimeout(user.address, kol.address);
      
      // Calculate expected refund (half of only the second batch fees)
      const expectedRefund = secondBatchFees / 2n;
      
      // Get final balance
      const finalSenderBalance = await ethers.provider.getBalance(user.address);
      
      // Verify sender received the correct refund
      // Initial - total spent on second batch - gas fees + refund
      const expectedBalance = initialSenderBalance - secondBatchFees - totalGasSpent + expectedRefund;
      
      console.log(`\nInitial balance: ${ethers.formatEther(initialSenderBalance)} ETH`);
      console.log(`Final balance: ${ethers.formatEther(finalSenderBalance)} ETH`);
      console.log(`Expected refund: ${ethers.formatEther(expectedRefund)} ETH`);
      
      // Using a tolerance threshold for gas cost estimation differences
      const balanceDiff = expectedBalance > finalSenderBalance 
        ? expectedBalance - finalSenderBalance 
        : finalSenderBalance - expectedBalance;
        
      console.log(`Balance difference: ${ethers.formatEther(balanceDiff)} ETH`);
      expect(balanceDiff).to.be.lessThan(ethers.parseEther("0.01")); // Tolerance of 0.01 ETH
      
      // Verify relationship tracking is reset
      expect(await messagingService.userToKolLatestMessage(user.address, kol.address)).to.equal(0);
      expect(await messagingService.userToKolFeesCollected(user.address, kol.address)).to.equal(0n);
      expect(await messagingService.isActivePair(user.address, kol.address)).to.be.false;
      
      // Platform fee calculation: 
      // - First batch: Fee on full first batch (from the response) 
      // - Second batch: Fee on half of second batch fees (from the timeout)
      const halfSecondBatch = secondBatchFees / 2n;
      const platformFeeTimeout = (halfSecondBatch * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
      const expectedTotalPlatformFees = platformFeeFirstBatch + platformFeeTimeout;
      
      console.log(`Platform fee first batch (response): ${ethers.formatEther(platformFeeFirstBatch)} ETH`);
      console.log(`Platform fee on timeout: ${ethers.formatEther(platformFeeTimeout)} ETH`);
      console.log(`Total platform fees: ${ethers.formatEther(expectedTotalPlatformFees)} ETH`);
      console.log(`Actual accumulated fees: ${ethers.formatEther(await messagingService.accumulatedFees())} ETH`);
      
      expect(await messagingService.accumulatedFees()).to.equal(expectedTotalPlatformFees);
    });
    
    it("Should demonstrate proper reset of userToKolFeesCollected", async function() {
      // This test verifies that userToKolFeesCollected is properly reset after response
      const user = users[0];
      const kol = kols[0];
      
      // 1. Send first message
      await messagingService.connect(user).sendEncryptedMessage(
        kol.address,
        senderPGPPublicKey,
        senderPGPNonce,
        "First message",
        { value: DEFAULT_FEE }
      );
      
      // Verify fees collected
      expect(await messagingService.userToKolFeesCollected(user.address, kol.address)).to.equal(DEFAULT_FEE);
      
      // 2. Respond to first message
      await messagingService.connect(kol).respondToMessage(user.address, "Response");
      
      // Verify fees collected are properly reset to 0
      expect(await messagingService.userToKolFeesCollected(user.address, kol.address)).to.equal(0n);
      
      // 3. Send second message
      await messagingService.connect(user).sendEncryptedMessage(
        kol.address,
        senderPGPPublicKey,
        senderPGPNonce,
        "Second message",
        { value: DEFAULT_FEE }
      );
      
      // Verify fees collected include ONLY the second message
      expect(await messagingService.userToKolFeesCollected(user.address, kol.address)).to.equal(DEFAULT_FEE);
      
      console.log("\nContractFeature: userToKolFeesCollected is properly reset after response");
      console.log(`Current value: ${ethers.formatEther(await messagingService.userToKolFeesCollected(user.address, kol.address))} ETH`);
      console.log("This prevents double-counting of messages in timeout refunds");
    });
  });
}); 