import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { RabitaMessaging, MockKolRegistry } from "../typechain-types";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { randomBytes, createCipheriv, createDecipheriv, publicEncrypt, privateDecrypt } from "crypto";
import { generateKeyPairSync } from 'crypto';
import { TypedDataDomain, TypedDataField } from "ethers";

// Types
interface MessageData {
  messageHash: string;
  encryptionProof: string;
  encryptedSymmetricKey: string;
  messageNonce: string;
  version: number;
  timestamp: number;
  content?: string;
  ipfsHash?: string;
  contentDigest: string;
}

interface EncryptedMessageContent {
  iv: string;
  encryptedData: string;
  ipfsHash: string;
  contentDigest: string;
}

interface KolProfile {
  wallet: string;
  socialPlatform: string;
  socialHandle: string;
  fee: bigint;
  profileIpfsHash: string;
  verified: boolean;
}

// Mock IPFS storage
class MockIPFS {
  private static storage: Map<string, string> = new Map();

  static async add(content: string): Promise<string> {
    // Generate a mock IPFS hash (in reality this would be content-addressed)
    const hash = "Qm" + ethers.hexlify(randomBytes(32)).slice(2);
    // console.log("Adding content to IPFS:", content);
    this.storage.set(hash, content);
    return hash;
  }

  static async get(hash: string): Promise<string> {
    const content = this.storage.get(hash);
    if (!content) throw new Error(`Content not found for hash: ${hash}`);
    return content;
  }
}

// EIP-712 Types
const EIP712_DOMAIN = {
  name: 'RabitaMessaging',
  version: '1',
  chainId: 31337, // Hardhat's default chainId
};

const ENCRYPTION_TYPES = {
  EncryptedMessage: [
    { name: 'messageHash', type: 'bytes32' },
    { name: 'recipient', type: 'address' },
    { name: 'timestamp', type: 'uint256' },
    { name: 'contentDigest', type: 'bytes32' },
  ],
};

// Encryption utilities
class MessageEncryption {
  private static keyPairs = new Map<string, { publicKey: string, privateKey: string }>();

  static generateKeyPair(address: string) {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    
    this.keyPairs.set(address, { publicKey, privateKey });
    return { publicKey, privateKey };
  }

  static getKeyPair(address: string) {
    let keyPair = this.keyPairs.get(address);
    if (!keyPair) {
      keyPair = this.generateKeyPair(address);
    }
    return keyPair;
  }

  static async encryptMessage(
    message: string,
    recipientAddress: string,
    recipientSigner: SignerWithAddress
  ): Promise<{
    encryptedContent: EncryptedMessageContent;
    encryptedSymmetricKey: string;
    messageHash: string;
    encryptionProof: string;
    timestamp: number;
  }> {
    // Generate a random symmetric key for this message
    const symmetricKey = randomBytes(32);
    const iv = randomBytes(16);

    // Encrypt the message content with the symmetric key
    const cipher = createCipheriv('aes-256-cbc', symmetricKey, iv);
    let encryptedData = cipher.update(message, 'utf8', 'hex');
    encryptedData += cipher.final('hex');

    // Get recipient's public key
    const recipientKeys = this.getKeyPair(recipientAddress);

    // Encrypt the symmetric key with recipient's public key
    const encryptedSymmetricKey = publicEncrypt(
      recipientKeys.publicKey,
      symmetricKey
    ).toString('hex');

    // Create content hash for verification
    const contentDigest = ethers.keccak256(
      ethers.solidityPacked(
        ['bytes', 'bytes'],
        ['0x' + encryptedData, '0x' + iv.toString('hex')]
      )
    );

    // Store encrypted content in IPFS
    const content = JSON.stringify({
      iv: iv.toString('hex'),
      encryptedData
    });
    const ipfsHash = await MockIPFS.add(content);

    // Get current block timestamp
    const block = await ethers.provider.getBlock('latest');
    if (!block) throw new Error('Failed to get latest block');
    const timestamp = block.timestamp;

    // Create message hash as per contract's _verifyEncryptionProof function
    const messageDataHash = ethers.keccak256(
      ethers.solidityPacked(
        ['address', 'bytes32', 'uint256'],
        [recipientAddress, contentDigest, timestamp]
      )
    );

    // Sign the message hash as the recipient
    const encryptionProof = await recipientSigner.signMessage(
      ethers.getBytes(messageDataHash)
    );

    return {
      encryptedContent: {
        iv: iv.toString('hex'),
        encryptedData,
        ipfsHash,
        contentDigest
      },
      encryptedSymmetricKey: '0x' + encryptedSymmetricKey,
      messageHash: messageDataHash,
      encryptionProof,
      timestamp
    };
  }

  static async decryptMessage(
    ipfsHash: string,
    encryptedSymmetricKey: string,
    recipientAddress: string
  ): Promise<string> {
    // Get recipient's private key
    const recipientKeys = this.getKeyPair(recipientAddress);

    // Remove '0x' prefix if present
    const encryptedKeyHex = encryptedSymmetricKey.startsWith('0x') 
      ? encryptedSymmetricKey.slice(2)
      : encryptedSymmetricKey;

    // Decrypt the symmetric key using recipient's private key
    const symmetricKey = privateDecrypt(
      recipientKeys.privateKey,
      Buffer.from(encryptedKeyHex, 'hex')
    );

    // Get encrypted content from IPFS
    const content = await MockIPFS.get(ipfsHash);
    const { iv, encryptedData } = JSON.parse(content);

    // Decrypt the message using the symmetric key
    const decipher = createDecipheriv(
      'aes-256-cbc',
      symmetricKey,
      Buffer.from(iv, 'hex')
    );

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  static verifySignature(
    signer: string,
    messageHash: string,
    signature: string,
    recipientAddress: string,
    timestamp: number,
    contentDigest: string
  ): boolean {
    try {
      // Recreate the message data hash
      const messageDataHash = ethers.keccak256(
        ethers.solidityPacked(
          ['address', 'bytes32', 'uint256'],
          [recipientAddress, contentDigest, timestamp]
        )
      );

      // Verify the signature
      const recoveredAddress = ethers.verifyMessage(
        ethers.getBytes(messageDataHash),
        signature
      );
      return recoveredAddress.toLowerCase() === signer.toLowerCase();
    } catch (error) {
      return false;
    }
  }
}

describe("RabitaMessaging", function () {
  // Constants
  const MESSAGE_EXPIRATION = 7 * 24 * 60 * 60; // 7 days in seconds
  const PLATFORM_FEE_PERCENT = 7;
  const DEFAULT_FEE = ethers.parseEther("0.1");
  const FEE_CLAIM_DELAY = 7 * 24 * 60 * 60; // 1 week in seconds

  // Contracts
  let messagingService: RabitaMessaging;
  let mockKolRegistry: MockKolRegistry;

  // Signers
  let deployer: SignerWithAddress;
  let feeCollector: SignerWithAddress;
  let kol: SignerWithAddress;
  let user: SignerWithAddress;
  let other: SignerWithAddress;

  // Helper functions
  function generateRandomBytes32(): string {
    return ethers.hexlify(ethers.randomBytes(32));
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
      fee,
      "ipfs://test",
      verified
    );
  }

  beforeEach(async function () {
    [deployer, feeCollector, kol, user, other] = await ethers.getSigners();

    // Deploy mock KOL registry
    const MockKolRegistry = await ethers.getContractFactory("MockKolRegistry");
    mockKolRegistry = await MockKolRegistry.deploy();

    // Deploy messaging service
    const RabitaMessaging = await ethers.getContractFactory("RabitaMessaging");
    messagingService = await RabitaMessaging.deploy(
      await mockKolRegistry.getAddress(),
      feeCollector.address
    );

    // Setup default KOL profile
    await setupMockKOLProfile(kol.address);
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
    let encryptedSalt: string;
    let messageNonce: string;

    beforeEach(async function () {
      encryptedSalt = generateRandomBytes32();
      messageNonce = generateRandomBytes32();
    });

    it("Should allow sending message to verified KOL", async function () {
      const tx = await messagingService.connect(user).sendEncryptedMessage(
        kol.address,
        encryptedSalt,
        messageNonce,
        testContent,
        { value: DEFAULT_FEE }
      );

      await expect(tx)
        .to.emit(messagingService, "MessageSent")
        .withArgs(
          1, // messageId
          user.address,
          kol.address,
          DEFAULT_FEE,
          anyValue, // deadline
          testContent
        );

      const message = await messagingService.messages(1);
      expect(message.sender).to.equal(user.address);
      expect(message.kol).to.equal(kol.address);
      expect(message.fee).to.equal(DEFAULT_FEE);
      expect(message.content).to.equal(testContent);
      expect(message.status).to.equal(0); // Pending

      const metadata = await messagingService.messageMetadata(1);
      expect(metadata.encryptedSalt).to.equal(encryptedSalt);
      expect(metadata.messageNonce).to.equal(messageNonce);
      expect(metadata.version).to.equal(1);
    });

    it("Should revert when sending to unverified KOL", async function () {
      await setupMockKOLProfile(kol.address, DEFAULT_FEE, false);

      await expect(
        messagingService.connect(user).sendEncryptedMessage(
          kol.address,
          encryptedSalt,
          messageNonce,
          testContent,
          { value: DEFAULT_FEE }
        )
      ).to.be.revertedWithCustomError(messagingService, "NotVerifiedKOL");
    });

    it("Should revert when sending with incorrect fee", async function () {
      await expect(
        messagingService.connect(user).sendEncryptedMessage(
          kol.address,
          encryptedSalt,
          messageNonce,
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
    let encryptedSalt: string;
    let messageNonce: string;

    beforeEach(async function () {
      encryptedSalt = generateRandomBytes32();
      messageNonce = generateRandomBytes32();

      await messagingService.connect(user).sendEncryptedMessage(
        kol.address,
        encryptedSalt,
        messageNonce,
        testContent,
        { value: DEFAULT_FEE }
      );
      messageId = 1n;
    });

    it("Should allow KOL to respond to message", async function () {
      const tx = await messagingService
        .connect(kol)
        .respondToEncryptedMessage(messageId, responseContent);

      await expect(tx)
        .to.emit(messagingService, "MessageResponded")
        .withArgs(messageId, kol.address, responseContent);

      const message = await messagingService.messages(messageId);
      expect(message.status).to.equal(1); // Responded

      // Check platform fee calculation
      const platformFee = (DEFAULT_FEE * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
      const netPayout = DEFAULT_FEE - platformFee;

      expect(await messagingService.accumulatedFees()).to.equal(platformFee);
    });

    it("Should revert when non-KOL tries to respond", async function () {
      await expect(
        messagingService
          .connect(other)
          .respondToEncryptedMessage(messageId, responseContent)
      ).to.be.revertedWithCustomError(messagingService, "NotAuthorizedKOL");
    });

    it("Should revert when message has expired", async function () {
      await time.increase(MESSAGE_EXPIRATION + 1);

      await expect(
        messagingService
          .connect(kol)
          .respondToEncryptedMessage(messageId, responseContent)
      ).to.be.revertedWithCustomError(messagingService, "MessageDeadlinePassed");
    });
  });

  describe("Message Timeout", function () {
    const testContent = "Test message content";
    let messageId: bigint;
    let encryptedSalt: string;
    let messageNonce: string;

    beforeEach(async function () {
      encryptedSalt = generateRandomBytes32();
      messageNonce = generateRandomBytes32();

      await messagingService.connect(user).sendEncryptedMessage(
        kol.address,
        encryptedSalt,
        messageNonce,
        testContent,
        { value: DEFAULT_FEE }
      );
      messageId = 1n;
    });

    it("Should allow triggering timeout after deadline", async function () {
      await time.increase(MESSAGE_EXPIRATION + 1);

      const tx = await messagingService.triggerTimeout(messageId);

      await expect(tx)
        .to.emit(messagingService, "MessageTimeoutTriggered")
        .withArgs(messageId);

      const message = await messagingService.messages(messageId);
      expect(message.status).to.equal(2); // Expired

      // Check refund and fee calculations
      const refundAmount = DEFAULT_FEE / 2n;
      const remainingAmount = DEFAULT_FEE - refundAmount;
      const platformFee = (remainingAmount * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
      const netPayout = remainingAmount - platformFee;

      expect(await messagingService.accumulatedFees()).to.equal(platformFee);
    });

    it("Should revert timeout trigger before deadline", async function () {
      await expect(
        messagingService.triggerTimeout(messageId)
      ).to.be.revertedWithCustomError(messagingService, "DeadlineNotReached");
    });
  });

  describe("Fee Collection", function () {
    const testContent = "Test message content";
    let encryptedSalt: string;
    let messageNonce: string;

    beforeEach(async function () {
      encryptedSalt = generateRandomBytes32();
      messageNonce = generateRandomBytes32();

      // Send and respond to a message to accumulate fees
      await messagingService.connect(user).sendEncryptedMessage(
        kol.address,
        encryptedSalt,
        messageNonce,
        testContent,
        { value: DEFAULT_FEE }
      );

      await messagingService
        .connect(kol)
        .respondToEncryptedMessage(1n, "Response");
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
}); 