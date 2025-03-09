import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { RabitaRegistry, Messaging, ReentrancyAttacker } from "../typechain-types";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";

describe("Rabita Protocol", function () {
  let rabitaRegistry: RabitaRegistry;
  let messagingService: Messaging;
  let deployer: SignerWithAddress;
  let verificationSigner: SignerWithAddress;
  let kol: SignerWithAddress;
  let requester: SignerWithAddress;
  let feeCollector: SignerWithAddress;
  let other: SignerWithAddress;

  const DEFAULT_FEE = ethers.parseEther("1");
  const PLATFORM_FEE_PERCENT = 7;
  const MESSAGE_EXPIRATION = 7 * 24 * 60 * 60; // 7 days in seconds

  async function deployContracts() {
    [deployer, verificationSigner, kol, requester, feeCollector, other] = await ethers.getSigners();
    
    const RabitaRegistry = await ethers.getContractFactory("RabitaRegistry");
    rabitaRegistry = await RabitaRegistry.deploy(verificationSigner.address);
    await rabitaRegistry.waitForDeployment();

    const Messaging = await ethers.getContractFactory("Messaging");
    messagingService = await Messaging.deploy(await rabitaRegistry.getAddress(), feeCollector.address);
    await messagingService.waitForDeployment();

    return { rabitaRegistry, messagingService, deployer, verificationSigner, kol, requester, feeCollector, other };
  }

  async function signRegistrationMessage(
    kolAddress: string,
    socialPlatform: string,
    socialHandle: string,
    salt: string,
    signer: SignerWithAddress
  ): Promise<string> {
    const messageHash = ethers.solidityPackedKeccak256(
      ["address", "string", "string", "string"],
      [kolAddress, socialPlatform, socialHandle, salt]
    );
    return await signer.signMessage(ethers.getBytes(messageHash));
  }

  async function registerKOL(
    kol: SignerWithAddress,
    socialPlatform: string = "Twitter",
    socialHandle: string = "test_kol",
    fee: bigint = DEFAULT_FEE
  ) {
    const salt = ethers.hexlify(ethers.randomBytes(32));
    const profileIpfsHash = "QmTest";
    const signature = await signRegistrationMessage(
      kol.address,
      socialPlatform,
      socialHandle,
      salt,
      verificationSigner
    );

    await rabitaRegistry.connect(kol).registerKOL(
      socialPlatform,
      socialHandle,
      fee,
      profileIpfsHash,
      salt,
      signature
    );
  }

  describe("RabitaRegistry", function () {
    beforeEach(async function () {
      await deployContracts();
    });

    describe("Deployment", function () {
      it("should set the correct verifier address", async function () {
        expect(await rabitaRegistry.verifier()).to.equal(verificationSigner.address);
      });

      it("should set the correct owner", async function () {
        expect(await rabitaRegistry.owner()).to.equal(deployer.address);
      });
    });

    describe("KOL Registration", function () {
      it("should register a KOL with valid signature", async function () {
        await registerKOL(kol);
        const profile = await rabitaRegistry.kolProfiles(kol.address);
        expect(profile.verified).to.be.true;
      });

      it("should prevent registration with invalid signature", async function () {
        const salt = ethers.hexlify(ethers.randomBytes(32));
        const signature = await signRegistrationMessage(
          kol.address,
          "Twitter",
          "test_kol",
          salt,
          other // Using wrong signer
        );

        await expect(
          rabitaRegistry.connect(kol).registerKOL(
            "Twitter",
            "test_kol",
            DEFAULT_FEE,
            "QmTest",
            salt,
            signature
          )
        ).to.be.revertedWith("Invalid signature");
      });

      it("should prevent duplicate registration", async function () {
        await registerKOL(kol);
        await expect(registerKOL(kol)).to.be.revertedWith("KOL already registered");
      });

      it("should prevent duplicate registration with same social handle but different wallet", async function () {
        await registerKOL(kol);
        await expect(registerKOL(other, "Twitter", "test_kol", DEFAULT_FEE)).to.be.revertedWith("Social handle already registered");
      });

      it("should emit KOLRegistered event", async function () {
        const salt = ethers.hexlify(ethers.randomBytes(32));
        const signature = await signRegistrationMessage(
          kol.address,
          "Twitter",
          "test_kol",
          salt,
          verificationSigner
        );

        await expect(
          rabitaRegistry.connect(kol).registerKOL(
            "Twitter",
            "test_kol",
            DEFAULT_FEE,
            "QmTest",
            salt,
            signature
          )
        )
          .to.emit(rabitaRegistry, "KOLRegistered")
          .withArgs(kol.address, "Twitter", "test_kol", DEFAULT_FEE, "QmTest");
      });
    });

    describe("Verifier Management", function () {
      it("should allow owner to update verifier", async function () {
        await rabitaRegistry.connect(deployer).updateVerifier(other.address);
        expect(await rabitaRegistry.verifier()).to.equal(other.address);
      });

      it("should prevent non-owner from updating verifier", async function () {
        await expect(
          rabitaRegistry.connect(other).updateVerifier(other.address)
        ).to.be.revertedWithCustomError(rabitaRegistry, "OwnableUnauthorizedAccount")
        .withArgs(other.address);
      });

      it("should prevent setting zero address as verifier", async function () {
        await expect(
          rabitaRegistry.connect(deployer).updateVerifier(ethers.ZeroAddress)
        ).to.be.revertedWith("Invalid verifier address");
      });
    });
  });

  describe("MessagingService", function () {
    beforeEach(async function () {
      await deployContracts();
      await registerKOL(kol);
    });

    describe("Message Sending", function () {
      it("should allow sending message to verified KOL", async function () {
        await expect(
          messagingService.connect(requester).sendMessage(kol.address, "QmMessage", { value: DEFAULT_FEE })
        )
          .to.emit(messagingService, "MessageSent")
          .withArgs(1, requester.address, kol.address, DEFAULT_FEE, anyValue, "QmMessage");
      });

      it("should prevent sending message to unverified KOL", async function () {
        await expect(
          messagingService.connect(requester).sendMessage(other.address, "QmMessage", { value: DEFAULT_FEE })
        ).to.be.revertedWith("Recipient is not a verified KOL");
      });

      it("should prevent sending message with incorrect fee", async function () {
        await expect(
          messagingService.connect(requester).sendMessage(kol.address, "QmMessage", { value: 0 })
        ).to.be.revertedWith("Incorrect fee amount sent");
      });
    });

    describe("Message Response", function () {
      beforeEach(async function () {
        await messagingService.connect(requester).sendMessage(kol.address, "QmMessage", { value: DEFAULT_FEE });
      });

      it("should allow KOL to respond to message", async function () {
        await expect(messagingService.connect(kol).respondMessage(1, "QmResponse"))
          .to.emit(messagingService, "MessageResponded")
          .withArgs(1, kol.address, "QmResponse");
      });

      it("should prevent non-KOL from responding", async function () {
        await expect(
          messagingService.connect(other).respondMessage(1, "QmResponse")
        ).to.be.revertedWith("Only the intended KOL can respond");
      });

      it("should prevent responding after deadline", async function () {
        await time.increase(MESSAGE_EXPIRATION + 1);
        await expect(
          messagingService.connect(kol).respondMessage(1, "QmResponse")
        ).to.be.revertedWith("Deadline has passed");
      });

      it("should distribute fees correctly on response", async function () {
        const initialKolBalance = await ethers.provider.getBalance(kol.address);
        const tx = await messagingService.connect(kol).respondMessage(1, "QmResponse");
        const receipt = await tx.wait();
        const gasUsed = receipt!.gasUsed * receipt!.gasPrice;

        const expectedPlatformFee = (DEFAULT_FEE * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
        const expectedKolPayout = DEFAULT_FEE - expectedPlatformFee;

        const finalKolBalance = await ethers.provider.getBalance(kol.address);
        expect(finalKolBalance).to.equal(
          initialKolBalance + expectedKolPayout - gasUsed
        );
      });
    });

    describe("Message Timeout", function () {
      beforeEach(async function () {
        await messagingService.connect(requester).sendMessage(kol.address, "QmMessage", { value: DEFAULT_FEE });
        await time.increase(MESSAGE_EXPIRATION + 1);
      });

      it("should allow timeout trigger after deadline", async function () {
        await expect(messagingService.triggerTimeout(1))
          .to.emit(messagingService, "MessageTimeoutTriggered")
          .withArgs(1);
      });

      it("should distribute fees correctly on timeout", async function () {
        const initialRequesterBalance = await ethers.provider.getBalance(requester.address);
        const initialKolBalance = await ethers.provider.getBalance(kol.address);

        await messagingService.triggerTimeout(1);

        const refundAmount = DEFAULT_FEE / 2n;
        const remainingFee = DEFAULT_FEE - refundAmount;
        const platformFee = (remainingFee * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
        const kolPayout = remainingFee - platformFee;

        const finalRequesterBalance = await ethers.provider.getBalance(requester.address);
        const finalKolBalance = await ethers.provider.getBalance(kol.address);

        expect(finalRequesterBalance).to.equal(initialRequesterBalance + refundAmount);
        expect(finalKolBalance).to.equal(initialKolBalance + kolPayout);
      });
    });

    describe("Fee Management", function () {
      it("should allow fee collector to claim fees after delay", async function () {
        await messagingService.connect(requester).sendMessage(kol.address, "QmMessage", { value: DEFAULT_FEE });
        await messagingService.connect(kol).respondMessage(1, "QmResponse");
        
        await time.increase(7 * 24 * 60 * 60 + 1); // 1 week + 1 second

        const initialBalance = await ethers.provider.getBalance(feeCollector.address);
        await messagingService.connect(feeCollector).claimFees();
        const finalBalance = await ethers.provider.getBalance(feeCollector.address);

        const expectedFee = (DEFAULT_FEE * BigInt(PLATFORM_FEE_PERCENT)) / 100n;
        expect(finalBalance).to.be.gt(initialBalance);
      });

      it("should prevent fee claims before delay period", async function () {
        await messagingService.connect(requester).sendMessage(kol.address, "QmMessage", { value: DEFAULT_FEE });
        await messagingService.connect(kol).respondMessage(1, "QmResponse");

        await expect(
          messagingService.connect(feeCollector).claimFees()
        ).to.be.revertedWith("Fee claim timelock active");
      });

      it("should prevent non-collector from claiming fees", async function () {
        await expect(
          messagingService.connect(other).claimFees()
        ).to.be.revertedWith("Only fee collector can claim fees");
      });
    });

    describe("Security Tests", function () {
      it("should prevent reentrancy in sendMessage", async function () {
        const AttackerFactory = await ethers.getContractFactory("ReentrancyAttacker");
        const attacker = (await AttackerFactory.deploy(messagingService.getAddress())) as ReentrancyAttacker;
        
        await expect(
          attacker.attack({ value: DEFAULT_FEE })
        ).to.be.reverted;
      });

      it("should handle multiple pending messages correctly", async function () {
        // Send multiple messages
        for(let i = 0; i < 3; i++) {
          await messagingService.connect(requester).sendMessage(kol.address, `QmMessage${i}`, { value: DEFAULT_FEE });
        }

        // Get initial pending messages count
        const initialCount = await messagingService.messageCount();

        // Respond to middle message
        await messagingService.connect(kol).respondMessage(2, "QmResponse");

        // Verify message status
        const message = await messagingService.messages(2);
        expect(message.status).to.equal(1); // 1 = Responded
      });

      it("should prevent unauthorized message responses", async function () {
        // First register a message so we can test with a valid KOL
        await messagingService.connect(requester).sendMessage(kol.address, "QmMessage", { value: DEFAULT_FEE });
        
        // Try to respond to any message ID with non-KOL (should fail with KOL check)
        await expect(
          messagingService.connect(other).respondMessage(999, "QmResponse")
        ).to.be.revertedWith("Only the intended KOL can respond");

        await expect(
          messagingService.connect(other).respondMessage(1, "QmResponse")
        ).to.be.revertedWith("Only the intended KOL can respond");

        // Respond to the message properly first
        await messagingService.connect(kol).respondMessage(1, "QmResponse");

        // Try to respond to an already responded message
        await expect(
          messagingService.connect(kol).respondMessage(1, "QmResponse")
        ).to.be.revertedWith("Message is not pending");
      });
    });
  });
});
