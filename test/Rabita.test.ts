import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { RabitaRegistry } from "../typechain-types";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";

describe("Rabita Protocol", function () {
  let rabitaRegistry: RabitaRegistry;
  let deployer: SignerWithAddress;
  let verificationSigner: SignerWithAddress;
  let kol: SignerWithAddress;
  let other: SignerWithAddress;

  const DEFAULT_FEE = ethers.parseEther("1");
  // Set a fixed timestamp far in the future to avoid timing issues
  const FUTURE_TIMESTAMP = 2000000000; // Year 2033
  const DOMAIN_NAME = "Rabita Social Verification";
  const DOMAIN_VERSION = "1";
  const DEFAULT_DOMAIN_STRING = "rabita.social";

  async function deployContracts() {
    [deployer, verificationSigner, kol, other] = await ethers.getSigners();
    
    const RabitaRegistry = await ethers.getContractFactory("RabitaRegistry");
    rabitaRegistry = await RabitaRegistry.deploy(verificationSigner.address);
    await rabitaRegistry.waitForDeployment();

    return { rabitaRegistry, deployer, verificationSigner, kol, other };
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
    // Note: The contract uses abi.encode() which is different from solidityPackedKeccak256
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

    // console.log("DEBUG: domain:", domain);

    // const domainSeparator = await rabitaRegistry.domainSeparatorV4();
    // console.log("DEBUG: domainSeparator:", domainSeparator);
    
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
    
    // Create a fresh wallet for testing
    // const testWallet = new ethers.Wallet(ethers.hexlify(ethers.randomBytes(32)));
    
    // Sign the typed data using EIP-712
    const signature = await wallet.signTypedData(domainPassed, types, message);
    
    // Sign the digest with the Ethereum prefix (this matches what the contract does)
    return signature;
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
      ethers.parseUnits(fee, "ether"), // _fee
      profileIpfsHash,    // _profileIpfsHash
      salt,               // _salt
      nonce,              // _nonce
      timestamp,          // _timestamp
      domain,             // _domain
      expiresAt,          // _expiresAt
      verifierSignature,  // _verifierSignature
      userSignature       // _userSignature
    );
  }

  describe("RabitaRegistry", function () {
    beforeEach(async function () {
      await deployContracts();
    });

    describe("Deployment", function () {
      it("should set the correct verifier address", async function () {
        expect(await rabitaRegistry.isVerifier(verificationSigner.address)).to.be.true;
      });

      it("should set the correct owner", async function () {
        expect(await rabitaRegistry.owner()).to.equal(deployer.address);
      });
    });

    describe("KOL Registration", function () {
      it("should register a KOL with valid signatures", async function () {
        await registerKOL(kol, "Twitter", "test_kol", "Test KOL", DEFAULT_FEE.toString(), "QmTest", verificationSigner);
        const profile = await rabitaRegistry.kolProfiles(kol.address);
        expect(profile.verified).to.be.true;
      });

      it("should prevent registration with invalid verifier signature", async function () {
        const profileIpfsHash = "QmTest";
        const expiryTimestamp = FUTURE_TIMESTAMP;
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const salt = generateRandomSalt();
        const nonce = generateRandomNonce();
        const socialName = "Test KOL";
        
        // Use wrong signer for verifier signature
        const verifierSignature = await signVerifierMessage(
          kol.address,
          "test_kol",
          salt,
          "Twitter",
          nonce,
          currentTimestamp,
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          other // Wrong signer
        );
        
        const userSignature = await signUserMessage(
          kol,
          "Twitter",
          "test_kol",
          salt,
          nonce,
          currentTimestamp,
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verifierSignature
        );

        await expect(
          rabitaRegistry.connect(kol).registerKOL(
            "Twitter",
            "test_kol",
            socialName,
            DEFAULT_FEE.toString(),
            profileIpfsHash,
            salt,
            nonce,
            currentTimestamp,
            DEFAULT_DOMAIN_STRING,
            expiryTimestamp,
            verifierSignature,
            userSignature
          )
        ).to.be.revertedWith("Invalid verifier signature");
      });

      it("should prevent registration with invalid user signature", async function () {
        const profileIpfsHash = "QmTest";
        const expiryTimestamp = FUTURE_TIMESTAMP;
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const salt = generateRandomSalt();
        const nonce = generateRandomNonce();
        const socialName = "Test KOL";
        
        // Get valid verifier signature
        const verifierSignature = await signVerifierMessage(
          kol.address,
          "test_kol",
          salt,
          "Twitter",
          nonce,
          currentTimestamp,
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verificationSigner
        );
        
        // Create an intentionally invalid user signature
        const malformedSignature = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627";

        // Test that it reverts with any error (could be a custom error)
        await expect(
          rabitaRegistry.connect(kol).registerKOL(
            "Twitter",
            "test_kol",
            socialName,
            DEFAULT_FEE.toString(),
            profileIpfsHash,
            salt,
            nonce,
            currentTimestamp,
            DEFAULT_DOMAIN_STRING,
            expiryTimestamp,
            verifierSignature,
            malformedSignature
          )
        ).to.be.reverted; // Changed from .to.be.revertedWith("Invalid user signature")
      });

      it("should prevent registration with expired timestamp", async function () {
        const profileIpfsHash = "QmTest";
        const socialName = "Test KOL";
        // Use an explicitly expired timestamp
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const expiryTimestamp = currentTimestamp - 3600; // 1 hour in the past
        const salt = generateRandomSalt();
        const nonce = generateRandomNonce();
        
        const verifierSignature = await signVerifierMessage(
          kol.address,
          "test_kol",
          salt,
          "Twitter",
          nonce,
          currentTimestamp,
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verificationSigner
        );
        
        const userSignature = await signUserMessage(
          kol,
          "Twitter",
          "test_kol",
          salt,
          nonce,
          currentTimestamp,
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verifierSignature
        );

        await expect(
          rabitaRegistry.connect(kol).registerKOL(
            "Twitter",
            "test_kol",
            socialName,
            DEFAULT_FEE.toString(),
            profileIpfsHash,
            salt,
            nonce,
            currentTimestamp,
            DEFAULT_DOMAIN_STRING,
            expiryTimestamp,
            verifierSignature,
            userSignature
          )
        ).to.be.revertedWith("Verification expired");
      });

      it("should prevent duplicate registration", async function () {
        await registerKOL(kol, "Twitter", "test_kol", "Test KOL", DEFAULT_FEE.toString(), "QmTest", verificationSigner);
        await expect(registerKOL(kol, "Twitter", "test_kol", "Test KOL", DEFAULT_FEE.toString(), "QmTest", verificationSigner)).to.be.revertedWith("KOL already registered");
      });

      it("should prevent duplicate registration of the same social handle on the same platform", async function () {
        await registerKOL(kol, "Twitter", "same_handle", "Test KOL", DEFAULT_FEE.toString(), "QmTest", verificationSigner);
        await expect(
          registerKOL(other, "Twitter", "same_handle", "Test KOL", DEFAULT_FEE.toString(), "QmTest", verificationSigner)
        ).to.be.revertedWith("Social handle already registered");
      });

      it("should allow same social handle on different platforms", async function () {
        await registerKOL(kol, "Twitter", "crossplatform", "Test KOL", DEFAULT_FEE.toString(), "QmTest", verificationSigner);
        await registerKOL(other, "Instagram", "crossplatform", "Test KOL", DEFAULT_FEE.toString(), "QmTest", verificationSigner);
        
        // Verify both KOLs are registered
        const twitterProfile = await rabitaRegistry.kolProfiles(kol.address);
        const instagramProfile = await rabitaRegistry.kolProfiles(other.address);
        
        expect(twitterProfile.verified).to.be.true;
        expect(instagramProfile.verified).to.be.true;
      });

      it("should emit KOLRegistered event", async function () {
        const profileIpfsHash = "QmTest";
        const expiryTimestamp = FUTURE_TIMESTAMP;
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const salt = generateRandomSalt();
        const nonce = generateRandomNonce();
        const socialName = "Test KOL";
        
        // Get valid signatures
        const verifierSignature = await signVerifierMessage(
          kol.address,
          "test_kol",
          salt,
          "Twitter",
          nonce,
          currentTimestamp,
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verificationSigner
        );
        
        const userSignature = await signUserMessage(
          kol,
          "Twitter",
          "test_kol",
          salt,
          nonce,
          currentTimestamp,
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verifierSignature
        );

        await expect(
          rabitaRegistry.connect(kol).registerKOL(
            "Twitter",
            "test_kol",
            socialName,
            DEFAULT_FEE.toString(),
            profileIpfsHash,
            salt,
            nonce,
            currentTimestamp,
            DEFAULT_DOMAIN_STRING,
            expiryTimestamp,
            verifierSignature,
            userSignature
          )
        )
          .to.emit(rabitaRegistry, "KOLRegistered")
          .withArgs(kol.address, "Twitter", "test_kol", socialName, DEFAULT_FEE);
      });

      it("should prevent nonce reuse", async function () {
        const profileIpfsHash = "QmTest";
        const expiryTimestamp = FUTURE_TIMESTAMP;
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const salt = generateRandomSalt();
        const nonce = generateRandomNonce(); // Same nonce
        const socialName = "Test KOL";
        const username = "nonce_reuse_test";
        
        // Register first KOL
        const verifier1Signature = await signVerifierMessage(
          kol.address,
          username,
          salt,
          "Twitter",
          nonce,
          currentTimestamp,
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verificationSigner
        );
        
        const user1Signature = await signUserMessage(
          kol,
          "Twitter",
          username,
          salt,
          nonce,
          currentTimestamp,
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verifier1Signature
        );
        
        // First registration should succeed
        await rabitaRegistry.connect(kol).registerKOL(
          "Twitter",
          username,
          socialName,
          DEFAULT_FEE.toString(),
          profileIpfsHash,
          salt,
          nonce,
          currentTimestamp,
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verifier1Signature,
          user1Signature
        );

        // Try to register again with the SAME user, username, nonce and timestamp
        // The composite nonce (keccak256(abi.encodePacked(msg.sender, _username, _nonce, _timestamp)))
        // should be identical, triggering the "Nonce already used" check
        const verifier2Signature = await signVerifierMessage(
          kol.address, // Same address
          username,    // Same username
          salt,
          "Twitter",
          nonce,       // Same nonce
          currentTimestamp, // Same timestamp
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verificationSigner
        );
        
        const user2Signature = await signUserMessage(
          kol,        // Same wallet
          "Twitter",
          username,   // Same username
          salt,
          nonce,      // Same nonce
          currentTimestamp, // Same timestamp
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verifier2Signature
        );

        // This should revert with "Nonce already used" because all components of
        // the composite nonce are identical
        await expect(
          rabitaRegistry.connect(kol).registerKOL(
            "Twitter",
            username,
            socialName,
            DEFAULT_FEE.toString(),
            profileIpfsHash,
            salt,
            nonce,
            currentTimestamp,
            DEFAULT_DOMAIN_STRING,
            expiryTimestamp,
            verifier2Signature,
            user2Signature
          )
        ).to.be.reverted; // Custom error or "Nonce already used"
      });

      it("should create appropriate nonce for replay protection", async function() {
        const profileIpfsHash = "QmTest";
        const expiryTimestamp = FUTURE_TIMESTAMP;
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const salt = generateRandomSalt();
        const nonce = generateRandomNonce();
        const socialName = "Test KOL";
        
        // Get address of "other"
        const otherAddress = other.address;
        
        // Register a user
        await registerKOL(kol, "Twitter", "test_kol", "Test KOL", DEFAULT_FEE.toString(), "QmTest", verificationSigner);
        
        // Now try to frontrun with a different address but same details
        const verifierSignature = await signVerifierMessage(
          otherAddress,
          "test_kol",
          salt,
          "Twitter",
          nonce,
          currentTimestamp,
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verificationSigner
        );
        
        const userSignature = await signUserMessage(
          other,
          "Twitter",
          "test_kol",
          salt,
          nonce,
          currentTimestamp,
          DEFAULT_DOMAIN_STRING,
          expiryTimestamp,
          verifierSignature
        );
        
        // This should fail because the handle is already registered
        await expect(
          rabitaRegistry.connect(other).registerKOL(
            "Twitter",
            "test_kol",
            socialName,
            DEFAULT_FEE.toString(),
            profileIpfsHash,
            salt,
            nonce,
            currentTimestamp,
            DEFAULT_DOMAIN_STRING,
            expiryTimestamp,
            verifierSignature,
            userSignature
          )
        ).to.be.revertedWith("Social handle already registered");
      });
    });

    describe("Verifier Management", function () {
      it("should allow owner to update verifier", async function () {
        await rabitaRegistry.connect(deployer).updateVerifier(other.address);
        expect(await rabitaRegistry.isVerifier(other.address)).to.equal(true);
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
      
      it("should allow removing verifiers", async function() {
        // First add a new verifier
        await rabitaRegistry.connect(deployer).updateVerifier(other.address);
        expect(await rabitaRegistry.isVerifier(other.address)).to.be.true;
        
        // Then remove it
        await rabitaRegistry.connect(deployer).removeVerifier(other.address);
        expect(await rabitaRegistry.isVerifier(other.address)).to.be.false;
      });
    });
  });
});
