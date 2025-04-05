import { ethers } from "hardhat";
import { RabitaRegistry, RabitaMessaging } from "../typechain-types";

/**
 * Creates a verifier signature for KOL data
 */
async function createVerifierSignature(
  kolAddress: string,
  socialPlatform: string,
  socialHandle: string,
  fee: bigint,
  profileIpfsHash: string,
  expiryTimestamp: number,
  verifierSigner: any
): Promise<string> {
  const messageHash = ethers.solidityPackedKeccak256(
    ["address", "string", "string", "uint256", "string", "uint256"],
    [kolAddress, socialPlatform, socialHandle, fee, profileIpfsHash, expiryTimestamp]
  );
  return await verifierSigner.signMessage(ethers.getBytes(messageHash));
}

/**
 * Creates a KOL signature that wraps the verifier's signature
 */
async function createKolSignature(
  kolAddress: string,
  socialPlatform: string,
  socialHandle: string,
  fee: bigint,
  profileIpfsHash: string,
  expiryTimestamp: number,
  verifierSignature: string,
  kolSigner: any
): Promise<string> {
  const messageHash = ethers.solidityPackedKeccak256(
    ["address", "string", "string", "uint256", "string", "uint256", "bytes"],
    [kolAddress, socialPlatform, socialHandle, fee, profileIpfsHash, expiryTimestamp, verifierSignature]
  );
  return await kolSigner.signMessage(ethers.getBytes(messageHash));
}

async function main() {
  const [deployer, verifier, feeCollector] = await ethers.getSigners();

  console.log("Configuring Rabita protocol with the account:", deployer.address);
  console.log("Account balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)));

  const rabitaRegistryAddress = process.env.RABITA_REGISTRY_ADDRESS;
  const messagingServiceAddress = process.env.MESSAGING_SERVICE_ADDRESS;

  if (!rabitaRegistryAddress || !messagingServiceAddress) {
    throw new Error("Contract addresses not provided. Set RABITA_REGISTRY_ADDRESS and MESSAGING_SERVICE_ADDRESS in your .env file");
  }

  const rabitaRegistry = await ethers.getContractAt("RabitaRegistry", rabitaRegistryAddress) as unknown as RabitaRegistry;
  const messagingService = await ethers.getContractAt("RabitaMessaging", messagingServiceAddress) as unknown as RabitaMessaging;

  console.log("RabitaRegistry address:", await rabitaRegistry.getAddress());
  console.log("MessagingService address:", await messagingService.getAddress());

  const fees = await messagingService.connect(deployer).PLATFORM_FEE_PERCENT();
  console.log("Fees:", fees);

  if (process.env.ADD_VERIFIER === "true") {
    console.log("Adding new verifier...");
    const newVerifierAddress = process.env.NEW_VERIFIER_ADDRESS || verifier.address;
    const tx = await rabitaRegistry.connect(deployer).updateVerifier(newVerifierAddress);
    await tx.wait();
    console.log(`Verifier added: ${newVerifierAddress}`);
  }
  if (process.env.REGISTER_KOL === "true") {
    console.log("Registering initial KOL...");
    
    const kolAddress = process.env.KOL_ADDRESS || (await ethers.getSigners())[2].address;
    const socialPlatform = process.env.KOL_PLATFORM || "Twitter";
    const socialHandle = process.env.KOL_HANDLE || "example_kol";
    const fee = ethers.parseEther(process.env.KOL_FEE || "0.1");
    const profileIpfsHash = process.env.KOL_PROFILE_HASH || "QmInitialProfile";
    
    const expiryTimestamp = Math.floor(Date.now() / 1000) + 3600;
    
    let kolSigner;
    if (process.env.KOL_PRIVATE_KEY) {
      kolSigner = new ethers.Wallet(process.env.KOL_PRIVATE_KEY, ethers.provider);
    } else {
      kolSigner = (await ethers.getSigners())[2]; 
      console.log("Using local account as KOL:", kolSigner.address);
    }
    
    console.log("Creating verifier signature...");
    const verifierSignature = await createVerifierSignature(
      kolSigner.address,
      socialPlatform,
      socialHandle,
      fee,
      profileIpfsHash,
      expiryTimestamp,
      verifier
    );
    console.log("Verifier signature created");
    
    console.log("Creating KOL signature...");
    const kolSignature = await createKolSignature(
      kolSigner.address,
      socialPlatform,
      socialHandle,
      fee,
      profileIpfsHash,
      expiryTimestamp,
      verifierSignature,
      kolSigner
    );
    console.log("KOL signature created");
    
    console.log("Submitting KOL registration...");
    // const tx = await rabitaRegistry.connect(kolSigner).registerKOL(
    //   socialPlatform,
    //   socialHandle,
    //   fee,
    //   profileIpfsHash,
    //   expiryTimestamp,
    //   verifierSignature,
    //   kolSignature
    // );
    // await tx.wait();
    
    // console.log(`KOL registered: ${kolSigner.address} (${socialPlatform}/${socialHandle})`);
  }

  console.log("Configuration complete!");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  }); 