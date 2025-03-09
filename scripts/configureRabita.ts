import { ethers } from "hardhat";
import { RabitaRegistry, Messaging } from "../typechain-types";

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
  const messagingService = await ethers.getContractAt("Messaging", messagingServiceAddress) as unknown as Messaging;

  console.log("RabitaRegistry address:", await rabitaRegistry.getAddress());
  console.log("MessagingService address:", await messagingService.getAddress());

  if (process.env.UPDATE_VERIFIER === "true") {
    console.log("Updating verifier address...");
    const newVerifierAddress = process.env.NEW_VERIFIER_ADDRESS || verifier.address;
    const tx = await rabitaRegistry.connect(deployer).updateVerifier(newVerifierAddress);
    await tx.wait();
    console.log(`Verifier updated to: ${newVerifierAddress}`);
  }

  if (process.env.REGISTER_KOL === "true") {
    console.log("Registering initial KOL...");
    const kolAddress = process.env.KOL_ADDRESS || (await ethers.getSigners())[2].address;
    const socialPlatform = process.env.KOL_PLATFORM || "Twitter";
    const socialHandle = process.env.KOL_HANDLE || "example_kol";
    const fee = ethers.parseEther(process.env.KOL_FEE || "0.1");
    const profileIpfsHash = process.env.KOL_PROFILE_HASH || "QmInitialProfile";
    const salt = ethers.hexlify(ethers.randomBytes(32));
    
    const messageHash = ethers.solidityPackedKeccak256(
      ["address", "string", "string", "string"],
      [kolAddress, socialPlatform, socialHandle, salt]
    );
    const signature = await verifier.signMessage(ethers.getBytes(messageHash));
    
    const kolSigner = await ethers.getSigner(kolAddress);
    const tx = await rabitaRegistry.connect(kolSigner).registerKOL(
      socialPlatform,
      socialHandle,
      fee,
      profileIpfsHash,
      salt,
      signature
    );
    console.log("tx", tx.hash);
    await tx.wait();
    
    console.log(`KOL registered: ${kolAddress}`);
  }

  console.log("Configuration complete!");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  }); 