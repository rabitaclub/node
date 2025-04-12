import hre from "hardhat";
import { writeFileSync } from "fs";
import { resolve } from "path";

async function main() {
  console.log("Starting Rabita protocol deployment...");

  const [deployer] = await hre.ethers.getSigners();
  const verifierAddress = process.env.VERIFIER_ADDRESS || deployer.address;
  const feeCollectorAddress = process.env.FEE_COLLECTOR_ADDRESS || deployer.address;
  
  console.log(`Deploying with account: ${deployer.address}`);
  console.log(`Verifier account: ${verifierAddress}`);
  console.log(`Fee collector account: ${feeCollectorAddress}`);

  console.log("Deploying contracts using Ignition...");
  const RabitaApp = await hre.ethers.getContractFactory("RabitaRegistry")
  const MessagingService = await hre.ethers.getContractFactory("RabitaMessaging")

  const rabitaRegistry = await RabitaApp.deploy(verifierAddress);
  // const rabitaRegistry = await RabitaApp.attach("0x3cB919f6585c6e18F313722965987604F70c1cBc");
  // const messagingService = await MessagingService.attach("0x3cB919f6585c6e18F313722965987604F70c1cBc");
  const messagingService = await MessagingService.deploy(await rabitaRegistry.getAddress(), feeCollectorAddress);

  const rabitaRegistryAddress = await rabitaRegistry.getAddress();
  const messagingServiceAddress = await messagingService.getAddress();

  console.log(`RabitaRegistry deployed to: ${rabitaRegistryAddress}`);
  console.log(`MessagingService deployed to: ${messagingServiceAddress}`);

  const envContent = `
# Rabita Protocol Deployed Contract Addresses
RABITA_REGISTRY_ADDRESS=${rabitaRegistryAddress}
MESSAGING_SERVICE_ADDRESS=${messagingServiceAddress}
VERIFIER_ADDRESS=${verifierAddress}
FEE_COLLECTOR_ADDRESS=${feeCollectorAddress}

# Configuration Options
# Set to "true" to add a new verifier
ADD_VERIFIER=false
NEW_VERIFIER_ADDRESS=

# Set to "true" to register an initial KOL during configuration
REGISTER_KOL=false
# If not provided, uses a local test account
KOL_ADDRESS=
# Optional: Provide private key if KOL is not a local test account
KOL_PRIVATE_KEY=
KOL_PLATFORM=Twitter
KOL_HANDLE=example_kol
KOL_FEE=0.1
KOL_PROFILE_HASH=QmInitialProfile
`;

  writeFileSync(resolve(__dirname, '../.env.deployment'), envContent);
  console.log("Deployment addresses saved to .env.deployment");
  console.log("To configure contracts, run: npx hardhat run scripts/configureRabita.ts");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  }); 