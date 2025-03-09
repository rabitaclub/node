import hre from "hardhat";
import { writeFileSync } from "fs";
import { resolve } from "path";
import RabitaDeploymentModule from "../ignition/modules/RabitaDeployment";

async function main() {
  console.log("Starting Rabita protocol deployment...");

  const [deployer, verifier, feeCollector] = await hre.ethers.getSigners();
  console.log(`Deploying with account: ${deployer.address}`);
  console.log(`Verifier account: ${verifier.address}`);
  console.log(`Fee collector account: ${feeCollector.address}`);

  console.log("Deploying contracts using Ignition...");
  const result = await hre.ignition.deploy(RabitaDeploymentModule, {
    parameters: {
      RabitaDeploymentModule: {
        verifierAddress: verifier.address,
        feeCollectorAddress: feeCollector.address
      }
    }
  });

  const rabitaRegistryAddress = await result.rabitaRegistry.getAddress();
  const messagingServiceAddress = await result.messagingService.getAddress();

  console.log(`RabitaRegistry deployed to: ${rabitaRegistryAddress}`);
  console.log(`MessagingService deployed to: ${messagingServiceAddress}`);

  const envContent = `
# Rabita Protocol Deployed Contract Addresses
RABITA_REGISTRY_ADDRESS=${rabitaRegistryAddress}
MESSAGING_SERVICE_ADDRESS=${messagingServiceAddress}
VERIFIER_ADDRESS=${verifier.address}
FEE_COLLECTOR_ADDRESS=${feeCollector.address}

# Configuration Options
# Set to "true" to update the verifier during configuration
UPDATE_VERIFIER=false
NEW_VERIFIER_ADDRESS=

# Set to "true" to register an initial KOL during configuration
REGISTER_KOL=false
KOL_ADDRESS=
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