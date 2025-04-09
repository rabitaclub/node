const { ethers } = require("hardhat");

async function main() {
  // Deploy the MockKolRegistry contract
  const MockKolRegistry = await ethers.getContractFactory("MockKolRegistry");
  const mockRegistry = await MockKolRegistry.deploy();
  await mockRegistry.waitForDeployment();
  
  console.log("MockKolRegistry deployed to:", await mockRegistry.getAddress());
  
  // Get the function signatures from the contract ABI
  const mockAbi = MockKolRegistry.interface.fragments;
  
  console.log("\nAvailable methods on MockKolRegistry:");
  mockAbi.forEach(fragment => {
    if (fragment.type === "function") {
      console.log(`- ${fragment.name}(${fragment.inputs.map(input => `${input.type} ${input.name}`).join(", ")})`);
    }
  });
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  }); 