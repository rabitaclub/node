import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { ethers } from "ethers";

const RabitaDeploymentModule = buildModule("RabitaDeploymentModule", (m) => {
  const verifierAddress = m.getParameter(
    "verifierAddress", 
    "0x0000000000000000000000000000000000000000"
  );
  
  const feeCollectorAddress = m.getParameter(
    "feeCollectorAddress", 
    "0x0000000000000000000000000000000000000000"
  );
  const rabitaRegistry = m.contract("RabitaRegistry", [verifierAddress]);
  const messagingService = m.contract("Messaging", [rabitaRegistry, feeCollectorAddress]);
  return { rabitaRegistry, messagingService };
});

export default RabitaDeploymentModule; 