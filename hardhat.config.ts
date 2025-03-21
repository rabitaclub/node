import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import { config as dotenvConfig } from "dotenv";

dotenvConfig();

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.28",
    settings: {
      viaIR: true,
    },
  },
  networks: {
    bsc: {
      url: process.env.BSC_URL,
      accounts: [process.env.BSC_KEY || ""],
    },
    testnet: {
      url: process.env.TEST_URL,
      accounts: [process.env.TEST_KEY || ""],
      gasPrice: 5_000_000_000,
    },
    hardhat: {}
  }
};

export default config;
