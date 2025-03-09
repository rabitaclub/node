import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import { config as dotenvConfig } from "dotenv";

dotenvConfig();

const config: HardhatUserConfig = {
  solidity: "0.8.28",
  networks: {
    bsc: {
      url: process.env.BSC_URL,
      accounts: [process.env.BSC_KEY || ""],
    },
    testnet: {
      url: process.env.TEST_URL,
      accounts: [process.env.TEST_KEY || ""],
    },
    hardhat: {}
  },
};

export default config;
