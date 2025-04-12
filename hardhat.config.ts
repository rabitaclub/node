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
  defaultNetwork: "testnet",
  networks: {
    hardhat: {
      accounts: {
        count: 20,
        accountsBalance: "10000000000000000000000"
      }
    },
    bsc: {
      url: process.env.BSC_URL,
      accounts: [process.env.BSC_KEY || ""],
      gasPrice: 3_000_000_000,
    },
    testnet: {
      url: process.env.TEST_URL,
      accounts: [process.env.TEST_KEY || ""],
      gasPrice: 5_000_000_000,
    },
    eth: {
      url: process.env.ETH_URL,
      accounts: [process.env.ETH_KEY || ""],
    },
    polygon: {
      url: process.env.POLYGON_URL,
      accounts: [process.env.POLYGON_KEY || ""],
    },
    arbitrum: {
      url: process.env.ARBITRUM_URL,
      accounts: [process.env.ARBITRUM_KEY || ""],
    },
    optimism: {
      url: process.env.OPTIMISM_URL,
      accounts: [process.env.OPTIMISM_KEY || ""],
    },
    base: {
      url: process.env.BASE_URL,
      accounts: [process.env.BASE_KEY || ""],
    }    
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY,
  },
};

export default config;
