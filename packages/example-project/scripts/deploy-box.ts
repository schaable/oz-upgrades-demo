import { network } from "hardhat";

const { networkName, ethers } = await network.connect();
const [deployer] = await ethers.getSigners();
console.log("Deploying with account:", deployer.address);

// Deploy implementation
const Box = await ethers.getContractFactory("Box");
const boxImpl = await Box.deploy();
await boxImpl.waitForDeployment();
const implAddress = await boxImpl.getAddress();
console.log("Implementation deployed to:", implAddress);

// Encode initialize call
const initData = Box.interface.encodeFunctionData("initialize", [42]);

// Deploy ERC1967Proxy (from @openzeppelin/contracts)
const ERC1967Proxy = await ethers.getContractFactory("ERC1967Proxy");
const proxy = await ERC1967Proxy.deploy(implAddress, initData);
await proxy.waitForDeployment();
const proxyAddress = await proxy.getAddress();
console.log("Proxy deployed to:", proxyAddress);

// Verify value was set
const box = Box.attach(proxyAddress);
console.log("Initial value:", await box.value());

// Output verification commands
console.log("\n--- Verification Commands ---");
console.log("\nTo verify:");
console.log(
  `pnpm hardhat verify etherscan --network ${networkName} ${proxyAddress}`,
);
