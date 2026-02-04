import type { Etherscan } from "@nomicfoundation/hardhat-verify/types";
import type { BuildInfo } from "hardhat/types/artifacts";

import {
  getTransactionByHash,
  getImplementationAddress,
  getBeaconAddress,
  getImplementationAddressFromBeacon,
  UpgradesError,
  getAdminAddress,
  isTransparentOrUUPSProxy,
  isBeacon,
  isBeaconProxy,
  isEmptySlot,
  getCode,
} from "@openzeppelin/upgrades-core";
import artifactsBuildInfo from "@openzeppelin/upgrades-core/artifacts/build-info-v5.json" with { type: "json" };

import ERC1967Proxy from "@openzeppelin/upgrades-core/artifacts/@openzeppelin/contracts-v5/proxy/ERC1967/ERC1967Proxy.sol/ERC1967Proxy.json" with { type: "json" };
import BeaconProxy from "@openzeppelin/upgrades-core/artifacts/@openzeppelin/contracts-v5/proxy/beacon/BeaconProxy.sol/BeaconProxy.json" with { type: "json" };
import UpgradeableBeacon from "@openzeppelin/upgrades-core/artifacts/@openzeppelin/contracts-v5/proxy/beacon/UpgradeableBeacon.sol/UpgradeableBeacon.json" with { type: "json" };
import TransparentUpgradeableProxy from "@openzeppelin/upgrades-core/artifacts/@openzeppelin/contracts-v5/proxy/transparent/TransparentUpgradeableProxy.sol/TransparentUpgradeableProxy.json" with { type: "json" };
import ProxyAdmin from "@openzeppelin/upgrades-core/artifacts/@openzeppelin/contracts-v5/proxy/transparent/ProxyAdmin.sol/ProxyAdmin.json" with { type: "json" };
import { keccak256 } from "ethereumjs-util";

import { TaskOverrideActionFunction } from "hardhat/types/tasks";
import { EthereumProvider } from "hardhat/types/providers";
import { Artifact } from "hardhat/types/artifacts";
import debug from "../../../utils/debug.js";

/**
 * A contract artifact and the corresponding event that it logs during construction.
 */
interface VerifiableContractInfo {
  artifact: Artifact;
  event: string;
}

interface ErrorReport {
  errors: string[];
  severity: "error" | "warn";
}

/**
 * Etherscan API response when getting event logs by address and topic.
 */
interface EtherscanEventResponse {
  topics: string[];
  transactionHash: string;
}

/**
 * The proxy-related contracts and their corresponding events that may have been deployed the current version of this plugin.
 */
const verifiableContracts = {
  erc1967proxy: {
    artifact: ERC1967Proxy as Artifact,
    event: "Upgraded(address)",
  },
  beaconProxy: {
    artifact: BeaconProxy as Artifact,
    event: "BeaconUpgraded(address)",
  },
  upgradeableBeacon: {
    artifact: UpgradeableBeacon as Artifact,
    event: "OwnershipTransferred(address,address)",
  },
  transparentUpgradeableProxy: {
    artifact: TransparentUpgradeableProxy as Artifact,
    event: "AdminChanged(address,address)",
  },
  proxyAdmin: {
    artifact: ProxyAdmin as Artifact,
    event: "OwnershipTransferred(address,address)",
  },
};

const RESPONSE_OK = "1";

// TODO: Consider splitting this file into modules (e.g., errors.ts, etherscan-api.ts, verify.ts).
// Hardhat usually keeps only the action function in task-action files, though is not a requirement and
// having helper functions here is also fine.

const verifyEtherscanAction: TaskOverrideActionFunction = async (
  args,
  hre,
  runSuper,
) => {
  const {
    provider,
    verifier: { etherscan },
  } = await hre.network.connect();
  // TODO: validate the address to avoid casting
  const proxyAddress = args.address as string;
  const errorReport: ErrorReport = {
    errors: [],
    severity: "error",
  };

  let proxy = true;

  if (await isTransparentOrUUPSProxy(provider, proxyAddress)) {
    await fullVerifyTransparentOrUUPS(
      provider,
      etherscan,
      proxyAddress,
      hardhatVerify,
      errorReport,
    );
  } else if (await isBeaconProxy(provider, proxyAddress)) {
    await fullVerifyBeaconProxy(
      provider,
      etherscan,
      proxyAddress,
      hardhatVerify,
      errorReport,
    );
  } else if (await isBeacon(provider, proxyAddress)) {
    proxy = false;
    await fullVerifyBeacon(
      provider,
      proxyAddress,
      hardhatVerify,
      etherscan,
      errorReport,
    );
  } else {
    // Doesn't look like a proxy, so just verify directly
    return hardhatVerify(proxyAddress);
  }

  if (errorReport.errors.length > 0) {
    displayErrorReport(errorReport);
  } else {
    console.info(`\n${proxy ? "Proxy" : "Contract"} fully verified.`);
  }

  async function hardhatVerify(address: string): Promise<unknown> {
    return await runSuper({ ...args, address });
  }
};

/**
 * Throws or warns with a formatted summary of all of the verification errors that have been recorded.
 *
 * @param errorReport Accumulated verification errors
 * @throws UpgradesError if errorReport.severity is 'error'
 */
function displayErrorReport(errorReport: ErrorReport) {
  let summary = `\nVerification completed with the following ${
    errorReport.severity === "error" ? "errors" : "warnings"
  }.`;
  for (let i = 0; i < errorReport.errors.length; i++) {
    const error = errorReport.errors[i];
    summary += `\n\n${errorReport.severity === "error" ? "Error" : "Warning"} ${i + 1}: ${error}`;
  }
  if (errorReport.severity === "error") {
    throw new UpgradesError(summary);
  } else {
    console.warn(summary);
  }
}

/**
 * Log an error about the given contract's verification attempt, and save it so it can be summarized at the end.
 *
 * @param address The address that failed to verify
 * @param contractType The type or name of the contract
 * @param details The error details
 * @param errorReport Accumulated verification errors
 */
function recordVerificationError(
  address: string,
  contractType: string,
  details: string,
  errorReport: ErrorReport,
) {
  const message = `Failed to verify ${contractType} contract at ${address}: ${details}`;
  recordError(message, errorReport);
}

function recordError(message: string, errorReport: ErrorReport) {
  console.error(message);
  errorReport.errors.push(message);
}

/**
 * Indicates that the expected event topic was not found in the contract's logs according to the Etherscan API, or an expected function was not found.
 */
class EventOrFunctionNotFound extends UpgradesError {}

class EventsNotFound extends EventOrFunctionNotFound {
  constructor(address: string, events: string[]) {
    super(
      `Could not find an event with any of the following topics in the logs for address ${address}: ${events.join(
        ", ",
      )}`,
      () =>
        "If the proxy was recently deployed, the transaction may not be available on Etherscan yet. Try running the verify task again after waiting a few blocks.",
    );
  }
}

/**
 * Indicates that the contract's bytecode does not match with the plugin's artifact.
 */
class BytecodeNotMatchArtifact extends Error {
  contractName: string;
  constructor(message: string, contractName: string) {
    super(message);
    this.contractName = contractName;
  }
}

/**
 * Fully verifies all contracts related to the given transparent or UUPS proxy address: implementation, admin (if any), and proxy.
 * Also links the proxy to the implementation ABI on Etherscan.
 *
 * This function will determine whether the address is a transparent or UUPS proxy based on whether its creation bytecode matches with
 * TransparentUpgradeableProxy or ERC1967Proxy.
 *
 * Note: this function does not use the admin slot to determine whether the proxy is transparent or UUPS, but will always verify
 * the admin address as long as the admin storage slot has an address.
 *
 * @param hre
 * @param proxyAddress The transparent or UUPS proxy address
 * @param hardhatVerify A function that invokes the hardhat-verify plugin's verify command
 * @param errorReport Accumulated verification errors
 */
export async function fullVerifyTransparentOrUUPS(
  provider: EthereumProvider,
  etherscan: Etherscan,
  proxyAddress: string,
  hardhatVerify: (address: string) => Promise<unknown>,
  errorReport: ErrorReport,
) {
  const implAddress = await getImplementationAddress(provider, proxyAddress);
  await verifyImplementation(hardhatVerify, implAddress, errorReport);

  await verifyTransparentOrUUPS();
  await linkProxyWithImplementationAbi(
    etherscan,
    proxyAddress,
    implAddress,
    errorReport,
  );
  // Either UUPS or Transparent proxy could have admin slot set, although typically this should only be for Transparent
  await verifyAdmin();

  async function verifyAdmin() {
    const adminAddress = await getAdminAddress(provider, proxyAddress);
    if (!isEmptySlot(adminAddress)) {
      console.log(`Verifying proxy admin: ${adminAddress}`);
      await verifyAdminOrFallback(
        hardhatVerify,
        etherscan,
        adminAddress,
        errorReport,
      );
    }
  }

  /**
   * Verifies a proxy admin contract by looking up an OwnershipTransferred event that should have been logged during construction
   * to get the owner used for its constructor.
   *
   * This is different from the verifyWithArtifactOrFallback function because the proxy admin in Contracts 5.0 is not deployed directly by the plugin,
   * but is deployed by the transparent proxy itself, so we cannot infer the admin's constructor arguments from the originating transaction's input bytecode.
   */
  async function verifyAdminOrFallback(
    hardhatVerify: (address: string) => Promise<unknown>,
    etherscan: Etherscan,
    adminAddress: string,
    errorReport: ErrorReport,
  ) {
    const attemptVerify = async () => {
      let encodedOwner: string;
      // Get the OwnershipTransferred event when the ProxyAdmin was created, which should have the encoded owner address as its second parameter (third topic).
      const response = await getEventResponse(
        adminAddress,
        verifiableContracts.proxyAdmin.event,
        etherscan,
      );
      if (response === undefined) {
        throw new EventsNotFound(adminAddress, [
          verifiableContracts.proxyAdmin.event,
        ]);
      } else if (response.topics.length !== 3) {
        throw new EventOrFunctionNotFound(
          `Unexpected number of topics in event logs for ${verifiableContracts.proxyAdmin.event} from ${adminAddress}. Expected 3, got ${response.topics.length}: ${response.topics.join(", ")}`,
          () =>
            `The contract at ${adminAddress} does not appear to be a known proxy admin contract.`,
        );
      } else {
        encodedOwner = response.topics[2].replace(/^0x/, "");
      }

      const artifact = verifiableContracts.proxyAdmin.artifact;
      const deployedBytecode = await getCode(provider, adminAddress);
      if (deployedBytecode !== artifact.deployedBytecode) {
        throw new BytecodeNotMatchArtifact(
          `Bytecode does not match with the current version of ${artifact.contractName} in the Hardhat Upgrades plugin.`,
          artifact.contractName,
        );
      }

      await verifyContractWithConstructorArgs(
        etherscan,
        adminAddress,
        artifact,
        encodedOwner,
        errorReport,
      );
    };

    await attemptVerifyOrFallback(
      attemptVerify,
      hardhatVerify,
      adminAddress,
      errorReport,
      // The user provided the proxy address to verify, whereas this function is only verifying the related proxy admin.
      // So even if this falls back and succeeds, we want to keep any errors that might have occurred while verifying the proxy itself.
      false,
    );
  }

  async function verifyTransparentOrUUPS() {
    console.log(`Verifying proxy: ${proxyAddress}`);
    await verifyWithArtifactOrFallback(
      provider,
      hardhatVerify,
      etherscan,
      proxyAddress,
      [
        verifiableContracts.transparentUpgradeableProxy,
        verifiableContracts.erc1967proxy,
      ],
      errorReport,
      true,
    );
  }
}

/**
 * Fully verifies all contracts related to the given beacon proxy address: implementation, beacon, and beacon proxy.
 * Also links the proxy to the implementation ABI on Etherscan.
 *
 * @param hre
 * @param proxyAddress The beacon proxy address
 * @param hardhatVerify A function that invokes the hardhat-verify plugin's verify command
 * @param errorReport Accumulated verification errors
 */
async function fullVerifyBeaconProxy(
  provider: EthereumProvider,
  etherscan: Etherscan,
  proxyAddress: string,
  hardhatVerify: (address: string) => Promise<unknown>,
  errorReport: ErrorReport,
) {
  const beaconAddress = await getBeaconAddress(provider, proxyAddress);
  const implAddress = await getImplementationAddressFromBeacon(
    provider,
    beaconAddress,
  );

  await fullVerifyBeacon(
    provider,
    beaconAddress,
    hardhatVerify,
    etherscan,
    errorReport,
  );
  await verifyBeaconProxy();
  await linkProxyWithImplementationAbi(
    etherscan,
    proxyAddress,
    implAddress,
    errorReport,
  );

  async function verifyBeaconProxy() {
    console.log(`Verifying beacon proxy: ${proxyAddress}`);
    await verifyWithArtifactOrFallback(
      provider,
      hardhatVerify,
      etherscan,
      proxyAddress,
      [verifiableContracts.beaconProxy],
      errorReport,
      true,
    );
  }
}

/**
 * Verifies all contracts resulting from a beacon deployment: implementation, beacon
 *
 * @param hre
 * @param beaconAddress The beacon address
 * @param hardhatVerify A function that invokes the hardhat-verify plugin's verify command
 * @param etherscan Etherscan instance
 * @param errorReport Accumulated verification errors
 */
async function fullVerifyBeacon(
  provider: EthereumProvider,
  beaconAddress: string,
  hardhatVerify: (address: string) => Promise<unknown>,
  etherscan: Etherscan,
  errorReport: ErrorReport,
) {
  const implAddress = await getImplementationAddressFromBeacon(
    provider,
    beaconAddress,
  );
  await verifyImplementation(hardhatVerify, implAddress, errorReport);
  await verifyBeacon();

  async function verifyBeacon() {
    console.log(`Verifying beacon or beacon-like contract: ${beaconAddress}`);
    await verifyWithArtifactOrFallback(
      provider,
      hardhatVerify,
      etherscan,
      beaconAddress,
      [verifiableContracts.upgradeableBeacon],
      errorReport,
      true,
    );
  }
}

/**
 * Runs hardhat-verify plugin's verify command on the given implementation address.
 *
 * @param hardhatVerify A function that invokes the hardhat-verify plugin's verify command
 * @param implAddress The implementation address
 * @param errorReport Accumulated verification errors
 */
async function verifyImplementation(
  hardhatVerify: (address: string) => Promise<unknown>,
  implAddress: string,
  errorReport: ErrorReport,
) {
  try {
    console.log(`Verifying implementation: ${implAddress}`);
    await hardhatVerify(implAddress);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    if (message.toLowerCase().includes("already verified")) {
      console.log(`Implementation ${implAddress} already verified.`);
    } else {
      recordVerificationError(
        implAddress,
        "implementation",
        message,
        errorReport,
      );
    }
  }
}

/**
 * Looks for any of the possible events (in array order) at the specified address using Etherscan API,
 * and returns the corresponding VerifiableContractInfo and txHash for the first event found.
 *
 * @param etherscan Etherscan instance
 * @param address The contract address for which to look for events
 * @param possibleContractInfo An array of possible contract artifacts to use for verification along
 *  with the corresponding creation event expected in the logs.
 * @returns the VerifiableContractInfo and txHash for the first event found
 * @throws {EventOrFunctionNotFound} if none of the events were found in the contract's logs according to Etherscan.
 */
async function searchEvent(
  etherscan: Etherscan,
  address: string,
  possibleContractInfo: VerifiableContractInfo[],
) {
  for (let i = 0; i < possibleContractInfo.length; i++) {
    const contractInfo = possibleContractInfo[i];
    const txHash = await getContractCreationTxHash(
      address,
      contractInfo.event,
      etherscan,
    );
    if (txHash !== undefined) {
      return { contractInfo, txHash };
    }
  }

  const events = possibleContractInfo.map((contractInfo) => {
    return contractInfo.event;
  });
  throw new EventsNotFound(address, events);
}

/**
 * Verifies a contract using the attemptVerify function. If it fails, falls back to verify directly using the regular hardhat verify task.
 *
 * If the fallback passes, logs as success.
 * If the fallback also fails, records errors for both the original and fallback attempts.
 *
 * @param attemptVerify A function that attempts to verify the contract.
 *  Should throw EventOrFunctionNotFound if the contract does not contain an expected event in its logs or function in its bytecode,
 *  or BytecodeNotMatchArtifact if the contract's bytecode does not match with the plugin's known artifact.
 * @param hardhatVerify A function that invokes the hardhat-verify plugin's verify command
 * @param address The contract address to verify
 * @param errorReport Accumulated verification errors
 * @param convertErrorsToWarningsOnFallbackSuccess If fallback verification occurred and succeeded, whether any
 *  previously accumulated errors should be converted into warnings in the final summary.
 */
async function attemptVerifyOrFallback(
  attemptVerify: () => Promise<unknown>,
  hardhatVerify: (address: string) => Promise<unknown>,
  address: string,
  errorReport: ErrorReport,
  convertErrorsToWarningsOnFallbackSuccess: boolean,
) {
  try {
    await attemptVerify();
    return true;
  } catch (origError: unknown) {
    if (
      origError instanceof BytecodeNotMatchArtifact ||
      origError instanceof EventOrFunctionNotFound
    ) {
      // Try falling back to regular hardhat verify in case the source code is available in the user's project.
      try {
        await hardhatVerify(address);
      } catch (fallbackError: unknown) {
        const message =
          fallbackError instanceof Error
            ? fallbackError.message
            : String(fallbackError);
        if (message.toLowerCase().includes("already verified")) {
          console.log(`Contract at ${address} already verified.`);
        } else {
          // Fallback failed, so record both the original error and the fallback attempt, then return
          if (origError instanceof BytecodeNotMatchArtifact) {
            recordVerificationError(
              address,
              origError.contractName,
              origError.message,
              errorReport,
            );
          } else {
            recordError(origError.message, errorReport);
          }

          recordError(
            `Failed to verify directly using hardhat verify: ${message}`,
            errorReport,
          );
          return;
        }
      }

      // Since the contract was able to be verified directly, we don't want the task to fail so we should convert earlier errors into warnings for other related contracts.
      // For example, the user provided constructor arguments for the verify command will apply to all calls of the regular hardhat verify,
      // so it is not possible to successfully verify both an impl and a proxy that uses the above fallback at the same time.
      if (convertErrorsToWarningsOnFallbackSuccess) {
        errorReport.severity = "warn";
      }
    } else {
      throw origError;
    }
  }
}

/**
 * Verifies a contract by matching with known artifacts.
 *
 * If a match was not found, falls back to verify directly using the regular hardhat verify task.
 *
 * If the fallback passes, logs as success.
 * If the fallback also fails, records errors for both the original and fallback attempts.
 *
 * @param hre
 * @param etherscan Etherscan instance
 * @param address The contract address to verify
 * @param possibleContractInfo An array of possible contract artifacts to use for verification along
 *  with the corresponding creation event expected in the logs.
 * @param errorReport Accumulated verification errors
 * @param convertErrorsToWarningsOnFallbackSuccess If fallback verification occurred and succeeded, whether any
 *  previously accumulated errors should be converted into warnings in the final summary.
 */
async function verifyWithArtifactOrFallback(
  provider: EthereumProvider,
  hardhatVerify: (address: string) => Promise<unknown>,
  etherscan: Etherscan,
  address: string,
  possibleContractInfo: VerifiableContractInfo[],
  errorReport: ErrorReport,
  convertErrorsToWarningsOnFallbackSuccess: boolean,
) {
  const attemptVerify = () =>
    attemptVerifyWithCreationEvent(
      provider,
      etherscan,
      address,
      possibleContractInfo,
      errorReport,
    );
  return await attemptVerifyOrFallback(
    attemptVerify,
    hardhatVerify,
    address,
    errorReport,
    convertErrorsToWarningsOnFallbackSuccess,
  );
}

/**
 * Attempts to verify a contract by looking up an event that should have been logged during contract construction,
 * finds the txHash for that, and infers the constructor args to use for verification.
 *
 * Iterates through each element of possibleContractInfo to look for that element's event, until an event is found.
 *
 * @param hre
 * @param etherscan Etherscan instance
 * @param address The contract address to verify
 * @param possibleContractInfo An array of possible contract artifacts to use for verification along
 *  with the corresponding creation event expected in the logs.
 * @param errorReport Accumulated verification errors
 * @throws {EventOrFunctionNotFound} if none of the events were found in the contract's logs according to Etherscan.
 * @throws {BytecodeNotMatchArtifact} if the contract's bytecode does not match with the plugin's known artifact.
 */
async function attemptVerifyWithCreationEvent(
  provider: EthereumProvider,
  etherscan: Etherscan,
  address: string,
  possibleContractInfo: VerifiableContractInfo[],
  errorReport: ErrorReport,
) {
  const { contractInfo, txHash } = await searchEvent(
    etherscan,
    address,
    possibleContractInfo,
  );
  debug(
    `verifying contract ${contractInfo.artifact.contractName} at ${address}`,
  );

  const tx = await getTransactionByHash(provider, txHash);
  if (tx === null) {
    // This should not happen since the txHash came from the logged event itself
    throw new UpgradesError(
      `The transaction hash ${txHash} from the contract's logs was not found on the network`,
    );
  }

  const constructorArguments = inferConstructorArgs(
    tx.input,
    contractInfo.artifact.bytecode,
  );
  if (constructorArguments === undefined) {
    // The creation bytecode for the address does not match with the expected artifact.
    // This may be because a different version of the contract was deployed compared to what is in the plugins.
    throw new BytecodeNotMatchArtifact(
      `Bytecode does not match with the current version of ${contractInfo.artifact.contractName} in the Hardhat Upgrades plugin.`,
      contractInfo.artifact.contractName,
    );
  } else {
    await verifyContractWithConstructorArgs(
      etherscan,
      address,
      contractInfo.artifact,
      constructorArguments,
      errorReport,
    );
  }
}

/**
 * Verifies a contract using the given constructor args.
 *
 * @param etherscan Etherscan instance
 * @param address The address of the contract to verify
 * @param artifact The contract artifact to use for verification.
 * @param constructorArguments The constructor arguments to use for verification.
 */
async function verifyContractWithConstructorArgs(
  etherscan: Etherscan,
  address: string,
  artifact: Artifact,
  constructorArguments: string,
  errorReport: ErrorReport,
) {
  debug(
    `verifying contract ${address} with constructor args ${constructorArguments}`,
  );

  const params = {
    contractAddress: address,
    compilerInput: artifactsBuildInfo.input,
    contractName: `${artifact.inputSourceName}:${artifact.contractName}`,
    compilerVersion: `v${artifactsBuildInfo.solcLongVersion}`,
    constructorArguments: constructorArguments,
  };

  try {
    const status = await verifyAndGetStatus(params, etherscan);

    if (status.success) {
      console.log(
        `Successfully verified contract ${artifact.contractName} at ${address}.`,
      );
    } else {
      recordVerificationError(
        address,
        artifact.contractName,
        status.message,
        errorReport,
      );
    }
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : String(e);
    if (message.toLowerCase().includes("already verified")) {
      console.log(`Contract at ${address} already verified.`);
    } else {
      recordVerificationError(
        address,
        artifact.contractName,
        message,
        errorReport,
      );
    }
  }
}

/**
 * Calls the Etherscan API to look for an event that should have been emitted during construction
 * of the contract at the given address, and returns the result corresponding to the first event found.
 *
 * @param address The address for which to get the event response.
 * @param topic The event topic string that should have been logged.
 * @param etherscan Etherscan instance
 * @returns The event response, or undefined if not found or if
 *   the address is not a contract.
 * @throws {UpgradesError} if the Etherscan API returned with not OK status
 */
async function getEventResponse(
  address: string,
  topic: string,
  etherscan: Etherscan,
): Promise<EtherscanEventResponse | undefined> {
  const params = {
    module: "logs",
    action: "getLogs",
    fromBlock: "0",
    toBlock: "latest",
    address: address,
    topic0: "0x" + keccak256(Buffer.from(topic)).toString("hex"),
  };

  const responseBody = await etherscan.customApiCall(params);

  if (responseBody.status === RESPONSE_OK) {
    const result = responseBody.result as EtherscanEventResponse[];
    return result[0];
  } else if (
    responseBody.message === "No records found" ||
    responseBody.message === "No logs found"
  ) {
    debug(`no result found for event topic ${topic} at address ${address}`);
    return undefined;
  } else {
    throw new UpgradesError(
      `Failed to get logs for contract at address ${address}.`,
      () =>
        // TODO: while usually result is a string message on Etherscan errors,
        // we should verify this cast is always valid
        `Etherscan returned with message: ${responseBody.message}, reason: ${responseBody.result as string}`,
    );
  }
}

/**
 * Gets the txhash that created the contract at the given address, by calling the
 * Etherscan API to look for an event that should have been emitted during construction.
 *
 * @param address The address to get the creation txhash for.
 * @param topic The event topic string that should have been logged.
 * @param etherscan Etherscan instance
 * @returns The txhash corresponding to the logged event, or undefined if not found or if
 *   the address is not a contract.
 * @throws {UpgradesError} if the Etherscan API returned with not OK status
 */
async function getContractCreationTxHash(
  address: string,
  topic: string,
  etherscan: Etherscan,
): Promise<string | undefined> {
  const eventResponse = await getEventResponse(address, topic, etherscan);
  if (eventResponse === undefined) {
    return undefined;
  } else {
    return eventResponse.transactionHash;
  }
}

/**
 * Calls the Etherscan API to link a proxy with its implementation ABI.
 *
 * @param etherscan Etherscan instance
 * @param proxyAddress The proxy address
 * @param implAddress The implementation address
 */
async function linkProxyWithImplementationAbi(
  etherscan: Etherscan,
  proxyAddress: string,
  implAddress: string,
  errorReport: ErrorReport,
) {
  console.log(`Linking proxy ${proxyAddress} with implementation`);
  const params = {
    module: "contract",
    action: "verifyproxycontract",
    address: proxyAddress,
    expectedimplementation: implAddress,
  };
  let responseBody = await etherscan.customApiCall(params);

  if (responseBody.status === RESPONSE_OK) {
    // initial call was OK, but need to send a status request using the returned guid to get the actual verification status
    const guid = responseBody.result as string;
    responseBody = await checkProxyVerificationStatus(etherscan, guid);

    while (responseBody.result === "Pending in queue") {
      await delay(3000);
      responseBody = await checkProxyVerificationStatus(etherscan, guid);
    }
  }

  if (responseBody.status === RESPONSE_OK) {
    console.log("Successfully linked proxy to implementation.");
  } else {
    recordError(
      // TODO: while usually result is a string message on Etherscan errors,
      // we should verify this cast is always valid
      `Failed to link proxy ${proxyAddress} with its implementation. Reason: ${responseBody.result as string}`,
      errorReport,
    );
  }

  async function delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

async function checkProxyVerificationStatus(
  etherscan: Etherscan,
  guid: string,
) {
  const checkProxyVerificationParams = {
    module: "contract",
    action: "checkproxyverification",
    guid: guid,
  };
  return await etherscan.customApiCall(checkProxyVerificationParams);
}

/**
 * Gets the constructor args from the given transaction input and creation code.
 *
 * @param txInput The transaction input that was used to deploy the contract.
 * @param creationCode The contract creation code.
 * @returns the encoded constructor args, or undefined if txInput does not start with the creationCode.
 */
function inferConstructorArgs(txInput: string, creationCode: string) {
  if (txInput.startsWith(creationCode)) {
    return txInput.substring(creationCode.length);
  } else {
    return undefined;
  }
}

export async function verifyAndGetStatus(
  params: {
    contractAddress: string;
    compilerInput: BuildInfo["input"];
    contractName: string;
    compilerVersion: string;
    constructorArguments: string;
  },
  etherscan: Etherscan,
) {
  const guid = await etherscan.verify(params);
  return etherscan.pollVerificationStatus(
    guid,
    params.contractAddress,
    params.contractName,
  );
}

export default verifyEtherscanAction;
