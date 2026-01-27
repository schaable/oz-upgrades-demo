/* eslint-disable @typescript-eslint/no-unused-vars -- Mock file */
import { EthereumProvider } from "@openzeppelin/upgrades-core";
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

export interface EtherscanResponseBody {
  status: string;
  message: string;
  result: unknown; // TODO: check what's the most specific type we can use here
}

export interface EtherscanVerifyFunctionArgs {
  contractAddress: string;
  compilerInput: string;
  contractName: string;
  compilerVersion: string;
  constructorArguments: string;
}

export interface EtherscanVerificationStatus {
  isSuccess(): boolean;
  message: string;
}

export class Etherscan {
  /*
   * Avoids users having to deal with the http client,
   * error handling, and manually constructing query parameters
   * with apiKey and chainId for each call.
   *
   * apiKey and chainId are handled internally, but overrides can be passed in params.
   * Should we assume POST call? all endpoints in Etherscan use GET or POST.
   * Error handling and response: generic error class and response type.
   */
  async customApiCall(
    params: Record<string, unknown>,
  ): Promise<EtherscanResponseBody> {
    // Mock implementation.
    throw new Error("Mock: customApiCall not implemented");
  }

  // Already implemented in hardhat-verify
  async verify(_args: EtherscanVerifyFunctionArgs): Promise<string> {
    // Mock implementation - returns a GUID for status checking
    throw new Error("Mock: verify not implemented");
  }

  // Already implemented in hardhat-verify
  async getVerificationStatus(
    _guid: string,
  ): Promise<EtherscanVerificationStatus> {
    // Mock implementation - returns verification status
    throw new Error("Mock: getVerificationStatus not implemented");
  }
}

/*
 * Alternative approaches for creating a verification provider:
 *
 * Option 1: Export createVerificationProviderInstance
 *
 *   async function createVerificationProviderInstance({
 *     provider,                    // (await hre.network.connect()).provider
 *     networkName,                 // (await hre.network.connect()).networkName
 *     chainDescriptors,            // hre.config.chainDescriptors
 *     verificationProviderName,    // ETHERSCAN_PROVIDER_NAME (needs to be exported)
 *     verificationProvidersConfig, // hre.config.verify
 *     dispatcher,                  // optional, not used
 *   }: {
 *     provider: EthereumProvider;
 *     networkName: string;
 *     chainDescriptors: ChainDescriptorsConfig;
 *     verificationProviderName: keyof VerificationProvidersConfig;
 *     verificationProvidersConfig: VerificationProvidersConfig;
 *     dispatcher?: Dispatcher;
 *   }): Promise<VerificationProvider>;
 *
 * Option 2: Create etherscan instance when connecting to the network
 *
 *   const { verify: { etherscan } } = hre.network.connect();
 */
export async function getEtherscanInstance(
  provider: EthereumProvider,
  config: HardhatRuntimeEnvironment["config"],
): Promise<Etherscan> {
  // Mock implementation.
  return new Etherscan();
}

/*
  Notes: 
   - in linkProxyWithImplementationAbi, getEventResponse function oz checks responseBody.status === 1 
   - in linkProxyWithImplementationAbi function, oz checks responseBody.result === "Pending in queue"
  Should we export constants for these?
  
   - oz imports json artifacts from @openzeppelin/upgrades-core/artifacts/..., 
     TS infers _format as string, but Hardhat's Artifact type expects the 
     literal "hh3-artifact-1", forcing casts in several places.
*/
