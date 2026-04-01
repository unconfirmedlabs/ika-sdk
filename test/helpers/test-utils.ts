// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import fs from 'fs';
import path from 'path';
import { toHex } from '@mysten/bcs';
import type { ClientWithCoreApi, SuiClientTypes } from '@mysten/sui/client';
import { getFaucetHost, requestSuiFromFaucetV2 } from '@mysten/sui/faucet';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Secp256k1Keypair } from '@mysten/sui/keypairs/secp256k1';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';
import { randomBytes } from '@noble/hashes/utils.js';

import { IkaClient } from '../../src/client.ts';
import { Curve } from '../../src/types.ts';
import type { IkaConfig } from '../../src/types.ts';
import { UserShareEncryptionKeys } from '../../src/crypto.ts';

// Store random seeds per test to ensure deterministic behavior within each test
const testSeeds = new Map<string, Uint8Array>();

export async function getObjectWithType<TObject>(
	suiClient: ClientWithCoreApi,
	objectID: string,
	isObject: (obj: any) => obj is TObject,
): Promise<TObject> {
	let timeout = 600_000; // Default timeout of 10 minutes
	const startTime = Date.now();
	while (Date.now() - startTime <= timeout) {
		const interval = 1;
		await delay(interval);
		const res = await suiClient.core.getObject({
			objectId: objectID,
			include: { json: true },
		});

		const objectData = res.object.json as TObject;

		if (objectData) {
			return objectData;
		}
	}
	const seconds = ((Date.now() - startTime) / 1000).toFixed(2);
	throw new Error(
		`timeout: unable to fetch an object within ${
			timeout / (60 * 1000)
		} minutes (${seconds} seconds passed).`,
	);
}

/**
 * Creates a deterministic seed for a test.
 */
export function createDeterministicSeed(testName: string): Uint8Array {
	if (!testSeeds.has(testName)) {
		const randomSeed = new Uint8Array(randomBytes(32));
		testSeeds.set(testName, randomSeed);
	}
	return testSeeds.get(testName)!;
}

export function clearTestSeed(testName: string): void {
	testSeeds.delete(testName);
}

export function clearAllTestSeeds(): void {
	testSeeds.clear();
}

/**
 * Creates a SuiClient for testing (gRPC-first).
 */
export function createTestSuiClient(): ClientWithCoreApi {
	return new SuiGrpcClient({
		baseUrl: process.env.SUI_TESTNET_URL || 'http://127.0.0.1:9000',
		network: 'localnet',
	});
}

/**
 * Requests funds from the faucet for a given address.
 */
export async function requestTestFaucetFunds(address: string): Promise<void> {
	const maxRetries = 3;
	const baseDelay = 5000;

	for (let attempt = 1; attempt <= maxRetries; attempt++) {
		try {
			await requestSuiFromFaucetV2({
				host: process.env.SUI_FAUCET_URL || getFaucetHost('localnet'),
				recipient: address,
			});

			await sleep(2000);
			return;
		} catch (error: any) {
			if (error.message?.includes('Too many requests') || error.name === 'FaucetRateLimitError') {
				const delay = baseDelay * attempt;
				console.warn(
					`Faucet rate limit hit for ${address}. Waiting ${delay / 1000}s before retry ${attempt}/${maxRetries}...`,
				);

				if (attempt < maxRetries) {
					await sleep(delay);
					continue;
				} else {
					console.warn(
						`Failed to fund ${address} after ${maxRetries} attempts. Proceeding without funds.`,
					);
					return;
				}
			} else {
				console.warn(`Faucet error for ${address}:`, error.message);
				return;
			}
		}
	}
}

export function findIkaConfigFile(): string {
	const possiblePaths = [
		'ika_config.json',
		'../ika_config.json',
		'../../ika_config.json',
		'../../../ika_config.json',
		...(process.env.IKA_CONFIG_PATH ? [process.env.IKA_CONFIG_PATH] : []),
		path.resolve(__dirname, '../../../../ika_config.json'),
		path.resolve(__dirname, '../../../ika_config.json'),
	];

	for (const configPath of possiblePaths) {
		try {
			const resolvedPath = path.resolve(configPath);
			if (fs.existsSync(resolvedPath)) {
				return resolvedPath;
			}
		} catch {
			continue;
		}
	}

	throw new Error(
		`Could not find ika_config.json file. Tried the following locations:\n` +
			`${possiblePaths.map((p) => `  - ${p}`).join('\n')}\n\n` +
			`Please ensure the file exists in one of these locations, or set the IKA_CONFIG_PATH environment variable.`,
	);
}

/**
 * Creates an IkaClient for testing.
 */
export function createTestIkaClient(suiClient: ClientWithCoreApi): IkaClient {
	const configPath = findIkaConfigFile();
	const parsedJson = JSON.parse(fs.readFileSync(configPath, 'utf8'));

	return new IkaClient(suiClient, {
		config: {
			packages: {
				ikaPackage: parsedJson.packages.ika_package_id,
				ikaCommonPackage: parsedJson.packages.ika_common_package_id,
				ikaDwallet2pcMpcPackage: parsedJson.packages.ika_dwallet_2pc_mpc_package_id,
				ikaSystemPackage: parsedJson.packages.ika_system_package_id,
				ikaSystemOriginalPackage: parsedJson.packages.ika_system_original_package_id,
				ikaDwallet2pcMpcOriginalPackage:
					parsedJson.packages.ika_dwallet_2pc_mpc_original_package_id,
			},
			objects: {
				ikaSystemObject: {
					objectID: parsedJson.objects.ika_system_object_id,
					initialSharedVersion: 0,
				},
				ikaDWalletCoordinator: {
					objectID: parsedJson.objects.ika_dwallet_coordinator_object_id,
					initialSharedVersion: 0,
				},
			},
		},
	});
}

/**
 * Executes a transaction with deterministic signing.
 */
export async function executeTestTransaction(
	suiClient: ClientWithCoreApi,
	transaction: Transaction,
	testName: string,
) {
	const seed = createDeterministicSeed(testName);
	const signerKeypair = Ed25519Keypair.deriveKeypairFromSeed(toHex(seed));

	return await executeTestTransactionWithKeypair(suiClient, transaction, signerKeypair);
}

/**
 * Executes a transaction with a provided keypair.
 */
export async function executeTestTransactionWithKeypair(
	suiClient: ClientWithCoreApi,
	transaction: Transaction,
	signerKeypair: Ed25519Keypair,
) {
	return suiClient.core
		.signAndExecuteTransaction({
			transaction,
			signer: signerKeypair,
			include: {
				events: true,
			},
		})
		.then(
			(result) =>
				result.Transaction as SuiClientTypes.Transaction<{
					events: true;
				}>,
		);
}

/**
 * Generates deterministic keypair for testing.
 */
export async function generateTestKeypair(testName: string, curve: Curve = Curve.SECP256K1) {
	const seed = createDeterministicSeed(testName);
	const userKeypair = Ed25519Keypair.deriveKeypairFromSeed(toHex(seed));

	const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(seed, curve);

	return {
		userShareEncryptionKeys,
		signerAddress: userKeypair.getPublicKey().toSuiAddress(),
		signerPublicKey: userKeypair.getPublicKey().toRawBytes(),
		userKeypair,
	};
}

/**
 * Generates deterministic keypair for Imported Key DWallet testing.
 */
export async function generateTestKeypairForImportedKeyDWallet(testName: string) {
	const seed = createDeterministicSeed(testName);
	const userKeypair = Ed25519Keypair.deriveKeypairFromSeed(toHex(seed));

	const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
		seed,
		Curve.SECP256K1,
	);
	const dWalletKeypair = Secp256k1Keypair.fromSeed(seed);

	return {
		userShareEncryptionKeys,
		dWalletKeypair,
		signerAddress: userKeypair.getPublicKey().toSuiAddress(),
		signerPublicKey: userKeypair.getPublicKey().toRawBytes(),
		userKeypair,
	};
}

/**
 * Creates an empty IKA token for transactions.
 */
export function createEmptyTestIkaToken(tx: Transaction, ikaConfig: IkaConfig) {
	return tx.moveCall({
		target: `0x2::coin::zero`,
		arguments: [],
		typeArguments: [`${ikaConfig.packages.ikaPackage}::ika::IKA`],
	});
}

/**
 * Destroys an empty IKA token.
 */
export function destroyEmptyTestIkaToken(
	tx: Transaction,
	ikaConfig: IkaConfig,
	ikaToken: TransactionObjectArgument,
) {
	return tx.moveCall({
		target: `0x2::coin::destroy_zero`,
		arguments: [ikaToken],
		typeArguments: [`${ikaConfig.packages.ikaPackage}::ika::IKA`],
	});
}

/**
 * Creates a deterministic message for testing.
 */
export function createTestMessage(testName: string, suffix: string = ''): Uint8Array {
	const message = `test-message-${testName}${suffix}`;
	return new TextEncoder().encode(message);
}

export function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * @deprecated Consider using IkaClient's *InParticularState methods directly instead.
 */
export async function retryUntil<T>(
	fn: () => Promise<T>,
	condition: (result: T) => boolean,
	maxAttempts: number = 30,
	delayMs: number = 1000,
): Promise<T> {
	const result = await fn();

	if (condition(result)) {
		return result;
	}

	for (let attempt = 1; attempt < maxAttempts; attempt++) {
		await sleep(delayMs);

		try {
			const result = await fn();
			if (condition(result)) {
				return result;
			}
		} catch (error) {
			if (attempt === maxAttempts - 1) {
				throw error;
			}
		}
	}

	throw new Error(`Condition not met after ${maxAttempts} attempts`);
}

export function delay(seconds: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}

export async function waitForEpochSwitch(ikaClient: IkaClient) {
	const startEpoch = await ikaClient.getEpoch();
	let epochSwitched = false;
	while (!epochSwitched) {
		ikaClient.invalidateCache();
		if ((await ikaClient.getEpoch()) > startEpoch) {
			epochSwitched = true;
		} else {
			await delay(5);
		}
	}
}
