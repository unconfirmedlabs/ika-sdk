// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bcs } from '@mysten/sui/bcs';
import type { ClientWithCoreApi, SuiClientRegistration } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';

import * as CoordinatorInnerModule from './generated/ika_dwallet_2pc_mpc/coordinator_inner.js';
import * as CoordinatorModule from './generated/ika_dwallet_2pc_mpc/coordinator.js';
import { TableVec } from './generated/ika_system/deps/sui/table_vec.js';
import * as SystemModule from './generated/ika_system/system.js';
import {
	networkDkgPublicOutputToProtocolPublicParameters,
	parseSignatureFromSignOutput,
	reconfigurationPublicOutputToProtocolPublicParameters,
} from './crypto.ts';
import { InvalidObjectError, NetworkError, ObjectNotFoundError } from './errors.ts';
import { fromNumberToCurve, validateCurveSignatureAlgorithm } from './validation.ts';
import type { ValidSignatureAlgorithmForCurve } from './validation.ts';
import {
	CoordinatorInnerDynamicField,
	DynamicField,
	SystemInnerDynamicField,
} from './types.ts';
import type {
	CoordinatorInner,
	Curve,
	DWallet,
	DWalletCap,
	DWalletInternal,
	DWalletKind,
	DWalletState,
	DWalletWithState,
	EncryptedUserSecretKeyShare,
	EncryptedUserSecretKeyShareState,
	EncryptedUserSecretKeyShareWithState,
	EncryptionKey,
	EncryptionKeyOptions,
	IkaConfig,
	NetworkEncryptionKey,
	PartialUserSignature,
	PartialUserSignatureState,
	PartialUserSignatureWithState,
	Presign,
	PresignState,
	PresignWithState,
	Sign,
	SignatureAlgorithm,
	SignState,
	SignWithState,
	SystemInner,
} from './types.ts';
import { fetchAllDynamicFields, objResToBcs } from './utils.ts';

// ============================================================================
// $extend registration
// ============================================================================

export interface IkaOptions<Name extends string = 'ika'> {
	/** Name for the client extension. Defaults to "ika". */
	name?: Name;
	/** The Ika network configuration. */
	config: IkaConfig;
	/** Whether to enable caching (default: true). */
	cache?: boolean;
	/** Default encryption key options for the client. */
	encryptionKeyOptions?: EncryptionKeyOptions;
}

/**
 * Creates an Ika client extension for use with `$extend()`.
 *
 * @example
 * ```ts
 * import { SuiGrpcClient } from '@mysten/sui/grpc';
 * import { ika } from '@unconfirmed/ika/client';
 * import { getNetworkConfig } from '@unconfirmed/ika';
 *
 * const client = new SuiGrpcClient({ network: 'testnet' })
 *   .$extend(ika({ config: getNetworkConfig('testnet') }));
 *
 * const dwallet = await client.ika.getDWallet('0x...');
 * ```
 */
export function ika<const Name extends string = 'ika'>(
	options: IkaOptions<Name>,
): SuiClientRegistration<ClientWithCoreApi, Name, IkaClient> {
	const name = (options.name ?? 'ika') as Name;
	return {
		name,
		register: (client) => new IkaClient(client, options),
	};
}

// ============================================================================
// IkaClient
// ============================================================================

export class IkaClient {
	/** The Ika network configuration including package IDs and object references */
	public ikaConfig: IkaConfig;
	/** Default encryption key options for the client */
	public encryptionKeyOptions: EncryptionKeyOptions;

	#client: ClientWithCoreApi;
	#cache: boolean;

	#cachedProtocolPublicParameters: Map<
		string,
		{
			networkEncryptionKeyPublicOutputID: string;
			epoch: number;
			curve: Curve;
			protocolPublicParameters: Uint8Array;
		}
	> = new Map();

	#cachedObjects?: {
		coordinatorInner: CoordinatorInner;
		systemInner: SystemInner;
	};

	#cachedEncryptionKeys: Map<string, NetworkEncryptionKey> = new Map();
	#objectsPromise?: Promise<{ coordinatorInner: CoordinatorInner; systemInner: SystemInner }>;
	#encryptionKeysPromise?: Promise<NetworkEncryptionKey[]>;

	constructor(client: ClientWithCoreApi, options: Omit<IkaOptions, 'name'>) {
		this.#client = client;
		this.ikaConfig = options.config;
		this.#cache = options.cache ?? true;
		this.encryptionKeyOptions = options.encryptionKeyOptions || { autoDetect: true };
	}

	/** The underlying Sui client */
	get client(): ClientWithCoreApi {
		return this.#client;
	}

	// ============================================================================
	// Cache management
	// ============================================================================

	invalidateCache(): void {
		this.#cachedObjects = undefined;
		this.#cachedProtocolPublicParameters.clear();
		this.#objectsPromise = undefined;
		this.#cachedEncryptionKeys.clear();
		this.#encryptionKeysPromise = undefined;
	}

	invalidateObjectCache(): void {
		this.#cachedObjects = undefined;
		this.#objectsPromise = undefined;
	}

	invalidateEncryptionKeyCache(): void {
		this.#cachedEncryptionKeys.clear();
		this.#encryptionKeysPromise = undefined;
	}

	invalidateProtocolPublicParametersCache(encryptionKeyID?: string, curve?: Curve): void {
		if (encryptionKeyID !== undefined && curve !== undefined) {
			this.#cachedProtocolPublicParameters.delete(this.#getCacheKey(encryptionKeyID, curve));
		} else if (encryptionKeyID !== undefined) {
			for (const key of this.#cachedProtocolPublicParameters.keys()) {
				if (key.startsWith(`${encryptionKeyID}-`)) {
					this.#cachedProtocolPublicParameters.delete(key);
				}
			}
		} else {
			this.#cachedProtocolPublicParameters.clear();
		}
	}

	// ============================================================================
	// Initialization
	// ============================================================================

	async initialize(): Promise<void> {
		await this.ensureInitialized();
	}

	async ensureInitialized(): Promise<{
		coordinatorInner: CoordinatorInner;
		systemInner: SystemInner;
	}> {
		if (!this.#cache) {
			return this.#getObjects();
		}

		if (this.#cachedObjects) {
			return this.#cachedObjects;
		}

		if (this.#objectsPromise) {
			await this.#objectsPromise;
			return this.#cachedObjects!;
		}

		await this.#getObjects();
		return this.#cachedObjects!;
	}

	// ============================================================================
	// Encryption key queries
	// ============================================================================

	async getAllNetworkEncryptionKeys(): Promise<NetworkEncryptionKey[]> {
		if (!this.#cache) {
			return this.#fetchEncryptionKeys();
		}

		if (this.#cachedEncryptionKeys.size > 0) {
			return Array.from(this.#cachedEncryptionKeys.values());
		}

		if (this.#encryptionKeysPromise) {
			await this.#encryptionKeysPromise;
			return Array.from(this.#cachedEncryptionKeys.values());
		}

		await this.#fetchEncryptionKeys();
		return Array.from(this.#cachedEncryptionKeys.values());
	}

	async getLatestNetworkEncryptionKey(): Promise<NetworkEncryptionKey> {
		const keys = await this.getAllNetworkEncryptionKeys();
		if (keys.length === 0) {
			throw new NetworkError('No network encryption keys found');
		}
		return keys[keys.length - 1]!;
	}

	async getNetworkEncryptionKey(encryptionKeyID: string): Promise<NetworkEncryptionKey> {
		const keys = await this.getAllNetworkEncryptionKeys();
		const key = keys.find((k) => k.id === encryptionKeyID);
		if (!key) {
			throw new ObjectNotFoundError(`Network encryption key ${encryptionKeyID} not found`);
		}
		return key;
	}

	async getDWalletNetworkEncryptionKey(dwalletID: string): Promise<NetworkEncryptionKey> {
		const dWallet = await this.getDWallet(dwalletID);
		const encryptionKeyID = dWallet.dwallet_network_encryption_key_id;
		return this.getNetworkEncryptionKey(encryptionKeyID);
	}

	async getConfiguredNetworkEncryptionKey(): Promise<NetworkEncryptionKey> {
		if (this.encryptionKeyOptions.encryptionKeyID) {
			return this.getNetworkEncryptionKey(this.encryptionKeyOptions.encryptionKeyID);
		}
		return this.getLatestNetworkEncryptionKey();
	}

	// ============================================================================
	// DWallet queries
	// ============================================================================

	async getDWallet(dwalletID: string): Promise<DWallet> {
		await this.ensureInitialized();

		return this.#client.core
			.getObject({
				objectId: dwalletID,
				include: { content: true },
			})
			.then((obj) => {
				const dWallet = CoordinatorInnerModule.DWallet.parse(objResToBcs(obj));
				return {
					...dWallet,
					kind: this.#getDWalletKind(dWallet),
				};
			});
	}

	async getDWalletInParticularState<S extends DWalletState>(
		dwalletID: string,
		state: S,
		options?: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		},
	): Promise<DWalletWithState<S>>;
	async getDWalletInParticularState(
		dwalletID: string,
		state: DWalletState,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<DWallet> {
		return this.#pollUntilState(
			() => this.getDWallet(dwalletID),
			state,
			`DWallet ${dwalletID} to reach state ${state}`,
			options,
		) as Promise<DWallet>;
	}

	async getMultipleDWallets(dwalletIDs: string[]): Promise<DWallet[]> {
		await this.ensureInitialized();

		return this.#client.core
			.getObjects({
				objectIds: dwalletIDs,
				include: { content: true },
			})
			.then((objs) => {
				return objs.objects.map((obj) => {
					const dWallet = CoordinatorInnerModule.DWallet.parse(objResToBcs(obj));
					return {
						...dWallet,
						kind: this.#getDWalletKind(dWallet),
					};
				});
			});
	}

	async getOwnedDWalletCaps(
		address: string,
		cursor?: string,
		limit?: number,
	): Promise<{
		dWalletCaps: DWalletCap[];
		cursor: string | null | undefined;
		hasNextPage: boolean;
	}> {
		await this.ensureInitialized();

		return this.#client.core
			.listOwnedObjects({
				owner: address,
				type: `${this.ikaConfig.packages.ikaDwallet2pcMpcOriginalPackage}::coordinator_inner::DWalletCap`,
				cursor,
				limit,
			})
			.then((response) => {
				return {
					dWalletCaps: response.objects.map((obj) =>
						CoordinatorInnerModule.DWalletCap.parse(objResToBcs(obj)),
					),
					cursor: response.cursor ?? null,
					hasNextPage: response.hasNextPage ?? false,
				};
			});
	}

	// ============================================================================
	// Presign / Sign / EncryptedShare queries
	// ============================================================================

	async getPresign(presignID: string): Promise<Presign> {
		await this.ensureInitialized();

		return this.#client.core
			.getObject({
				objectId: presignID,
				include: { content: true },
			})
			.then((obj) => {
				return CoordinatorInnerModule.PresignSession.parse(objResToBcs(obj));
			});
	}

	async getPresignInParticularState<S extends PresignState>(
		presignID: string,
		state: S,
		options?: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		},
	): Promise<PresignWithState<S>>;
	async getPresignInParticularState(
		presignID: string,
		state: PresignState,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<Presign> {
		return this.#pollUntilState(
			() => this.getPresign(presignID),
			state,
			`presign ${presignID} to reach state ${state}`,
			options,
		) as Promise<Presign>;
	}

	async getEncryptedUserSecretKeyShare(
		encryptedUserSecretKeyShareID: string,
	): Promise<EncryptedUserSecretKeyShare> {
		await this.ensureInitialized();

		return this.#client.core
			.getObject({
				objectId: encryptedUserSecretKeyShareID,
				include: { content: true },
			})
			.then((obj) => {
				return CoordinatorInnerModule.EncryptedUserSecretKeyShare.parse(objResToBcs(obj));
			});
	}

	async getEncryptedUserSecretKeyShareInParticularState<
		S extends EncryptedUserSecretKeyShareState,
	>(
		encryptedUserSecretKeyShareID: string,
		state: S,
		options?: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		},
	): Promise<EncryptedUserSecretKeyShareWithState<S>>;
	async getEncryptedUserSecretKeyShareInParticularState(
		encryptedUserSecretKeyShareID: string,
		state: EncryptedUserSecretKeyShareState,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<EncryptedUserSecretKeyShare> {
		return this.#pollUntilState(
			() => this.getEncryptedUserSecretKeyShare(encryptedUserSecretKeyShareID),
			state,
			`encrypted user secret key share ${encryptedUserSecretKeyShareID} to reach state ${state}`,
			options,
		) as Promise<EncryptedUserSecretKeyShare>;
	}

	async getPartialUserSignature(
		partialCentralizedSignedMessageID: string,
	): Promise<PartialUserSignature> {
		await this.ensureInitialized();

		return this.#client.core
			.getObject({
				objectId: partialCentralizedSignedMessageID,
				include: { content: true },
			})
			.then((obj) => {
				return CoordinatorInnerModule.PartialUserSignature.parse(objResToBcs(obj));
			});
	}

	async getPartialUserSignatureInParticularState<S extends PartialUserSignatureState>(
		partialCentralizedSignedMessageID: string,
		state: S,
		options?: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		},
	): Promise<PartialUserSignatureWithState<S>>;
	async getPartialUserSignatureInParticularState(
		partialCentralizedSignedMessageID: string,
		state: PartialUserSignatureState,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<PartialUserSignature> {
		return this.#pollUntilState(
			() => this.getPartialUserSignature(partialCentralizedSignedMessageID),
			state,
			`partial user signature ${partialCentralizedSignedMessageID} to reach state ${state}`,
			options,
		) as Promise<PartialUserSignature>;
	}

	async getSign<C extends Curve>(
		signID: string,
		curve: C,
		signatureAlgorithm: ValidSignatureAlgorithmForCurve<C>,
	): Promise<Sign> {
		await this.ensureInitialized();

		validateCurveSignatureAlgorithm(curve, signatureAlgorithm);

		const unparsedSign = await this.#client.core.getObject({
			objectId: signID,
			include: { content: true },
		});

		const sign = CoordinatorInnerModule.SignSession.parse(objResToBcs(unparsedSign));

		if (sign.state.$kind === 'Completed') {
			sign.state.Completed.signature = Array.from(
				await parseSignatureFromSignOutput(
					curve,
					signatureAlgorithm,
					Uint8Array.from(sign.state.Completed.signature),
				),
			);
		}

		return sign;
	}

	async getSignInParticularState<S extends SignState>(
		signID: string,
		curve: Curve,
		signatureAlgorithm: SignatureAlgorithm,
		state: S,
		options?: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		},
	): Promise<SignWithState<S>>;
	async getSignInParticularState(
		signID: string,
		curve: Curve,
		signatureAlgorithm: SignatureAlgorithm,
		state: SignState,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<Sign> {
		return this.#pollUntilState(
			() => this.getSign(signID, curve, signatureAlgorithm),
			state,
			`sign ${signID} to reach state ${state}`,
			options,
		) as Promise<Sign>;
	}

	// ============================================================================
	// Protocol parameters
	// ============================================================================

	getCachedProtocolPublicParameters(
		encryptionKeyID: string,
		curve: Curve,
	): Uint8Array | undefined {
		const cacheKey = this.#getCacheKey(encryptionKeyID, curve);
		const cachedParams = this.#cachedProtocolPublicParameters.get(cacheKey);
		if (!cachedParams) return undefined;

		const currentKey = this.#cachedEncryptionKeys.get(encryptionKeyID);
		if (!currentKey) return undefined;

		if (
			cachedParams.networkEncryptionKeyPublicOutputID === currentKey.networkDKGOutputID &&
			cachedParams.epoch === currentKey.epoch &&
			cachedParams.curve === curve
		) {
			return cachedParams.protocolPublicParameters;
		}

		this.#cachedProtocolPublicParameters.delete(cacheKey);
		return undefined;
	}

	isProtocolPublicParametersCached(encryptionKeyID: string, curve: Curve): boolean {
		return this.getCachedProtocolPublicParameters(encryptionKeyID, curve) !== undefined;
	}

	getEncryptionKeyOptions(): EncryptionKeyOptions {
		return { ...this.encryptionKeyOptions };
	}

	setEncryptionKeyOptions(options: EncryptionKeyOptions): void {
		this.encryptionKeyOptions = { ...options };
	}

	setEncryptionKeyID(encryptionKeyID: string): void {
		this.encryptionKeyOptions = { ...this.encryptionKeyOptions, encryptionKeyID };
	}

	async getProtocolPublicParameters(dWallet?: DWallet, curve?: Curve): Promise<Uint8Array> {
		await this.#fetchEncryptionKeysFromNetwork();

		let networkEncryptionKey: NetworkEncryptionKey;

		if (dWallet) {
			networkEncryptionKey = await this.getDWalletNetworkEncryptionKey(dWallet.id);
		} else {
			networkEncryptionKey = await this.getConfiguredNetworkEncryptionKey();
		}

		const encryptionKeyID = networkEncryptionKey.id;
		const networkEncryptionKeyPublicOutputID = networkEncryptionKey.networkDKGOutputID;
		const epoch = networkEncryptionKey.epoch;

		let selectedCurve: Curve;

		if (dWallet) {
			selectedCurve = fromNumberToCurve(dWallet.curve);
		} else {
			selectedCurve = curve !== undefined ? curve : fromNumberToCurve(0);
		}

		const cacheKey = this.#getCacheKey(encryptionKeyID, selectedCurve);
		const cachedParams = this.#cachedProtocolPublicParameters.get(cacheKey);
		if (cachedParams) {
			if (
				cachedParams.networkEncryptionKeyPublicOutputID === networkEncryptionKeyPublicOutputID &&
				cachedParams.epoch === epoch &&
				cachedParams.curve === selectedCurve
			) {
				return cachedParams.protocolPublicParameters;
			}
		}

		const protocolPublicParameters = !networkEncryptionKey.reconfigurationOutputID
			? await networkDkgPublicOutputToProtocolPublicParameters(
					selectedCurve,
					await this.readTableVecAsRawBytes(networkEncryptionKeyPublicOutputID),
				)
			: await reconfigurationPublicOutputToProtocolPublicParameters(
					selectedCurve,
					await this.readTableVecAsRawBytes(networkEncryptionKey.reconfigurationOutputID),
					await this.readTableVecAsRawBytes(networkEncryptionKeyPublicOutputID),
				);

		this.#cachedProtocolPublicParameters.set(cacheKey, {
			networkEncryptionKeyPublicOutputID,
			epoch,
			curve: selectedCurve,
			protocolPublicParameters,
		});

		return protocolPublicParameters;
	}

	// ============================================================================
	// Active encryption key
	// ============================================================================

	async getActiveEncryptionKey(address: string): Promise<EncryptionKey> {
		await this.ensureInitialized();

		const tx = new Transaction();
		tx.setSender(address);

		tx.moveCall({
			target: `${this.ikaConfig.packages.ikaDwallet2pcMpcPackage}::coordinator::get_active_encryption_key`,
			arguments: [
				tx.sharedObjectRef({
					objectId: this.ikaConfig.objects.ikaDWalletCoordinator.objectID,
					initialSharedVersion:
						this.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
					mutable: true,
				}),
				tx.pure.address(address),
			],
		});

		const res = await this.#client.core.simulateTransaction({
			transaction: tx,
			include: { commandResults: true },
		});

		const objID = bcs.Address.parse(
			res.commandResults?.at(0)?.returnValues?.at(0)?.bcs ?? new Uint8Array(),
		);

		const obj = await this.#client.core.getObject({
			objectId: objID,
			include: { content: true },
		});

		return CoordinatorInnerModule.EncryptionKey.parse(objResToBcs(obj));
	}

	// ============================================================================
	// Epoch
	// ============================================================================

	async getEpoch(): Promise<number> {
		const objects = await this.ensureInitialized();
		return Number(objects.coordinatorInner.current_epoch);
	}

	// ============================================================================
	// Table reading
	// ============================================================================

	async readTableVecAsRawBytes(tableID: string): Promise<Uint8Array> {
		try {
			let cursor: string | null = null;
			const allTableRows: { objectId: string }[] = [];

			do {
				const dynamicFieldPage = await this.#client.core.listDynamicFields({
					parentId: tableID,
					cursor,
				});

				if (!dynamicFieldPage?.dynamicFields?.length) {
					if (allTableRows.length === 0) {
						throw new ObjectNotFoundError('Dynamic fields', tableID);
					}
					break;
				}

				allTableRows.push(
					...dynamicFieldPage.dynamicFields.map((df) => ({
						objectId: df.fieldId,
					})),
				);
				cursor = dynamicFieldPage.cursor;

				if (!dynamicFieldPage.hasNextPage) {
					break;
				}
			} while (cursor);

			const dataMap = new Map<number, Uint8Array>();

			const objectIds = new Set(allTableRows.map((tableRowResult) => tableRowResult.objectId));

			await this.#processBatchedObjects([...objectIds], ({ objectId, fields }) => {
				const tableIndex = parseInt(fields.name);

				if (isNaN(tableIndex)) {
					throw new InvalidObjectError('Table index (expected numeric name)', objectId);
				}

				dataMap.set(tableIndex, fields.value);
			});

			const indices = Array.from(dataMap.keys()).sort((a, b) => a - b);

			if (indices.length === 0) {
				throw new ObjectNotFoundError('No table chunks found', tableID);
			}

			const orderedChunks: Uint8Array[] = indices
				.map((idx) => dataMap.get(idx)!)
				.filter((chunk): chunk is Uint8Array => !!chunk);

			const totalLength = orderedChunks.reduce((acc, arr) => acc + arr.length, 0);
			const result = new Uint8Array(totalLength);
			let offset = 0;

			for (const chunk of orderedChunks) {
				result.set(chunk, offset);
				offset += chunk.length;
			}

			return result;
		} catch (error) {
			if (
				error instanceof InvalidObjectError ||
				error instanceof ObjectNotFoundError ||
				error instanceof NetworkError
			) {
				throw error;
			}
			throw new NetworkError(
				`Failed to read table vector as raw bytes: ${tableID}`,
				error as Error,
			);
		}
	}

	// ============================================================================
	// Private helpers
	// ============================================================================

	async #getObjects() {
		if (this.#cachedObjects) {
			return {
				coordinatorInner: this.#cachedObjects.coordinatorInner,
				systemInner: this.#cachedObjects.systemInner,
			};
		}

		if (this.#objectsPromise) {
			return this.#objectsPromise;
		}

		this.#objectsPromise = this.#fetchObjectsFromNetwork();

		try {
			const result = await this.#objectsPromise;
			this.#cachedObjects = {
				coordinatorInner: result.coordinatorInner,
				systemInner: result.systemInner,
			};
			return result;
		} catch (error) {
			this.#objectsPromise = undefined;
			throw error;
		}
	}

	async #fetchObjectsFromNetwork() {
		try {
			const {
				objects: [coordinator, system],
			} = await this.#client.core.getObjects({
				objectIds: [
					this.ikaConfig.objects.ikaDWalletCoordinator.objectID,
					this.ikaConfig.objects.ikaSystemObject.objectID,
				],
				include: {
					content: true,
					owner: true,
				},
			});

			if (coordinator instanceof Error || system instanceof Error) {
				throw new NetworkError(
					'Failed to fetch objects',
					coordinator instanceof Error ? coordinator : (system as Error),
				);
			}

			const coordinatorParsed = CoordinatorModule.DWalletCoordinator.parse(
				objResToBcs(coordinator),
			);
			const systemParsed = SystemModule.System.parse(objResToBcs(system));

			const [coordinatorDFs, systemDFs] = await Promise.all([
				this.#client.core.listDynamicFields({
					parentId: coordinatorParsed.id,
				}),
				this.#client.core.listDynamicFields({
					parentId: systemParsed.id,
				}),
			]);

			if (!coordinatorDFs.dynamicFields?.length || !systemDFs.dynamicFields?.length) {
				throw new ObjectNotFoundError('Dynamic fields for coordinator or system');
			}

			const coordinatorInnerDF =
				coordinatorDFs.dynamicFields[coordinatorDFs.dynamicFields.length - 1]!;
			const systemInnerDF = systemDFs.dynamicFields[systemDFs.dynamicFields.length - 1]!;

			const respObjects = await this.#client.core.getObjects({
				objectIds: [coordinatorInnerDF.fieldId, systemInnerDF.fieldId],
				include: { content: true, owner: true },
			});

			const [coordinatorInner, systemInner] = respObjects.objects;

			const coordinatorInnerParsed = CoordinatorInnerDynamicField.parse(
				objResToBcs(coordinatorInner!),
			).value;

			const systemInnerParsed = SystemInnerDynamicField.parse(
				objResToBcs(systemInner!),
			).value;

			this.ikaConfig.packages.ikaSystemPackage = systemParsed.package_id;
			this.ikaConfig.packages.ikaDwallet2pcMpcPackage = coordinatorParsed.package_id;

			this.ikaConfig.objects.ikaSystemObject.initialSharedVersion = Number(
				system.owner?.Shared?.initialSharedVersion ?? 0,
			);
			this.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion = Number(
				coordinator.owner?.Shared?.initialSharedVersion ?? 0,
			);

			return {
				coordinatorInner: coordinatorInnerParsed,
				systemInner: systemInnerParsed,
			};
		} catch (error) {
			if (error instanceof InvalidObjectError || error instanceof ObjectNotFoundError) {
				throw error;
			}

			throw new NetworkError('Failed to fetch objects', error as Error);
		}
	}

	async #fetchEncryptionKeys(): Promise<NetworkEncryptionKey[]> {
		if (this.#encryptionKeysPromise) {
			return this.#encryptionKeysPromise;
		}

		this.#encryptionKeysPromise = this.#fetchEncryptionKeysFromNetwork();

		try {
			const result = await this.#encryptionKeysPromise;
			return result;
		} catch (error) {
			this.#encryptionKeysPromise = undefined;
			throw error;
		}
	}

	async #fetchEncryptionKeysFromNetwork(): Promise<NetworkEncryptionKey[]> {
		try {
			const objects = await this.ensureInitialized();
			const keysDFs = await this.#client.core.listDynamicFields({
				parentId: objects.coordinatorInner.dwallet_network_encryption_keys.id,
			});

			if (!keysDFs.dynamicFields?.length) {
				throw new ObjectNotFoundError('Network encryption keys');
			}

			const encryptionKeys: NetworkEncryptionKey[] = [];

			for (const keyDF of keysDFs.dynamicFields) {
				const keyName = bcs.Address.parse(keyDF.name.bcs);
				const keyObject = await this.#client.core.getObject({
					objectId: keyDF.childId!,
					include: { content: true },
				});

				const keyParsed = CoordinatorInnerModule.DWalletNetworkEncryptionKey.parse(
					objResToBcs(keyObject),
				);

				const reconfigOutputsDFs = await fetchAllDynamicFields(
					this.#client,
					keyParsed.reconfiguration_public_outputs.id,
				);

				const lastReconfigOutput = (
					await Promise.all(
						reconfigOutputsDFs.map(async (df) => {
							const name = bcs.u32().parse(df.name.bcs);
							const reconfigObject = await this.#client.core.getObject({
								objectId: df.fieldId,
								include: { content: true },
							});

							const parsedValue = DynamicField(TableVec).parse(
								objResToBcs(reconfigObject),
							);

							return {
								name,
								parsedValue,
							};
						}),
					)
				)
					.sort((a, b) => Number(a.name) - Number(b.name))
					.at(-2);

				const encryptionKey: NetworkEncryptionKey = {
					id: keyName,
					epoch: Number(keyParsed.dkg_at_epoch),
					networkDKGOutputID: keyParsed.network_dkg_public_output.contents.id,
					reconfigurationOutputID: lastReconfigOutput?.parsedValue.value.contents.id,
				};

				encryptionKeys.push(encryptionKey);
				this.#cachedEncryptionKeys.set(keyName, encryptionKey);
			}

			encryptionKeys.sort((a, b) => a.epoch - b.epoch);

			return encryptionKeys;
		} catch (error) {
			if (error instanceof InvalidObjectError || error instanceof ObjectNotFoundError) {
				throw error;
			}

			throw new NetworkError('Failed to fetch encryption keys', error as Error);
		}
	}

	async #processBatchedObjects<TReturn = void>(
		objectIds: string[],
		processor: (input: {
			objectId: string;
			fields: { name: string; value: Uint8Array };
		}) => TReturn,
	): Promise<TReturn[]> {
		const batchSize = 50;

		try {
			const results: TReturn[] = [];
			for (let i = 0; i < objectIds.length; i += batchSize) {
				const batchIds = objectIds.slice(i, i + batchSize);

				const dynFields = await this.#client.core.getObjects({
					objectIds: batchIds,
					include: { content: true },
				});

				for (const dynField of dynFields.objects) {
					if (dynField instanceof Error) {
						throw new NetworkError(
							`Failed to fetch object ${dynField.name}: ${dynField.message}`,
						);
					}

					const parsed = DynamicField(bcs.byteVector()).parse(objResToBcs(dynField));

					results.push(
						processor({
							objectId: dynField.objectId,
							fields: { name: parsed.name.toString(), value: parsed.value },
						}),
					);
				}
			}
			return results;
		} catch (error) {
			if (error instanceof NetworkError || error instanceof InvalidObjectError) {
				throw error;
			}
			throw new NetworkError('Failed to process batched objects', error as Error);
		}
	}

	#getCacheKey(encryptionKeyID: string, curve: Curve): string {
		return `${encryptionKeyID}-${curve}`;
	}

	#getDWalletKind(dWallet: DWalletInternal): DWalletKind {
		if (dWallet.is_imported_key_dwallet && dWallet.public_user_secret_key_share) {
			return 'imported-key-shared';
		}

		if (dWallet.is_imported_key_dwallet) {
			return 'imported-key';
		}

		if (dWallet.public_user_secret_key_share) {
			return 'shared';
		}

		return 'zero-trust';
	}

	async #pollUntilCondition<T>(
		fetcher: () => Promise<T>,
		condition: (obj: T) => boolean,
		errorContext: string,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<T> {
		await this.ensureInitialized();

		const {
			timeout = 30000,
			interval = 1000,
			maxInterval = 5000,
			backoffMultiplier = 1.5,
			signal,
		} = options;

		if (signal?.aborted) {
			throw new Error('Operation aborted');
		}

		const startTime = Date.now();
		let currentInterval = interval;
		let lastError: Error | undefined;

		while (Date.now() - startTime < timeout) {
			if (signal?.aborted) {
				throw new Error('Operation aborted');
			}

			try {
				const obj = await fetcher();

				if (condition(obj)) {
					return obj;
				}
			} catch (error) {
				lastError = error as Error;
			}

			const waitTime = currentInterval;
			await new Promise((resolve, reject) => {
				const timeoutId = setTimeout(resolve, waitTime);
				signal?.addEventListener('abort', () => {
					clearTimeout(timeoutId);
					reject(new Error('Operation aborted'));
				});
			});

			currentInterval = Math.min(currentInterval * backoffMultiplier, maxInterval);
		}

		const errorMessage = lastError
			? `Timeout waiting for ${errorContext}. Last error: ${lastError.message}`
			: `Timeout waiting for ${errorContext}`;

		throw new Error(errorMessage);
	}

	async #pollUntilState<T extends { state: { $kind: string } }>(
		fetcher: () => Promise<T>,
		state: string,
		errorContext: string,
		options: {
			timeout?: number;
			interval?: number;
			maxInterval?: number;
			backoffMultiplier?: number;
			signal?: AbortSignal;
		} = {},
	): Promise<T> {
		return this.#pollUntilCondition(
			fetcher,
			(obj) => obj.state.$kind === state,
			errorContext,
			options,
		);
	}
}
