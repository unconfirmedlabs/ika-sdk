// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { toHex } from '@mysten/bcs';
import { bcs } from '@mysten/sui/bcs';
import type { PublicKey } from '@mysten/sui/cryptography';
import { SIGNATURE_FLAG_TO_SCHEME } from '@mysten/sui/cryptography';
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { randomBytes } from '@noble/hashes/utils.js';

import {
	fromCurveAndSignatureAlgorithmAndHashToNumbers,
	fromCurveToNumber,
	fromNumberToCurve,
	fromSignatureAlgorithmToNumber,
} from './validation.ts';
import type {
	ValidHashForSignature,
	ValidSignatureAlgorithmForCurve,
} from './validation.ts';
import type { IkaClient } from './client.ts';
import type { DWallet, EncryptedUserSecretKeyShare, EncryptionKey } from './types.ts';
import { Curve } from './types.ts';
import { encodeToASCII, u64ToBytesBigEndian } from './utils.ts';
import {
	centralized_and_decentralized_parties_dkg_output_match,
	create_dkg_centralized_output_v2,
	create_dkg_centralized_output_v1 as create_dkg_user_output,
	create_imported_dwallet_centralized_step as create_imported_dwallet_user_output,
	create_sign_centralized_party_message_with_centralized_party_dkg_output,
	create_sign_centralized_party_message as create_sign_user_message,
	decrypt_user_share,
	encrypt_secret_share,
	generate_secp_cg_keypair_from_seed,
	network_dkg_public_output_to_protocol_pp,
	parse_signature_from_sign_output,
	public_key_from_centralized_dkg_output,
	public_key_from_dwallet_output,
	reconfiguration_public_output_to_protocol_pp,
	verify_secp_signature,
	verify_user_share,
} from './wasm.ts';

// =============================================================================
// Cryptography types
// =============================================================================

/**
 * Prepared data for the second round of Distributed Key Generation (DKG).
 * Contains all cryptographic outputs needed to complete the DKG process.
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export interface DKGRequestInput {
	/** The user's public key share along with its zero-knowledge proof */
	userDKGMessage: Uint8Array;
	/** The user's public output from the DKG process */
	userPublicOutput: Uint8Array;
	/** The encrypted user share with its proof of correct encryption */
	encryptedUserShareAndProof: Uint8Array;
	/** The raw secret key share (user share) */
	userSecretKeyShare: Uint8Array;
}

/**
 * Prepared data for importing an existing cryptographic key as a DWallet.
 * Contains verification data needed to prove ownership of the imported key.
 */
export interface ImportDWalletVerificationRequestInput {
	/** The public output that can be verified against the imported key */
	userPublicOutput: Uint8Array;
	/** The outgoing message for the verification protocol */
	userMessage: Uint8Array;
	/** The encrypted user share with proof for the imported key */
	encryptedUserShareAndProof: Uint8Array;
}

// =============================================================================
// Cryptography functions
// =============================================================================

/**
 * Create a class groups keypair from a seed for encryption/decryption operations.
 * Uses SECP256k1, SECP256r1, Ristretto, or ED25519 curves with class groups for homomorphic encryption capabilities.
 *
 * @param seed - The seed bytes to generate the keypair from
 * @param curve - The curve to use for key generation
 * @returns Object containing the encryption key (public) and decryption key (private)
 */
export async function createClassGroupsKeypair(
	seed: Uint8Array,
	curve: Curve,
): Promise<{
	encryptionKey: Uint8Array;
	decryptionKey: Uint8Array;
}> {
	if (seed.length !== 32) {
		throw new Error('Seed must be 32 bytes');
	}

	let encryptionKey: Uint8Array;
	let decryptionKey: Uint8Array;

	if (
		curve === Curve.SECP256K1 ||
		curve === Curve.SECP256R1 ||
		curve === Curve.RISTRETTO ||
		curve === Curve.ED25519
	) {
		[encryptionKey, decryptionKey] = await generate_secp_cg_keypair_from_seed(
			fromCurveToNumber(curve),
			seed,
		);
	} else {
		throw new Error(
			'Only SECP256K1, SECP256R1, RISTRETTO, and ED25519 curves are supported for now',
		);
	}

	return {
		encryptionKey: Uint8Array.from(encryptionKey),
		decryptionKey: Uint8Array.from(decryptionKey),
	};
}

/**
 * Create the user's output and message for the Distributed Key Generation (DKG) protocol.
 * This function takes the first round output and produces the user's contribution.
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 *
 * @param protocolPublicParameters - The protocol public parameters for decryption
 * @param networkFirstRoundOutput - The output from the network's first round of DKG
 * @param sessionIdentifier - Unique identifier for this DKG session
 * @returns Object containing the user's DKG message, public output, and secret key share
 *
 */
export async function createDKGUserOutput(
	protocolPublicParameters: Uint8Array,
	networkFirstRoundOutput: Uint8Array,
): Promise<{
	userDKGMessage: Uint8Array;
	userPublicOutput: Uint8Array;
	userSecretKeyShare: Uint8Array;
}> {
	const [userDKGMessage, userPublicOutput, userSecretKeyShare] = await create_dkg_user_output(
		protocolPublicParameters,
		Uint8Array.from(networkFirstRoundOutput),
	);

	return {
		userDKGMessage: Uint8Array.from(userDKGMessage),
		userPublicOutput: Uint8Array.from(userPublicOutput),
		userSecretKeyShare: Uint8Array.from(userSecretKeyShare),
	};
}

/**
 * Encrypt a secret share using the provided encryption key.
 * This creates an encrypted share that can only be decrypted by the corresponding decryption key.
 *
 * @param curve - The curve to use for encryption
 * @param userSecretKeyShare - The secret key share to encrypt
 * @param encryptionKey - The public encryption key to encrypt with
 * @param protocolPublicParameters - The protocol public parameters for encryption
 * @returns The encrypted secret share with proof of correct encryption
 */
export async function encryptSecretShare(
	curve: Curve,
	userSecretKeyShare: Uint8Array,
	encryptionKey: Uint8Array,
	protocolPublicParameters: Uint8Array,
): Promise<Uint8Array> {
	const encryptedUserShareAndProof = await encrypt_secret_share(
		fromCurveToNumber(curve),
		userSecretKeyShare,
		encryptionKey,
		protocolPublicParameters,
	);

	return Uint8Array.from(encryptedUserShareAndProof);
}

/**
 * @deprecated Use prepareDKG instead
 *
 * @param _protocolPublicParameters - The protocol public parameters
 * @param _dWallet - The DWallet object containing first round output
 * @param _encryptionKey - The user's public encryption key
 * @returns Complete prepared data for the second DKG round
 * @throws {Error} If the first round output is not available in the DWallet
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export async function prepareDKGSecondRound(
	_protocolPublicParameters: Uint8Array,
	_dWallet: DWallet,
	_encryptionKey: Uint8Array,
): Promise<DKGRequestInput> {
	throw new Error('prepareDKGSecondRound is deprecated. Use prepareDKG instead');
}

/**
 * Prepare all cryptographic data needed for DKG.
 *
 * @param protocolPublicParameters - The protocol public parameters
 * @param curve - The curve to use for key generation
 * @param encryptionKey - The user's public encryption key
 * @param bytesToHash - The bytes to hash for session identifier generation
 * @param senderAddress - The sender address for session identifier generation
 * @returns Complete prepared data for DKG including user message, public output, encrypted share, and secret key share
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export async function prepareDKG(
	protocolPublicParameters: Uint8Array,
	curve: Curve,
	encryptionKey: Uint8Array,
	bytesToHash: Uint8Array,
	senderAddress: string,
): Promise<DKGRequestInput> {
	const senderAddressBytes = bcs.Address.serialize(senderAddress).toBytes();

	const [userDKGMessage, userPublicOutput, userSecretKeyShare] =
		await create_dkg_centralized_output_v2(
			fromCurveToNumber(curve),
			protocolPublicParameters,
			sessionIdentifierDigest(bytesToHash, senderAddressBytes),
		);

	const encryptedUserShareAndProof = await encryptSecretShare(
		curve,
		userSecretKeyShare,
		encryptionKey,
		protocolPublicParameters,
	);

	return {
		userDKGMessage: Uint8Array.from(userDKGMessage),
		userPublicOutput: Uint8Array.from(userPublicOutput),
		encryptedUserShareAndProof: Uint8Array.from(encryptedUserShareAndProof),
		userSecretKeyShare: Uint8Array.from(userSecretKeyShare),
	};
}

/**
 * @deprecated Use prepareDKGAsync instead
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param dWallet - The DWallet object containing first round output
 * @param userShareEncryptionKeys - The user's encryption keys for securing the user's share
 * @returns Promise resolving to complete prepared data for the second DKG round
 * @throws {Error} If the first round output is not available or network parameters cannot be fetched
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export async function prepareDKGSecondRoundAsync(
	_ikaClient: IkaClient,
	_dWallet: DWallet,
	_userShareEncryptionKeys: UserShareEncryptionKeys,
): Promise<DKGRequestInput> {
	throw new Error('prepareDKGSecondRoundAsync is deprecated. Use prepareDKGAsync instead');
}

/**
 * Prepare all cryptographic data needed for DKG (async version that fetches protocol parameters).
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param curve - The curve to use for key generation
 * @param userShareEncryptionKeys - The user's encryption keys for securing the user's share
 * @param bytesToHash - The bytes to hash for session identifier generation
 * @param senderAddress - The sender address for session identifier generation
 * @returns Promise resolving to complete prepared data for DKG including user message, public output, encrypted share, and secret key share
 * @throws {Error} If network parameters cannot be fetched
 *
 * SECURITY WARNING: *secret key share must be kept private!* never send it to anyone, or store it anywhere unencrypted.
 */
export async function prepareDKGAsync(
	ikaClient: IkaClient,
	curve: Curve,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	bytesToHash: Uint8Array,
	senderAddress: string,
): Promise<DKGRequestInput> {
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(undefined, curve);

	return prepareDKG(
		protocolPublicParameters,
		curve,
		userShareEncryptionKeys.encryptionKey,
		bytesToHash,
		senderAddress,
	);
}

/**
 * Prepare verification data for importing an existing cryptographic key as a DWallet.
 * This function creates all necessary proofs and encrypted data for the import process.
 *
 * @param ikaClient - The IkaClient instance to fetch network parameters from
 * @param curve - The curve to use for key generation
 * @param bytesToHash - The bytes to hash for session identifier generation
 * @param senderAddress - The sender address for session identifier generation
 * @param userShareEncryptionKeys - The user's encryption keys for securing the imported share
 * @param privateKey - The existing private key to import as a DWallet
 * @returns Promise resolving to complete verification data for the import process including user public output, message, and encrypted share
 * @throws {Error} If network parameters cannot be fetched or key import preparation fails
 */
export async function prepareImportedKeyDWalletVerification(
	ikaClient: IkaClient,
	curve: Curve,
	bytesToHash: Uint8Array,
	senderAddress: string,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	privateKey: Uint8Array,
): Promise<ImportDWalletVerificationRequestInput> {
	const senderAddressBytes = bcs.Address.serialize(senderAddress).toBytes();
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(undefined, curve);

	const [userSecretShare, userPublicOutput, userMessage] =
		await create_imported_dwallet_user_output(
			fromCurveToNumber(curve),
			protocolPublicParameters,
			sessionIdentifierDigest(bytesToHash, senderAddressBytes),
			privateKey,
		);

	const encryptedUserShareAndProof = await encryptSecretShare(
		curve,
		userSecretShare,
		userShareEncryptionKeys.encryptionKey,
		protocolPublicParameters,
	);

	return {
		userPublicOutput: Uint8Array.from(userPublicOutput),
		userMessage: Uint8Array.from(userMessage),
		encryptedUserShareAndProof: Uint8Array.from(encryptedUserShareAndProof),
	};
}

/**
 * Create the user's sign message for the signature generation process.
 * This function combines the user's secret key, presign, and message to create a sign message to be sent to the network.
 *
 * This function is used when developer has access to the user's public output which should be verified before using this method.
 *
 * @param protocolPublicParameters - The protocol public parameters
 * @param publicOutput - The user's public output
 * @param userSecretKeyShare - The user's secret key share
 * @param presign - The presignature data from a completed presign operation
 * @param message - The message bytes to sign
 * @param hash - The hash scheme to use for signing
 * @param signatureAlgorithm - The signature algorithm to use
 * @param curve - The curve to use
 * @returns The user's sign message that will be sent to the network for signature generation
 */
export async function createUserSignMessageWithPublicOutput<
	C extends Curve,
	S extends ValidSignatureAlgorithmForCurve<C>,
	H extends ValidHashForSignature<S>,
>(
	protocolPublicParameters: Uint8Array,
	publicOutput: Uint8Array,
	userSecretKeyShare: Uint8Array,
	presign: Uint8Array,
	message: Uint8Array,
	hash: H,
	signatureAlgorithm: S,
	curve: C,
): Promise<Uint8Array> {
	const { signatureAlgorithmNumber, hashNumber, curveNumber } =
		fromCurveAndSignatureAlgorithmAndHashToNumbers(curve, signatureAlgorithm, hash);

	return Uint8Array.from(
		await create_sign_user_message(
			protocolPublicParameters,
			publicOutput,
			userSecretKeyShare,
			presign,
			message,
			hashNumber,
			signatureAlgorithmNumber,
			curveNumber,
		),
	);
}

/**
 * Create the user's sign message for the signature generation process.
 * This function combines the user's secret key, presign, and message to create a sign message to be sent to the network.
 *
 * This function is used when developer has access to the centralized DKG output which should be verified before using this method.
 *
 * @param protocolPublicParameters - The protocol public parameters
 * @param centralizedDkgOutput - The centralized DKG output
 * @param userSecretKeyShare - The user's secret key share
 * @param presign - The presignature data from a completed presign operation
 * @param message - The message bytes to sign
 * @param hash - The hash scheme to use for signing
 * @param signatureAlgorithm - The signature algorithm to use
 * @param curve - The curve to use
 * @returns The user's sign message that will be sent to the network for signature generation
 */
export async function createUserSignMessageWithCentralizedOutput<
	C extends Curve,
	S extends ValidSignatureAlgorithmForCurve<C>,
	H extends ValidHashForSignature<S>,
>(
	protocolPublicParameters: Uint8Array,
	centralizedDkgOutput: Uint8Array,
	userSecretKeyShare: Uint8Array,
	presign: Uint8Array,
	message: Uint8Array,
	hash: H,
	signatureAlgorithm: S,
	curve: C,
): Promise<Uint8Array> {
	const { signatureAlgorithmNumber, hashNumber, curveNumber } =
		fromCurveAndSignatureAlgorithmAndHashToNumbers(curve, signatureAlgorithm, hash);

	return Uint8Array.from(
		await create_sign_centralized_party_message_with_centralized_party_dkg_output(
			protocolPublicParameters,
			centralizedDkgOutput,
			userSecretKeyShare,
			presign,
			message,
			hashNumber,
			signatureAlgorithmNumber,
			curveNumber,
		),
	);
}

/**
 * Convert a network DKG public output to the protocol public parameters.
 *
 * @param curve - The curve to use for key generation
 * @param network_dkg_public_output - The network DKG public output
 * @returns The protocol public parameters
 */
export async function networkDkgPublicOutputToProtocolPublicParameters(
	curve: Curve,
	network_dkg_public_output: Uint8Array,
): Promise<Uint8Array> {
	return Uint8Array.from(
		await network_dkg_public_output_to_protocol_pp(
			fromCurveToNumber(curve),
			network_dkg_public_output,
		),
	);
}

/**
 * Convert a reconfiguration DKG public output to the protocol public parameters.
 *
 * @param curve - The curve to use for key generation
 * @param reconfiguration_public_output - The reconfiguration DKG public output
 * @param network_dkg_public_output - The network DKG public output
 * @returns The protocol public parameters
 */
export async function reconfigurationPublicOutputToProtocolPublicParameters(
	curve: Curve,
	reconfiguration_public_output: Uint8Array,
	network_dkg_public_output: Uint8Array,
): Promise<Uint8Array> {
	return Uint8Array.from(
		await reconfiguration_public_output_to_protocol_pp(
			fromCurveToNumber(curve),
			reconfiguration_public_output,
			network_dkg_public_output,
		),
	);
}

/**
 * Verify a user's secret key share.
 *
 * @param curve - The curve to use for key generation
 * @param userSecretKeyShare - The user's unencrypted secret key share
 * @param userDKGOutput - The user's DKG output
 * @param networkDkgPublicOutput - The network DKG public output
 * @returns True if the user's secret key share is valid, false otherwise
 */
export async function verifyUserShare(
	curve: Curve,
	userSecretKeyShare: Uint8Array,
	userDKGOutput: Uint8Array,
	networkDkgPublicOutput: Uint8Array,
): Promise<boolean> {
	return await verify_user_share(
		fromCurveToNumber(curve),
		userSecretKeyShare,
		userDKGOutput,
		networkDkgPublicOutput,
	);
}

/**
 * Verify a signature.
 *
 * @param publicKey - The public key bytes
 * @param signature - The signature bytes to verify
 * @param message - The message bytes that was signed
 * @param networkDkgPublicOutput - The network DKG public output
 * @param hash - The hash scheme to use for verification
 * @param signatureAlgorithm - The signature algorithm to use
 * @param curve - The curve to use
 * @returns True if the signature is valid, false otherwise
 */
export async function verifySecpSignature<
	C extends Curve,
	S extends ValidSignatureAlgorithmForCurve<C>,
	H extends ValidHashForSignature<S>,
>(
	publicKey: Uint8Array,
	signature: Uint8Array,
	message: Uint8Array,
	networkDkgPublicOutput: Uint8Array,
	hash: H,
	signatureAlgorithm: S,
	curve: C,
): Promise<boolean> {
	const { signatureAlgorithmNumber, hashNumber, curveNumber } =
		fromCurveAndSignatureAlgorithmAndHashToNumbers(curve, signatureAlgorithm, hash);

	return await verify_secp_signature(
		publicKey,
		signature,
		message,
		networkDkgPublicOutput,
		hashNumber,
		signatureAlgorithmNumber,
		curveNumber,
	);
}

/**
 * Create a public key from a DWallet output.
 *
 * @param curve - The curve to use for key generation
 * @param dWalletOutput - The DWallet output
 *
 * @returns The BCS-encoded public key
 */
export async function publicKeyFromDWalletOutput(
	curve: Curve,
	dWalletOutput: Uint8Array,
): Promise<Uint8Array> {
	return Uint8Array.from(
		await public_key_from_dwallet_output(fromCurveToNumber(curve), dWalletOutput),
	);
}

/**
 * Create a public key from a centralized DKG output.
 *
 * @param curve - The curve to use for key generation
 * @param centralizedDkgOutput - The centralized DKG output
 *
 * @returns The BCS-encoded public key
 */
export async function publicKeyFromCentralizedDKGOutput(
	curve: Curve,
	centralizedDkgOutput: Uint8Array,
): Promise<Uint8Array> {
	return Uint8Array.from(
		await public_key_from_centralized_dkg_output(fromCurveToNumber(curve), centralizedDkgOutput),
	);
}

/**
 * Verify and get the DWallet DKG public output.
 * The `publicKey` is used to verify the user's public output signature.
 *
 * SECURITY WARNING: For withSecrets flows, the public key or public output must be saved by the developer during DKG,
 * NOT fetched from the network, to ensure proper verification.
 *
 * @param dWallet - The DWallet object containing the user's public output
 * @param encryptedUserSecretKeyShare - The encrypted user secret key share
 * @param publicKey - The user share encryption key's public key for verification
 * @returns The DKG public output
 */
export async function verifyAndGetDWalletDKGPublicOutput(
	dWallet: DWallet,
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	publicKey: PublicKey,
): Promise<Uint8Array> {
	if (
		SIGNATURE_FLAG_TO_SCHEME[publicKey.flag() as keyof typeof SIGNATURE_FLAG_TO_SCHEME] !==
		'ED25519'
	) {
		throw new Error('Only ED25519 public keys are supported.');
	}

	if (!dWallet.state.Active?.public_output) {
		throw new Error('DWallet is not in active state');
	}

	if (!encryptedUserSecretKeyShare.state.KeyHolderSigned?.user_output_signature) {
		throw new Error('User output signature is undefined');
	}

	const userPublicOutput = Uint8Array.from(dWallet.state.Active.public_output);

	const userOutputSignature = Uint8Array.from(
		encryptedUserSecretKeyShare.state.KeyHolderSigned?.user_output_signature,
	);

	if (!(await publicKey.verify(userPublicOutput, userOutputSignature))) {
		throw new Error('Invalid signature');
	}

	if (publicKey.toSuiAddress() !== encryptedUserSecretKeyShare.encryption_key_address) {
		throw new Error(
			'Invalid Sui address. The encryption key address does not match the signing keypair address.',
		);
	}

	return Uint8Array.from(dWallet.state.Active.public_output);
}

/**
 * Verify that the user's public output matches the network's public output.
 *
 * @param curve - The curve to use
 * @param userPublicOutput - The user's public output
 * @param networkDKGOutput - The network's public output
 * @returns True if the user's public output matches the network's public output, false otherwise
 */
export async function userAndNetworkDKGOutputMatch(
	curve: Curve,
	userPublicOutput: Uint8Array,
	networkDKGOutput: Uint8Array,
): Promise<boolean> {
	return await centralized_and_decentralized_parties_dkg_output_match(
		fromCurveToNumber(curve),
		userPublicOutput,
		networkDKGOutput,
	);
}

/**
 * Parse a signature from a sign output.
 *
 * @param curve - The curve to use
 * @param signatureAlgorithm - The signature algorithm to use
 * @param signatureOutput - The signature output bytes from the network
 * @returns The parsed signature bytes
 */
export async function parseSignatureFromSignOutput<
	C extends Curve,
	S extends ValidSignatureAlgorithmForCurve<C>,
>(curve: C, signatureAlgorithm: S, signatureOutput: Uint8Array): Promise<Uint8Array> {
	return Uint8Array.from(
		await parse_signature_from_sign_output(
			fromCurveToNumber(curve),
			fromSignatureAlgorithmToNumber(curve, signatureAlgorithm),
			signatureOutput,
		),
	);
}

/**
 * Create a digest of the session identifier for cryptographic operations.
 * This function creates a versioned, domain-separated hash of the session identifier.
 *
 * @param bytesToHash - The bytes to hash for session identifier generation
 * @param senderAddressBytes - The sender address bytes for session identifier generation
 * @returns The KECCAK-256 digest of the versioned and domain-separated session identifier
 * @private
 */
export function sessionIdentifierDigest(
	bytesToHash: Uint8Array,
	senderAddressBytes: Uint8Array,
): Uint8Array {
	const preimage = keccak_256(Uint8Array.from([...senderAddressBytes, ...bytesToHash]));
	const version = 0; // Version of the session identifier
	// Calculate the user session identifier for digest
	const data = Uint8Array.from([
		...u64ToBytesBigEndian(version),
		...encodeToASCII('USER'),
		...preimage,
	]);
	// Compute the SHA3-256 digest of the serialized data
	const digest = keccak_256(data);
	return Uint8Array.from(digest);
}

/**
 * Create a random session identifier.
 *
 * @returns 32 random bytes for use as a session identifier
 */
export function createRandomSessionIdentifier(): Uint8Array {
	return Uint8Array.from(randomBytes(32));
}

// =============================================================================
// UserShareEncryptionKeys
// =============================================================================

/**
 * BCS enum for serializing/deserializing UserShareEncryptionKeys.
 *
 * - `V1`: Keys derived with the legacy hash (curve byte always 0).
 * - `V2`: Keys derived with the fixed hash (correct curve byte).
 *
 * Both variants have the same fields; the variant tag is what distinguishes
 * which hash derivation was used, so deserialization can reconstruct
 * the keys with the right derivation function.
 */
export const VersionedUserShareEncryptionKeysBcs = bcs.enum('VersionedUserShareEncryptionKeys', {
	V1: bcs.struct('UserShareEncryptionKeysV1', {
		encryptionKey: bcs.vector(bcs.u8()),
		decryptionKey: bcs.vector(bcs.u8()),
		secretShareSigningSecretKey: bcs.string(),
		curve: bcs.u64(),
	}),
	V2: bcs.struct('UserShareEncryptionKeysV2', {
		encryptionKey: bcs.vector(bcs.u8()),
		decryptionKey: bcs.vector(bcs.u8()),
		secretShareSigningSecretKey: bcs.string(),
		curve: bcs.u32(),
	}),
});

/**
 * Manages encryption/decryption keys and Ed25519 signing keypairs for
 * encrypting, decrypting, and authorizing dWallet user secret shares.
 *
 * ## Key derivation
 *
 * All keys are deterministically derived from a single 32-byte root seed
 * via domain-separated `keccak256` hashes:
 *
 * ```
 * seed = keccak256(ASCII(domain) || curveByte || rootSeed)
 * ```
 *
 * - **Class-groups keypair** — encrypts/decrypts the user secret share.
 * - **Ed25519 signing keypair** — signs the encryption key and dWallet
 *   public outputs to prove ownership and authorize operations.
 *
 * ## Legacy vs fixed hash
 *
 * An earlier version had a bug where the curve byte was always `0`
 * regardless of the actual curve (the `Curve` string enum was passed to
 * `Uint8Array.from()`, which coerced it to `NaN` → `0`).
 * This only matters for non-SECP256K1 curves (whose curve number is
 * already `0`).
 *
 * - Use {@link fromRootSeedKey} for new registrations (fixed hash).
 * - Use {@link fromRootSeedKeyLegacyHash} only to reproduce keys that
 *   were registered on-chain before the fix.
 *
 * Serialization via {@link toShareEncryptionKeysBytes} records which
 * derivation was used (BCS `V1` = legacy, `V2` = fixed), so
 * {@link fromShareEncryptionKeysBytes} always picks the right one.
 */
export class UserShareEncryptionKeys {
	/** Class-groups public encryption key (encrypts secret shares). */
	encryptionKey: Uint8Array;
	/** Class-groups private decryption key (decrypts secret shares). */
	decryptionKey: Uint8Array;
	/** Ed25519 keypair used to sign encryption keys and dWallet outputs. */
	#encryptedSecretShareSigningKeypair: Ed25519Keypair;
	/** Curve these keys were generated for. */
	curve: Curve;
	/**
	 * `true` when the keys were derived with the legacy (buggy) hash that
	 * always uses `0` as the curve byte.
	 */
	readonly legacyHash: boolean;

	/** Domain separators used in the keccak256 key derivation hash. */
	static domainSeparators = {
		classGroups: 'CLASS_GROUPS_DECRYPTION_KEY_V1',
		encryptionSignerKey: 'ED25519_SIGNING_KEY_V1',
	};

	private constructor(
		encryptionKey: Uint8Array,
		decryptionKey: Uint8Array,
		secretShareSigningSecretKey: Ed25519Keypair,
		curve: Curve,
		legacyHash: boolean = false,
	) {
		this.encryptionKey = encryptionKey;
		this.decryptionKey = decryptionKey;
		this.#encryptedSecretShareSigningKeypair = secretShareSigningSecretKey;
		this.curve = curve;
		this.legacyHash = legacyHash;
	}

	// -----------------------------------------------------------------------
	// Construction
	// -----------------------------------------------------------------------

	/**
	 * Derives encryption keys from a root seed using the **fixed** hash
	 * (`keccak256(domain || curveNumber || seed)`).
	 *
	 * This is the default and recommended constructor for all new key
	 * registrations.
	 */
	static async fromRootSeedKey(
		rootSeedKey: Uint8Array,
		curve: Curve,
	): Promise<UserShareEncryptionKeys> {
		return UserShareEncryptionKeys.#createFromSeed(rootSeedKey, curve, false);
	}

	/**
	 * Derives encryption keys from a root seed using the **legacy** hash
	 * (`keccak256(domain || 0 || seed)` — curve byte is always `0`).
	 *
	 * Only needed to reproduce keys that were registered on-chain before
	 * the curve-byte fix. SECP256K1 is unaffected (its curve number is
	 * already `0`), so this only matters for SECP256R1, ED25519, and
	 * RISTRETTO keys.
	 *
	 * @deprecated Register new keys with {@link fromRootSeedKey} instead.
	 */
	static async fromRootSeedKeyLegacyHash(
		rootSeedKey: Uint8Array,
		curve: Curve,
	): Promise<UserShareEncryptionKeys> {
		return UserShareEncryptionKeys.#createFromSeed(rootSeedKey, curve, true);
	}

	/**
	 * Shared construction logic — derives class-groups and Ed25519 keypairs
	 * from a root seed, using either the fixed or legacy hash function.
	 */
	static async #createFromSeed(
		rootSeedKey: Uint8Array,
		curve: Curve,
		legacyHash: boolean,
	): Promise<UserShareEncryptionKeys> {
		const hashFn = legacyHash ? UserShareEncryptionKeys.hashLegacy : UserShareEncryptionKeys.hash;

		const classGroupsSeed = hashFn(
			UserShareEncryptionKeys.domainSeparators.classGroups,
			rootSeedKey,
			curve,
		);

		const encryptionSignerKeySeed = hashFn(
			UserShareEncryptionKeys.domainSeparators.encryptionSignerKey,
			rootSeedKey,
			curve,
		);

		const classGroupsKeypair = await createClassGroupsKeypair(classGroupsSeed, curve);
		const encryptionSignerKey = Ed25519Keypair.deriveKeypairFromSeed(
			toHex(encryptionSignerKeySeed),
		);

		return new UserShareEncryptionKeys(
			new Uint8Array(classGroupsKeypair.encryptionKey),
			new Uint8Array(classGroupsKeypair.decryptionKey),
			encryptionSignerKey,
			curve,
			legacyHash,
		);
	}

	// -----------------------------------------------------------------------
	// Serialization / deserialization
	// -----------------------------------------------------------------------

	/**
	 * Restores a `UserShareEncryptionKeys` instance from bytes previously
	 * produced by {@link toShareEncryptionKeysBytes}.
	 *
	 * The BCS variant (`V1` vs `V2`) determines whether the legacy or
	 * fixed hash was used, so the returned instance always has the correct
	 * {@link legacyHash} flag.
	 */
	static fromShareEncryptionKeysBytes(
		shareEncryptionKeysBytes: Uint8Array,
	): UserShareEncryptionKeys {
		const { encryptionKey, decryptionKey, secretShareSigningSecretKey, curve, legacyHash } =
			this.#parseShareEncryptionKeys(shareEncryptionKeysBytes);

		const secretShareSigningKeypair = Ed25519Keypair.fromSecretKey(secretShareSigningSecretKey);

		return new UserShareEncryptionKeys(
			encryptionKey,
			decryptionKey,
			secretShareSigningKeypair,
			curve,
			legacyHash,
		);
	}

	/**
	 * Serializes these keys to bytes (BCS `V1` for legacy, `V2` for fixed).
	 *
	 * The output is suitable for persistent storage and can be restored
	 * with {@link fromShareEncryptionKeysBytes}.
	 */
	toShareEncryptionKeysBytes(): Uint8Array {
		return this.#serializeShareEncryptionKeys();
	}

	// -----------------------------------------------------------------------
	// Identity
	// -----------------------------------------------------------------------

	/** Returns the Ed25519 public key of the signing keypair. */
	getPublicKey() {
		return this.#encryptedSecretShareSigningKeypair.getPublicKey();
	}

	/** Returns the Sui address derived from the signing keypair. */
	getSuiAddress(): string {
		return this.#encryptedSecretShareSigningKeypair.getPublicKey().toSuiAddress();
	}

	/** Returns the raw bytes of the Ed25519 signing public key. */
	getSigningPublicKeyBytes(): Uint8Array {
		return this.#encryptedSecretShareSigningKeypair.getPublicKey().toRawBytes();
	}

	// -----------------------------------------------------------------------
	// Signature operations
	// -----------------------------------------------------------------------

	/**
	 * Verifies an Ed25519 signature over a message using the signing
	 * public key.
	 */
	async verifySignature(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
		return await this.#encryptedSecretShareSigningKeypair.getPublicKey().verify(message, signature);
	}

	/**
	 * Signs the encryption key with the Ed25519 signing keypair.
	 * Used to prove ownership when registering the key on-chain.
	 */
	async getEncryptionKeySignature(): Promise<Uint8Array> {
		return await this.#encryptedSecretShareSigningKeypair.sign(this.encryptionKey);
	}

	/**
	 * Signs the dWallet public output to authorize a newly created dWallet.
	 *
	 * @throws If the dWallet is not in `AwaitingKeyHolderSignature` state,
	 *         or the user public output doesn't match the on-chain output.
	 */
	async getUserOutputSignature(
		dWallet: DWallet,
		userPublicOutput: Uint8Array,
	): Promise<Uint8Array> {
		if (!dWallet.state.AwaitingKeyHolderSignature?.public_output) {
			throw new Error('DWallet is not in awaiting key holder signature state');
		}

		const dWalletPublicOutput = Uint8Array.from(
			dWallet.state.AwaitingKeyHolderSignature?.public_output,
		);

		const isOutputMatch = await userAndNetworkDKGOutputMatch(
			fromNumberToCurve(dWallet.curve),
			userPublicOutput,
			dWalletPublicOutput,
		).catch(() => false);

		if (!isOutputMatch) {
			throw new Error('User public output does not match the DWallet public output');
		}

		return await this.#encryptedSecretShareSigningKeypair.sign(dWalletPublicOutput);
	}

	/**
	 * Signs the dWallet public output for a transferred/shared dWallet.
	 *
	 * Verifies the source encrypted share against the source encryption key
	 * before signing. The source encryption key should be known to the
	 * receiver through a trusted channel — **do not fetch it from the
	 * network without independent verification.**
	 */
	async getUserOutputSignatureForTransferredDWallet(
		dWallet: DWallet,
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
		sourceEncryptionKey: EncryptionKey,
	): Promise<Uint8Array> {
		const dWalletPublicOutput = await verifyAndGetDWalletDKGPublicOutput(
			dWallet,
			sourceEncryptedUserSecretKeyShare,
			new Ed25519PublicKey(sourceEncryptionKey.signer_public_key),
		);

		return await this.#encryptedSecretShareSigningKeypair.sign(dWalletPublicOutput);
	}

	// -----------------------------------------------------------------------
	// Decryption
	// -----------------------------------------------------------------------

	/**
	 * Decrypts an encrypted user secret key share for a dWallet.
	 *
	 * Performs multi-layer verification before decryption:
	 * 1. Validates the dWallet is active with a public output.
	 * 2. Checks the encrypted share's signature against the signing key.
	 * 3. Decrypts with the class-groups decryption key.
	 * 4. Verifies consistency of the decrypted share against the public output.
	 *
	 * @throws If the dWallet is not active, verification fails, or
	 *         decryption fails.
	 */
	async decryptUserShare(
		dWallet: DWallet,
		encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
		protocolPublicParameters: Uint8Array,
	): Promise<{
		verifiedPublicOutput: Uint8Array;
		secretShare: Uint8Array;
	}> {
		const dWalletPublicOutput = await verifyAndGetDWalletDKGPublicOutput(
			dWallet,
			encryptedUserSecretKeyShare,
			this.#encryptedSecretShareSigningKeypair.getPublicKey(),
		);

		return {
			verifiedPublicOutput: dWalletPublicOutput,
			secretShare: Uint8Array.from(
				await decrypt_user_share(
					fromCurveToNumber(this.curve),
					this.decryptionKey,
					dWalletPublicOutput,
					Uint8Array.from(encryptedUserSecretKeyShare.encrypted_centralized_secret_share_and_proof),
					protocolPublicParameters,
				),
			),
		};
	}

	// -----------------------------------------------------------------------
	// Hash functions
	// -----------------------------------------------------------------------

	/**
	 * Derives a 32-byte seed by hashing:
	 * `keccak256(ASCII(domainSeparator) || curveNumber || rootSeed)`
	 *
	 * This is the correct derivation that includes the actual curve byte.
	 */
	static hash(domainSeparator: string, rootSeed: Uint8Array, curve: Curve): Uint8Array {
		return new Uint8Array(
			keccak_256(
				Uint8Array.from([...encodeToASCII(domainSeparator), fromCurveToNumber(curve), ...rootSeed]),
			),
		);
	}

	/**
	 * Legacy hash: `keccak256(ASCII(domainSeparator) || 0 || rootSeed)`.
	 *
	 * Always uses `0` as the curve byte regardless of the actual curve,
	 * matching the original buggy behavior. Only used internally by
	 * {@link fromRootSeedKeyLegacyHash}.
	 *
	 * @deprecated Use {@link hash} for all new key derivations.
	 */
	static hashLegacy(domainSeparator: string, rootSeed: Uint8Array, _curve: Curve): Uint8Array {
		return new Uint8Array(
			keccak_256(Uint8Array.from([...encodeToASCII(domainSeparator), 0, ...rootSeed])),
		);
	}

	// -----------------------------------------------------------------------
	// Private serialization helpers
	// -----------------------------------------------------------------------

	#serializeShareEncryptionKeys() {
		const fields = {
			encryptionKey: this.encryptionKey,
			decryptionKey: this.decryptionKey,
			secretShareSigningSecretKey: this.#encryptedSecretShareSigningKeypair.getSecretKey(),
			curve: fromCurveToNumber(this.curve),
		};

		// Legacy keys serialize as V1, fixed keys as V2.
		return VersionedUserShareEncryptionKeysBcs.serialize(
			this.legacyHash ? { V1: fields } : { V2: fields },
		).toBytes();
	}

	static #parseShareEncryptionKeys(shareEncryptionKeysBytes: Uint8Array) {
		const parsed = VersionedUserShareEncryptionKeysBcs.parse(shareEncryptionKeysBytes);

		// V1 variant → legacy hash was used; V2 → fixed hash.
		const variant = parsed.V1 ?? parsed.V2;
		const legacyHash = !!parsed.V1;
		const { encryptionKey, decryptionKey, secretShareSigningSecretKey, curve } = variant;

		return {
			encryptionKey: new Uint8Array(encryptionKey),
			decryptionKey: new Uint8Array(decryptionKey),
			secretShareSigningSecretKey,
			curve: fromNumberToCurve(Number(curve)),
			legacyHash,
		};
	}
}
