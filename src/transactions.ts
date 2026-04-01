// Copyright (c) Unconfirmed Labs Ltd.
// SPDX-License-Identifier: Apache-2.0

// =============================================================================
// transactions.ts — Standalone transaction builders for the @unconfirmed/ika SDK
//
// Each public function takes a single params object, creates or accepts a
// `Transaction`, and returns the `Transaction` (or `Promise<Transaction>` for
// async operations). Low-level Move call helpers from the original coordinator
// and system modules are inlined as private helpers.
// =============================================================================

import { bcs } from '@mysten/sui/bcs';
import { Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import type {
	TransactionObjectArgument,
	TransactionResult,
} from '@mysten/sui/transactions';

import type { IkaConfig } from './types.ts';
import type { IkaClient } from './client.ts';
import type {
	Curve,
	DWallet,
	EncryptedUserSecretKeyShare,
	EncryptionKey,
	Hash,
	ImportedKeyDWallet,
	ImportedSharedDWallet,
	Presign,
	SharedDWallet,
	UserSignatureInputs,
	ZeroTrustDWallet,
} from './types.ts';
import { SignatureAlgorithm } from './types.ts';
import type { DKGRequestInput, ImportDWalletVerificationRequestInput, UserShareEncryptionKeys } from './crypto.ts';
import type { ValidHashForSignature, ValidSignatureAlgorithmForCurve } from './validation.ts';
import {
	fromCurveAndSignatureAlgorithmAndHashToNumbers,
	fromCurveAndSignatureAlgorithmToNumbers,
	fromCurveToNumber,
	fromHashToNumber,
	fromNumberToCurve,
	validateCurveSignatureAlgorithm,
	validateHashSignatureCombination,
} from './validation.ts';
import {
	createRandomSessionIdentifier,
	encryptSecretShare,
	verifyUserShare,
} from './crypto.ts';
import {
	create_sign_centralized_party_message as create_sign,
	create_sign_centralized_party_message_with_centralized_party_dkg_output as create_sign_with_centralized_output,
} from './wasm.ts';

// =============================================================================
// Shared-object reference helpers
// =============================================================================

function getCoordinatorObjectRef(
	config: IkaConfig,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.sharedObjectRef({
		objectId: config.objects.ikaDWalletCoordinator.objectID,
		initialSharedVersion: config.objects.ikaDWalletCoordinator.initialSharedVersion,
		mutable: true,
	});
}

function getSystemObjectRef(
	config: IkaConfig,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.sharedObjectRef({
		objectId: config.objects.ikaSystemObject.objectID,
		initialSharedVersion: config.objects.ikaSystemObject.initialSharedVersion,
		mutable: true,
	});
}

// =============================================================================
// Private low-level coordinator Move call helpers
// =============================================================================

function registerEncryptionKeyTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	curve: number,
	encryptionKey: Uint8Array,
	encryptionKeySignature: Uint8Array,
	signerPublicKey: Uint8Array,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::register_encryption_key`,
		arguments: [
			coordinatorRef,
			tx.pure.u32(curve),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptionKey)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptionKeySignature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signerPublicKey)),
		],
	});
}

function registerSessionIdentifierTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	sessionIdentifier: Uint8Array,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::register_session_identifier`,
		arguments: [coordinatorRef, tx.pure(bcs.vector(bcs.u8()).serialize(sessionIdentifier))],
	});
}

function getActiveEncryptionKeyTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	address: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::get_active_encryption_key`,
		arguments: [coordinatorRef, tx.pure.address(address)],
	});
}

function approveMessageTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	dwalletCap: TransactionObjectArgument,
	signatureAlgorithm: number,
	hashScheme: number,
	message: Uint8Array,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::approve_message`,
		arguments: [
			coordinatorRef,
			dwalletCap,
			tx.pure.u32(signatureAlgorithm),
			tx.pure.u32(hashScheme),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

function approveImportedKeyMessageTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	importedKeyDWalletCap: TransactionObjectArgument,
	signatureAlgorithm: number,
	hashScheme: number,
	message: Uint8Array,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::approve_imported_key_message`,
		arguments: [
			coordinatorRef,
			importedKeyDWalletCap,
			tx.pure.u32(signatureAlgorithm),
			tx.pure.u32(hashScheme),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

function requestDWalletDKGTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	dwalletNetworkEncryptionKeyId: string,
	curve: number,
	userPublicKeyShareAndProof: Uint8Array,
	encryptedUserShareAndProof: Uint8Array,
	encryptionKeyAddress: string,
	userPublicOutput: Uint8Array,
	signerPublicKey: Uint8Array,
	sessionIdentifier: TransactionObjectArgument,
	signDuringDKGRequest: TransactionObjectArgument | null,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionResult {
	const signDuringDKGRequestSerialized = tx.object.option({
		type: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator_inner::SignDuringDKGRequest`,
		value: signDuringDKGRequest,
	})(tx);

	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_dwallet_dkg`,
		arguments: [
			coordinatorRef,
			tx.pure.id(dwalletNetworkEncryptionKeyId),
			tx.pure.u32(curve),
			tx.pure(bcs.vector(bcs.u8()).serialize(userPublicKeyShareAndProof)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptedUserShareAndProof)),
			tx.pure.address(encryptionKeyAddress),
			tx.pure(bcs.vector(bcs.u8()).serialize(userPublicOutput)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signerPublicKey)),
			signDuringDKGRequestSerialized,
			tx.object(sessionIdentifier),
			ikaCoin,
			suiCoin,
		],
	});
}

function requestDWalletDKGWithPublicUserSecretKeyShareTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	dwalletNetworkEncryptionKeyId: string,
	curve: number,
	userPublicKeyShareAndProof: Uint8Array,
	publicUserSecretKeyShare: Uint8Array,
	userPublicOutput: Uint8Array,
	sessionIdentifier: TransactionObjectArgument,
	signDuringDKGRequest: TransactionObjectArgument | null,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionResult {
	const signDuringDKGRequestSerialized = tx.object.option({
		type: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator_inner::SignDuringDKGRequest`,
		value: signDuringDKGRequest,
	})(tx);

	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_dwallet_dkg_with_public_user_secret_key_share`,
		arguments: [
			coordinatorRef,
			tx.pure.id(dwalletNetworkEncryptionKeyId),
			tx.pure.u32(curve),
			tx.pure(bcs.vector(bcs.u8()).serialize(userPublicKeyShareAndProof)),
			tx.pure(bcs.vector(bcs.u8()).serialize(userPublicOutput)),
			tx.pure(bcs.vector(bcs.u8()).serialize(publicUserSecretKeyShare)),
			signDuringDKGRequestSerialized,
			tx.object(sessionIdentifier),
			ikaCoin,
			suiCoin,
		],
	});
}

function signDuringDKGRequestTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	presignCap: TransactionObjectArgument,
	hashScheme: number,
	message: Uint8Array,
	messageCentralizedSignature: Uint8Array,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::sign_during_dkg_request`,
		arguments: [
			coordinatorRef,
			presignCap,
			tx.pure.u32(hashScheme),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
			tx.pure(bcs.vector(bcs.u8()).serialize(messageCentralizedSignature)),
		],
	});
}

function requestPresignTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	dwalletId: string,
	signatureAlgorithm: number,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_presign`,
		arguments: [
			coordinatorRef,
			tx.pure.id(dwalletId),
			tx.pure.u32(signatureAlgorithm),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

function requestGlobalPresignTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	dwalletNetworkEncryptionKeyId: string,
	curve: number,
	signatureAlgorithm: number,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_global_presign`,
		arguments: [
			coordinatorRef,
			tx.pure.id(dwalletNetworkEncryptionKeyId),
			tx.pure.u32(curve),
			tx.pure.u32(signatureAlgorithm),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

function verifyPresignCapTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	unverifiedPresignCap: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::verify_presign_cap`,
		arguments: [coordinatorRef, tx.object(unverifiedPresignCap)],
	});
}

function requestSignAndReturnIdTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	verifiedPresignCap: TransactionObjectArgument,
	messageApproval: TransactionObjectArgument,
	messageUserSignature: Uint8Array,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_sign_and_return_id`,
		arguments: [
			coordinatorRef,
			verifiedPresignCap,
			messageApproval,
			tx.pure(bcs.vector(bcs.u8()).serialize(messageUserSignature)),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

function requestImportedKeySignAndReturnIdTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	verifiedPresignCap: TransactionObjectArgument,
	importedKeyMessageApproval: TransactionObjectArgument,
	messageUserSignature: Uint8Array,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_imported_key_sign_and_return_id`,
		arguments: [
			coordinatorRef,
			verifiedPresignCap,
			importedKeyMessageApproval,
			tx.pure(bcs.vector(bcs.u8()).serialize(messageUserSignature)),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

function requestFutureSignTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	dwalletId: string,
	verifiedPresignCap: TransactionObjectArgument,
	message: Uint8Array,
	hashScheme: number,
	messageUserSignature: Uint8Array,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_future_sign`,
		arguments: [
			coordinatorRef,
			tx.pure.id(dwalletId),
			verifiedPresignCap,
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
			tx.pure.u32(hashScheme),
			tx.pure(bcs.vector(bcs.u8()).serialize(messageUserSignature)),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

function verifyPartialUserSignatureCapTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	unverifiedPartialUserSignatureCap: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::verify_partial_user_signature_cap`,
		arguments: [coordinatorRef, tx.object(unverifiedPartialUserSignatureCap)],
	});
}

function requestSignWithPartialUserSignatureAndReturnIdTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	verifiedPartialUserSignatureCap: TransactionObjectArgument,
	messageApproval: TransactionObjectArgument,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_sign_with_partial_user_signature_and_return_id`,
		arguments: [
			coordinatorRef,
			tx.object(verifiedPartialUserSignatureCap),
			tx.object(messageApproval),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

function requestImportedKeySignWithPartialUserSignatureAndReturnIdTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	verifiedPartialUserSignatureCap: TransactionObjectArgument | string,
	importedKeyMessageApproval: TransactionObjectArgument | string,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_imported_key_sign_with_partial_user_signature_and_return_id`,
		arguments: [
			coordinatorRef,
			tx.object(verifiedPartialUserSignatureCap),
			tx.object(importedKeyMessageApproval),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

function acceptEncryptedUserShareTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	dwalletId: string,
	encryptedUserSecretKeyShareId: string,
	userOutputSignature: Uint8Array,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::accept_encrypted_user_share`,
		arguments: [
			coordinatorRef,
			tx.pure.id(dwalletId),
			tx.pure.id(encryptedUserSecretKeyShareId),
			tx.pure(bcs.vector(bcs.u8()).serialize(userOutputSignature)),
		],
	});
}

function requestMakeDwalletUserSecretKeySharesPublicTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	dwalletId: string,
	publicUserSecretKeyShare: Uint8Array,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_make_dwallet_user_secret_key_shares_public`,
		arguments: [
			coordinatorRef,
			tx.pure.id(dwalletId),
			tx.pure(bcs.vector(bcs.u8()).serialize(publicUserSecretKeyShare)),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

function requestReEncryptUserShareForTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	dwalletId: string,
	destinationEncryptionKeyAddress: string,
	encryptedUserShareAndProof: Uint8Array,
	sourceEncryptedUserSecretKeyShareId: string,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
) {
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_re_encrypt_user_share_for`,
		arguments: [
			coordinatorRef,
			tx.pure.id(dwalletId),
			tx.pure.address(destinationEncryptionKeyAddress),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptedUserShareAndProof)),
			tx.pure.id(sourceEncryptedUserSecretKeyShareId),
			sessionIdentifier,
			ikaCoin,
			suiCoin,
		],
	});
}

function requestImportedKeyDwalletVerificationTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	dwalletNetworkEncryptionKeyId: string,
	curve: number,
	userOutgoingMessage: Uint8Array,
	encryptedUserShareAndProof: Uint8Array,
	encryptionKeyAddress: string,
	userPublicOutput: Uint8Array,
	signerPublicKey: Uint8Array,
	sessionIdentifier: TransactionObjectArgument,
	ikaCoin: TransactionObjectArgument,
	suiCoin: TransactionObjectArgument,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_imported_key_dwallet_verification`,
		arguments: [
			coordinatorRef,
			tx.pure.id(dwalletNetworkEncryptionKeyId),
			tx.pure.u32(curve),
			tx.pure(bcs.vector(bcs.u8()).serialize(userOutgoingMessage)),
			tx.pure(bcs.vector(bcs.u8()).serialize(encryptedUserShareAndProof)),
			tx.pure.address(encryptionKeyAddress),
			tx.pure(bcs.vector(bcs.u8()).serialize(userPublicOutput)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signerPublicKey)),
			tx.object(sessionIdentifier),
			ikaCoin,
			suiCoin,
		],
	});
}

function hasDWalletTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	dwalletId: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::has_dwallet`,
		arguments: [coordinatorRef, tx.pure.id(dwalletId)],
	});
}

function getDWalletTx(
	config: IkaConfig,
	coordinatorRef: TransactionObjectArgument,
	dwalletId: string,
	tx: Transaction,
): TransactionObjectArgument {
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::get_dwallet`,
		arguments: [coordinatorRef, tx.pure.id(dwalletId)],
	});
}

// =============================================================================
// Private internal helpers (assertion, crypto, signing)
// =============================================================================

function assertDWalletPublicOutputSet(
	dWallet: DWallet,
): asserts dWallet is DWallet & { state: { Active: { public_output: Uint8Array } } } {
	if (!dWallet.state.Active?.public_output) {
		throw new Error('DWallet public output is not set');
	}
}

function assertDWalletPublicUserSecretKeyShareSet(
	dWallet: DWallet,
): asserts dWallet is DWallet & { public_user_secret_key_share: Uint8Array } {
	if (!dWallet.public_user_secret_key_share) {
		throw new Error('DWallet public user secret key share is not set');
	}
}

function assertPresignCompleted(
	presign: Presign,
): asserts presign is Presign & { state: { Completed: { presign: Uint8Array } } } {
	if (!presign.state.Completed?.presign) {
		throw new Error('Presign is not completed');
	}
}

function assertCanRunNormalPresign(dWallet: DWallet, signatureAlgorithm: SignatureAlgorithm) {
	if (
		dWallet.is_imported_key_dwallet &&
		(signatureAlgorithm === 'ECDSASecp256k1' || signatureAlgorithm === 'ECDSASecp256r1')
	) {
		return;
	}

	const dWalletVersion = dWallet.state.Active?.public_output?.[0] ?? 0 + 1;

	if (
		!dWallet.is_imported_key_dwallet &&
		dWallet.state.Active?.public_output &&
		dWalletVersion === 1 &&
		signatureAlgorithm === 'ECDSASecp256k1'
	) {
		return;
	}

	throw new Error(
		'You can call this function for ecdsa signatures only, and if this is imported key dwallet, or the version is 1',
	);
}

async function decryptAndVerifySecretShare({
	dWallet,
	encryptedUserSecretKeyShare,
	userShareEncryptionKeys,
	publicParameters,
}: {
	dWallet: DWallet;
	encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
	userShareEncryptionKeys: UserShareEncryptionKeys;
	publicParameters: Uint8Array;
}): Promise<{
	publicParameters: Uint8Array;
	secretShare: Uint8Array;
	verifiedPublicOutput: Uint8Array;
}> {
	const { secretShare, verifiedPublicOutput } =
		await userShareEncryptionKeys.decryptUserShare(
			dWallet,
			encryptedUserSecretKeyShare,
			publicParameters,
		);

	const userShareVerified = verifyUserShare(
		fromNumberToCurve(dWallet.curve),
		secretShare,
		verifiedPublicOutput,
		publicParameters,
	);

	if (!userShareVerified) {
		throw new Error('User share verification failed');
	}

	return { publicParameters, secretShare, verifiedPublicOutput };
}

async function getUserSecretKeyShare({
	secretShare,
	encryptedUserSecretKeyShare,
	activeDWallet,
	publicParameters,
	publicOutput,
	userShareEncryptionKeys,
}: {
	secretShare?: Uint8Array;
	encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
	activeDWallet: DWallet;
	publicParameters: Uint8Array;
	publicOutput?: Uint8Array;
	userShareEncryptionKeys?: UserShareEncryptionKeys;
}): Promise<{
	secretShare: Uint8Array;
	verifiedPublicOutput: Uint8Array;
}> {
	if (secretShare) {
		if (!publicOutput) {
			throw new Error('Public output is required when providing secret share directly');
		}
		return { secretShare, verifiedPublicOutput: publicOutput };
	}

	if (!encryptedUserSecretKeyShare) {
		throw new Error('Encrypted user secret key share is not set');
	}

	if (!userShareEncryptionKeys) {
		throw new Error('User share encryption keys are not set');
	}

	return decryptAndVerifySecretShare({
		dWallet: activeDWallet,
		encryptedUserSecretKeyShare,
		userShareEncryptionKeys,
		publicParameters,
	});
}

async function createUserSignMessageWithPublicOutput({
	protocolPublicParameters,
	publicOutput,
	userSecretKeyShare,
	presign,
	message,
	hash,
	signatureScheme,
	curve,
	createWithCentralizedOutput,
}: {
	protocolPublicParameters: Uint8Array;
	publicOutput: Uint8Array;
	userSecretKeyShare: Uint8Array;
	presign: Uint8Array;
	message: Uint8Array;
	hash: Hash;
	signatureScheme: SignatureAlgorithm;
	curve: Curve;
	createWithCentralizedOutput?: boolean;
}): Promise<Uint8Array> {
	const { curveNumber, signatureAlgorithmNumber, hashNumber } =
		fromCurveAndSignatureAlgorithmAndHashToNumbers(curve, signatureScheme, hash);

	if (createWithCentralizedOutput) {
		return new Uint8Array(
			await create_sign_with_centralized_output(
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
	} else {
		return new Uint8Array(
			await create_sign(
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
}

/**
 * Internal helper to compute the user's sign message from UserSignatureInputs.
 * Handles decryption, verification, and WASM sign creation.
 */
async function getUserSignMessage({
	userSignatureInputs,
	signDuringDKG = false,
	ikaClient,
	userShareEncryptionKeys,
}: {
	userSignatureInputs: UserSignatureInputs;
	signDuringDKG?: boolean;
	ikaClient: IkaClient;
	userShareEncryptionKeys?: UserShareEncryptionKeys;
}): Promise<Uint8Array> {
	assertPresignCompleted(userSignatureInputs.presign);

	const publicParameters = await ikaClient.getProtocolPublicParameters(
		userSignatureInputs.activeDWallet,
		userSignatureInputs.curve,
	);

	let secretShare: Uint8Array;
	let publicOutput: Uint8Array;

	if (userSignatureInputs.activeDWallet) {
		if (
			userSignatureInputs.activeDWallet.public_user_secret_key_share &&
			userSignatureInputs.activeDWallet.state.Active?.public_output
		) {
			secretShare = Uint8Array.from(
				userSignatureInputs.activeDWallet.public_user_secret_key_share,
			);
			publicOutput = Uint8Array.from(
				userSignatureInputs.activeDWallet.state.Active?.public_output,
			);
		} else {
			const userSecretKeyShareResponse = await getUserSecretKeyShare({
				secretShare: userSignatureInputs.secretShare,
				encryptedUserSecretKeyShare: userSignatureInputs.encryptedUserSecretKeyShare,
				activeDWallet: userSignatureInputs.activeDWallet,
				publicParameters,
				publicOutput: userSignatureInputs.publicOutput,
				userShareEncryptionKeys,
			});

			secretShare = userSecretKeyShareResponse.secretShare;
			publicOutput = userSecretKeyShareResponse.verifiedPublicOutput;
		}
	} else {
		if (!userSignatureInputs.secretShare || !userSignatureInputs.publicOutput) {
			throw new Error(
				'Secret share and public output are required when activeDWallet is not set',
			);
		}

		secretShare = userSignatureInputs.secretShare;
		publicOutput = userSignatureInputs.publicOutput;

		if (!signDuringDKG) {
			if (!userSignatureInputs.curve) {
				throw new Error(
					'Curve is required when providing explicit secret share and public output without activeDWallet',
				);
			}

			const userShareVerified = verifyUserShare(
				userSignatureInputs.curve,
				secretShare,
				publicOutput,
				publicParameters,
			);

			if (!userShareVerified) {
				throw new Error('User share verification failed');
			}
		}
	}

	return createUserSignMessageWithPublicOutput({
		protocolPublicParameters: publicParameters,
		publicOutput,
		userSecretKeyShare: secretShare,
		presign: userSignatureInputs.presign.state.Completed?.presign,
		message: userSignatureInputs.message,
		hash: userSignatureInputs.hash,
		signatureScheme: userSignatureInputs.signatureScheme,
		curve: userSignatureInputs.curve,
		createWithCentralizedOutput: userSignatureInputs.createWithCentralizedOutput,
	});
}

// =============================================================================
// Helper to create a session identifier within a transaction
// =============================================================================

function createSessionId(
	config: IkaConfig,
	tx: Transaction,
): TransactionObjectArgument {
	return registerSessionIdentifierTx(
		config,
		getCoordinatorObjectRef(config, tx),
		createRandomSessionIdentifier(),
		tx,
	);
}

// =============================================================================
// PUBLIC TRANSACTION BUILDERS — Session
// =============================================================================

/**
 * Create a random session identifier and register it with the coordinator.
 */
export function createSessionIdentifier(params: {
	config: IkaConfig;
	tx: Transaction;
}): TransactionObjectArgument {
	const { config, tx } = params;
	return createSessionId(config, tx);
}

/**
 * Register a specific session identifier with the coordinator.
 */
export function registerSessionIdentifier(params: {
	config: IkaConfig;
	tx: Transaction;
	sessionIdentifier: Uint8Array;
}): TransactionObjectArgument {
	const { config, tx, sessionIdentifier } = params;
	return registerSessionIdentifierTx(
		config,
		getCoordinatorObjectRef(config, tx),
		sessionIdentifier,
		tx,
	);
}

// =============================================================================
// PUBLIC TRANSACTION BUILDERS — DKG
// =============================================================================

/**
 * Request DKG (Distributed Key Generation) to create a dWallet.
 * Returns the DWallet capability transaction result.
 */
export async function requestDWalletDKG<S extends SignatureAlgorithm = never>(params: {
	config: IkaConfig;
	tx: Transaction;
	ikaClient: IkaClient;
	userShareEncryptionKeys: UserShareEncryptionKeys;
	dkgRequestInput: DKGRequestInput;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
	sessionIdentifier: TransactionObjectArgument;
	dwalletNetworkEncryptionKeyId: string;
	curve: Curve;
	signDuringDKGRequest?: S extends never
		? never
		: {
				message: Uint8Array;
				presign: Presign;
				verifiedPresignCap: TransactionObjectArgument;
				hashScheme: ValidHashForSignature<S>;
				signatureAlgorithm: S;
			};
}): Promise<{ tx: Transaction; dwalletRef: TransactionResult }> {
	const {
		config,
		tx,
		ikaClient,
		userShareEncryptionKeys,
		dkgRequestInput,
		ikaCoin,
		suiCoin,
		sessionIdentifier,
		dwalletNetworkEncryptionKeyId,
		curve,
		signDuringDKGRequest,
	} = params;

	const coordinatorRef = getCoordinatorObjectRef(config, tx);

	// Validate hash and signature algorithm combination if signing during DKG
	if (signDuringDKGRequest) {
		validateHashSignatureCombination(
			signDuringDKGRequest.hashScheme,
			signDuringDKGRequest.signatureAlgorithm,
		);
		validateCurveSignatureAlgorithm(curve, signDuringDKGRequest.signatureAlgorithm);
	}

	let signDuringDKGRequestObj: TransactionObjectArgument | null = null;
	if (signDuringDKGRequest) {
		const userSignMsg = await getUserSignMessage({
			userSignatureInputs: {
				secretShare: dkgRequestInput.userSecretKeyShare,
				publicOutput: dkgRequestInput.userPublicOutput,
				hash: signDuringDKGRequest.hashScheme,
				message: signDuringDKGRequest.message,
				signatureScheme: signDuringDKGRequest.signatureAlgorithm,
				presign: signDuringDKGRequest.presign,
				curve,
				createWithCentralizedOutput: true,
			},
			signDuringDKG: true,
			ikaClient,
			userShareEncryptionKeys,
		});

		signDuringDKGRequestObj = signDuringDKGRequestTx(
			config,
			coordinatorRef,
			signDuringDKGRequest.verifiedPresignCap,
			fromHashToNumber(
				curve,
				signDuringDKGRequest.signatureAlgorithm,
				signDuringDKGRequest.hashScheme,
			),
			signDuringDKGRequest.message,
			userSignMsg,
			tx,
		);
	}

	const dwalletRef = requestDWalletDKGTx(
		config,
		coordinatorRef,
		dwalletNetworkEncryptionKeyId,
		fromCurveToNumber(curve),
		dkgRequestInput.userDKGMessage,
		dkgRequestInput.encryptedUserShareAndProof,
		userShareEncryptionKeys.getSuiAddress(),
		dkgRequestInput.userPublicOutput,
		userShareEncryptionKeys.getSigningPublicKeyBytes(),
		sessionIdentifier,
		signDuringDKGRequestObj,
		ikaCoin,
		suiCoin,
		tx,
	);

	return { tx, dwalletRef };
}

/**
 * Request DKG with a public (non-encrypted) user secret key share.
 * Returns the DWallet capability transaction result.
 */
export async function requestDWalletDKGWithPublicUserShare<
	S extends SignatureAlgorithm = never,
>(params: {
	config: IkaConfig;
	tx: Transaction;
	ikaClient: IkaClient;
	userShareEncryptionKeys: UserShareEncryptionKeys;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
	sessionIdentifier: TransactionObjectArgument;
	dwalletNetworkEncryptionKeyId: string;
	curve: Curve;
	publicKeyShareAndProof: Uint8Array;
	publicUserSecretKeyShare: Uint8Array;
	userPublicOutput: Uint8Array;
	signDuringDKGRequest?: S extends never
		? never
		: {
				message: Uint8Array;
				presign: Presign;
				verifiedPresignCap: TransactionObjectArgument;
				hashScheme: ValidHashForSignature<S>;
				signatureAlgorithm: S;
			};
}): Promise<{ tx: Transaction; dwalletRef: TransactionResult }> {
	const {
		config,
		tx,
		ikaClient,
		userShareEncryptionKeys,
		ikaCoin,
		suiCoin,
		sessionIdentifier,
		dwalletNetworkEncryptionKeyId,
		curve,
		publicKeyShareAndProof,
		publicUserSecretKeyShare,
		userPublicOutput,
		signDuringDKGRequest,
	} = params;

	const coordinatorRef = getCoordinatorObjectRef(config, tx);

	// Validate hash and signature algorithm combination if signing during DKG
	if (signDuringDKGRequest) {
		validateHashSignatureCombination(
			signDuringDKGRequest.hashScheme,
			signDuringDKGRequest.signatureAlgorithm,
		);
		validateCurveSignatureAlgorithm(curve, signDuringDKGRequest.signatureAlgorithm);
	}

	let signDuringDKGRequestObj: TransactionObjectArgument | null = null;
	if (signDuringDKGRequest) {
		const userSignMsg = await getUserSignMessage({
			userSignatureInputs: {
				hash: signDuringDKGRequest.hashScheme,
				message: signDuringDKGRequest.message,
				signatureScheme: signDuringDKGRequest.signatureAlgorithm,
				presign: signDuringDKGRequest.presign,
				curve,
				publicOutput: userPublicOutput,
				secretShare: publicUserSecretKeyShare,
				createWithCentralizedOutput: true,
			},
			signDuringDKG: true,
			ikaClient,
			userShareEncryptionKeys,
		});

		signDuringDKGRequestObj = signDuringDKGRequestTx(
			config,
			coordinatorRef,
			signDuringDKGRequest.verifiedPresignCap,
			fromHashToNumber(
				curve,
				signDuringDKGRequest.signatureAlgorithm,
				signDuringDKGRequest.hashScheme,
			),
			signDuringDKGRequest.message,
			userSignMsg,
			tx,
		);
	}

	const dwalletRef = requestDWalletDKGWithPublicUserSecretKeyShareTx(
		config,
		coordinatorRef,
		dwalletNetworkEncryptionKeyId,
		fromCurveToNumber(curve),
		publicKeyShareAndProof,
		publicUserSecretKeyShare,
		userPublicOutput,
		sessionIdentifier,
		signDuringDKGRequestObj,
		ikaCoin,
		suiCoin,
		tx,
	);

	return { tx, dwalletRef };
}

// =============================================================================
// PUBLIC TRANSACTION BUILDERS — Presign
// =============================================================================

/**
 * Request a presign operation for a DWallet.
 *
 * Use this for ECDSA (k1, r1) signatures with imported key dwallets.
 * For Schnorr, SchnorrkelSubstrate, EdDSA, and Taproot, use `requestGlobalPresign` instead.
 */
export function requestPresign(params: {
	config: IkaConfig;
	tx: Transaction;
	dWallet: DWallet;
	signatureAlgorithm: SignatureAlgorithm;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): TransactionObjectArgument {
	const { config, tx, dWallet, signatureAlgorithm, ikaCoin, suiCoin } = params;

	assertDWalletPublicOutputSet(dWallet);
	assertCanRunNormalPresign(dWallet, signatureAlgorithm);
	validateCurveSignatureAlgorithm(fromNumberToCurve(dWallet.curve), signatureAlgorithm);

	const coordinatorRef = getCoordinatorObjectRef(config, tx);
	const { signatureAlgorithmNumber } = fromCurveAndSignatureAlgorithmToNumbers(
		fromNumberToCurve(dWallet.curve),
		signatureAlgorithm,
	);

	return requestPresignTx(
		config,
		coordinatorRef,
		dWallet.id,
		signatureAlgorithmNumber,
		createSessionId(config, tx),
		ikaCoin,
		suiCoin,
		tx,
	);
}

/**
 * Request a global presign operation.
 *
 * Use this for Schnorr, SchnorrkelSubstrate, EdDSA, and Taproot signatures.
 * For ECDSA (k1, r1) with imported key dwallets, use `requestPresign` instead.
 */
export function requestGlobalPresign<C extends Curve>(params: {
	config: IkaConfig;
	tx: Transaction;
	dwalletNetworkEncryptionKeyId: string;
	curve: C;
	signatureAlgorithm: ValidSignatureAlgorithmForCurve<C>;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): TransactionObjectArgument {
	const { config, tx, dwalletNetworkEncryptionKeyId, curve, signatureAlgorithm, ikaCoin, suiCoin } =
		params;

	validateCurveSignatureAlgorithm(curve, signatureAlgorithm);

	const coordinatorRef = getCoordinatorObjectRef(config, tx);
	const { curveNumber, signatureAlgorithmNumber } = fromCurveAndSignatureAlgorithmToNumbers(
		curve,
		signatureAlgorithm,
	);

	return requestGlobalPresignTx(
		config,
		coordinatorRef,
		dwalletNetworkEncryptionKeyId,
		curveNumber,
		signatureAlgorithmNumber,
		createSessionId(config, tx),
		ikaCoin,
		suiCoin,
		tx,
	);
}

// =============================================================================
// PUBLIC TRANSACTION BUILDERS — Message Approval
// =============================================================================

/**
 * Approve a message for signing with a DWallet.
 * Returns the message approval transaction object argument.
 */
export function approveMessage<C extends Curve, S extends ValidSignatureAlgorithmForCurve<C>>(params: {
	config: IkaConfig;
	tx: Transaction;
	dWalletCap: TransactionObjectArgument | string;
	curve: C;
	signatureAlgorithm: S;
	hashScheme: ValidHashForSignature<S>;
	message: Uint8Array;
}): TransactionObjectArgument {
	const { config, tx, dWalletCap, curve, signatureAlgorithm, hashScheme, message } = params;

	validateCurveSignatureAlgorithm(curve, signatureAlgorithm);
	validateHashSignatureCombination(hashScheme, signatureAlgorithm);

	const { signatureAlgorithmNumber, hashNumber } =
		fromCurveAndSignatureAlgorithmAndHashToNumbers(curve, signatureAlgorithm, hashScheme);

	return approveMessageTx(
		config,
		getCoordinatorObjectRef(config, tx),
		tx.object(dWalletCap),
		signatureAlgorithmNumber,
		hashNumber,
		message,
		tx,
	);
}

/**
 * Approve a message for signing with an imported key DWallet.
 * Returns the imported key message approval transaction object argument.
 */
export function approveImportedKeyMessage<
	C extends Curve,
	S extends ValidSignatureAlgorithmForCurve<C>,
>(params: {
	config: IkaConfig;
	tx: Transaction;
	dWalletCap: TransactionObjectArgument | string;
	curve: C;
	signatureAlgorithm: S;
	hashScheme: ValidHashForSignature<S>;
	message: Uint8Array;
}): TransactionObjectArgument {
	const { config, tx, dWalletCap, curve, signatureAlgorithm, hashScheme, message } = params;

	validateCurveSignatureAlgorithm(curve, signatureAlgorithm);
	validateHashSignatureCombination(hashScheme, signatureAlgorithm);

	const { signatureAlgorithmNumber, hashNumber } =
		fromCurveAndSignatureAlgorithmAndHashToNumbers(curve, signatureAlgorithm, hashScheme);

	return approveImportedKeyMessageTx(
		config,
		getCoordinatorObjectRef(config, tx),
		tx.object(dWalletCap),
		signatureAlgorithmNumber,
		hashNumber,
		message,
		tx,
	);
}

/**
 * Verify a presign capability to ensure it can be used for signing.
 * Converts an unverified presign capability into a verified one.
 */
export function verifyPresignCap(params: {
	config: IkaConfig;
	tx: Transaction;
	presign?: Presign;
	unverifiedPresignCap?: TransactionObjectArgument | string;
}): TransactionObjectArgument {
	const { config, tx, presign, unverifiedPresignCap } = params;

	let capId: TransactionObjectArgument | string;

	if (unverifiedPresignCap) {
		capId = unverifiedPresignCap;
	} else if (presign?.cap_id) {
		capId = presign.cap_id;
	} else {
		throw new Error('Either presign or unverifiedPresignCap must be provided');
	}

	return verifyPresignCapTx(
		config,
		getCoordinatorObjectRef(config, tx),
		tx.object(capId),
		tx,
	);
}

// =============================================================================
// PUBLIC TRANSACTION BUILDERS — Signing
// =============================================================================

/**
 * Sign a message using a DWallet (ZeroTrust or Shared).
 * For imported key DWallets, use `requestSignWithImportedKey` instead.
 */
export async function requestSign<S extends SignatureAlgorithm>(params: {
	config: IkaConfig;
	tx: Transaction;
	ikaClient: IkaClient;
	userShareEncryptionKeys?: UserShareEncryptionKeys;
	dWallet: ZeroTrustDWallet | SharedDWallet;
	messageApproval: TransactionObjectArgument;
	hashScheme: ValidHashForSignature<S>;
	verifiedPresignCap: TransactionObjectArgument;
	presign: Presign;
	encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
	secretShare?: Uint8Array;
	publicOutput?: Uint8Array;
	message: Uint8Array;
	signatureScheme: S;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): Promise<Transaction> {
	const {
		config,
		tx,
		ikaClient,
		userShareEncryptionKeys,
		dWallet,
		messageApproval,
		hashScheme,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		secretShare,
		publicOutput,
		message,
		signatureScheme,
		ikaCoin,
		suiCoin,
	} = params;

	validateHashSignatureCombination(hashScheme, signatureScheme);
	validateCurveSignatureAlgorithm(fromNumberToCurve(dWallet.curve), signatureScheme);

	const hasPublicShares = !!dWallet.public_user_secret_key_share;

	let userSignatureInputs: UserSignatureInputs;

	if (encryptedUserSecretKeyShare) {
		userSignatureInputs = {
			activeDWallet: dWallet,
			presign,
			encryptedUserSecretKeyShare,
			message,
			hash: hashScheme,
			signatureScheme,
			curve: fromNumberToCurve(dWallet.curve),
		};
	} else if (secretShare && publicOutput) {
		userSignatureInputs = {
			activeDWallet: dWallet,
			presign,
			secretShare,
			publicOutput,
			message,
			hash: hashScheme,
			signatureScheme,
			curve: fromNumberToCurve(dWallet.curve),
		};
	} else if (hasPublicShares) {
		assertDWalletPublicUserSecretKeyShareSet(dWallet);
		assertDWalletPublicOutputSet(dWallet);

		userSignatureInputs = {
			activeDWallet: dWallet,
			presign,
			publicOutput: Uint8Array.from(dWallet.state.Active?.public_output),
			secretShare: Uint8Array.from(dWallet.public_user_secret_key_share),
			message,
			hash: hashScheme,
			signatureScheme,
			curve: fromNumberToCurve(dWallet.curve),
		};
	} else {
		throw new Error(
			'DWallet signing requires either encryptedUserSecretKeyShare, (secretShare + publicOutput), or public_user_secret_key_share on the DWallet',
		);
	}

	const userSignMessage = await getUserSignMessage({
		userSignatureInputs,
		ikaClient,
		userShareEncryptionKeys,
	});

	const coordinatorRef = getCoordinatorObjectRef(config, tx);

	requestSignAndReturnIdTx(
		config,
		coordinatorRef,
		verifiedPresignCap,
		messageApproval,
		userSignMessage,
		createSessionId(config, tx),
		ikaCoin,
		suiCoin,
		tx,
	);

	return tx;
}

/**
 * Sign a message using an Imported Key DWallet.
 */
export async function requestSignWithImportedKey<
	S extends SignatureAlgorithm = typeof SignatureAlgorithm.ECDSASecp256k1,
>(params: {
	config: IkaConfig;
	tx: Transaction;
	ikaClient: IkaClient;
	userShareEncryptionKeys?: UserShareEncryptionKeys;
	dWallet: ImportedKeyDWallet | ImportedSharedDWallet;
	importedKeyMessageApproval: TransactionObjectArgument;
	hashScheme: ValidHashForSignature<S>;
	verifiedPresignCap: TransactionObjectArgument;
	presign: Presign;
	encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
	secretShare?: Uint8Array;
	publicOutput?: Uint8Array;
	message: Uint8Array;
	signatureScheme?: S;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): Promise<Transaction> {
	const {
		config,
		tx,
		ikaClient,
		userShareEncryptionKeys,
		dWallet,
		importedKeyMessageApproval,
		hashScheme,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		secretShare,
		publicOutput,
		message,
		signatureScheme,
		ikaCoin,
		suiCoin,
	} = params;

	if (!dWallet.is_imported_key_dwallet) {
		throw new Error('dWallet must be an ImportedKeyDWallet');
	}

	const actualSignatureScheme = signatureScheme || SignatureAlgorithm.ECDSASecp256k1;
	validateHashSignatureCombination(hashScheme, actualSignatureScheme);
	validateCurveSignatureAlgorithm(fromNumberToCurve(dWallet.curve), actualSignatureScheme);

	const hasPublicShares = !!dWallet.public_user_secret_key_share;

	let userSignatureInputs: UserSignatureInputs;

	if (encryptedUserSecretKeyShare) {
		userSignatureInputs = {
			activeDWallet: dWallet,
			encryptedUserSecretKeyShare,
			presign,
			message,
			hash: hashScheme,
			signatureScheme: actualSignatureScheme,
			curve: fromNumberToCurve(dWallet.curve),
		};
	} else if (secretShare && publicOutput) {
		userSignatureInputs = {
			activeDWallet: dWallet,
			secretShare,
			publicOutput,
			presign,
			message,
			hash: hashScheme,
			signatureScheme: actualSignatureScheme,
			curve: fromNumberToCurve(dWallet.curve),
		};
	} else if (hasPublicShares) {
		assertDWalletPublicUserSecretKeyShareSet(dWallet);

		userSignatureInputs = {
			activeDWallet: dWallet,
			presign,
			message,
			hash: hashScheme,
			signatureScheme: actualSignatureScheme,
			curve: fromNumberToCurve(dWallet.curve),
		};
	} else {
		throw new Error(
			'Imported Key DWallet signing requires either encryptedUserSecretKeyShare, (secretShare + publicOutput), or public_user_secret_key_share on the DWallet',
		);
	}

	const userSignMessage = await getUserSignMessage({
		userSignatureInputs,
		ikaClient,
		userShareEncryptionKeys,
	});

	const coordinatorRef = getCoordinatorObjectRef(config, tx);

	requestImportedKeySignAndReturnIdTx(
		config,
		coordinatorRef,
		verifiedPresignCap,
		importedKeyMessageApproval,
		userSignMessage,
		createSessionId(config, tx),
		ikaCoin,
		suiCoin,
		tx,
	);

	return tx;
}

// =============================================================================
// PUBLIC TRANSACTION BUILDERS — Future Sign
// =============================================================================

/**
 * Request a future sign operation for a DWallet (ZeroTrust or Shared).
 * Creates a partial user signature capability that can later be combined with a message approval.
 * For imported key DWallets, use `requestFutureSignWithImportedKey` instead.
 */
export async function requestFutureSign<S extends SignatureAlgorithm>(params: {
	config: IkaConfig;
	tx: Transaction;
	ikaClient: IkaClient;
	userShareEncryptionKeys?: UserShareEncryptionKeys;
	dWallet: ZeroTrustDWallet | SharedDWallet;
	verifiedPresignCap: TransactionObjectArgument;
	presign: Presign;
	encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
	secretShare?: Uint8Array;
	publicOutput?: Uint8Array;
	message: Uint8Array;
	hashScheme: ValidHashForSignature<S>;
	signatureScheme: S;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): Promise<Transaction> {
	const {
		config,
		tx,
		ikaClient,
		userShareEncryptionKeys,
		dWallet,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		secretShare,
		publicOutput,
		message,
		hashScheme,
		signatureScheme,
		ikaCoin,
		suiCoin,
	} = params;

	validateHashSignatureCombination(hashScheme, signatureScheme);
	validateCurveSignatureAlgorithm(fromNumberToCurve(dWallet.curve), signatureScheme);

	const hasPublicShares = !!dWallet.public_user_secret_key_share;

	let userSignatureInputs: UserSignatureInputs;

	if (encryptedUserSecretKeyShare) {
		userSignatureInputs = {
			activeDWallet: dWallet,
			presign,
			encryptedUserSecretKeyShare,
			message,
			hash: hashScheme,
			signatureScheme,
			curve: fromNumberToCurve(dWallet.curve),
		};
	} else if (secretShare && publicOutput) {
		userSignatureInputs = {
			activeDWallet: dWallet,
			presign,
			secretShare,
			publicOutput,
			message,
			hash: hashScheme,
			signatureScheme,
			curve: fromNumberToCurve(dWallet.curve),
		};
	} else if (hasPublicShares) {
		assertDWalletPublicUserSecretKeyShareSet(dWallet);
		assertDWalletPublicOutputSet(dWallet);

		userSignatureInputs = {
			activeDWallet: dWallet,
			presign,
			publicOutput: Uint8Array.from(dWallet.state.Active?.public_output),
			secretShare: Uint8Array.from(dWallet.public_user_secret_key_share),
			message,
			hash: hashScheme,
			signatureScheme,
			curve: fromNumberToCurve(dWallet.curve),
		};
	} else {
		throw new Error(
			'DWallet future signing requires either encryptedUserSecretKeyShare, (secretShare + publicOutput), or public_user_secret_key_share on the DWallet',
		);
	}

	if (!userSignatureInputs.activeDWallet) {
		throw new Error('Active DWallet is required');
	}

	const userSignMessage = await getUserSignMessage({
		userSignatureInputs,
		ikaClient,
		userShareEncryptionKeys,
	});

	const { hashNumber } = fromCurveAndSignatureAlgorithmAndHashToNumbers(
		userSignatureInputs.curve,
		userSignatureInputs.signatureScheme,
		userSignatureInputs.hash,
	);

	const coordinatorRef = getCoordinatorObjectRef(config, tx);

	requestFutureSignTx(
		config,
		coordinatorRef,
		userSignatureInputs.activeDWallet.id,
		verifiedPresignCap,
		userSignatureInputs.message,
		hashNumber,
		userSignMessage,
		createSessionId(config, tx),
		ikaCoin,
		suiCoin,
		tx,
	);

	return tx;
}

/**
 * Request a future sign operation for an Imported Key DWallet.
 * Creates a partial user signature capability that can later be combined with a message approval.
 */
export async function requestFutureSignWithImportedKey<S extends SignatureAlgorithm>(params: {
	config: IkaConfig;
	tx: Transaction;
	ikaClient: IkaClient;
	userShareEncryptionKeys?: UserShareEncryptionKeys;
	dWallet: ImportedKeyDWallet | ImportedSharedDWallet;
	verifiedPresignCap: TransactionObjectArgument;
	presign: Presign;
	encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
	secretShare?: Uint8Array;
	publicOutput?: Uint8Array;
	message: Uint8Array;
	hashScheme: ValidHashForSignature<S>;
	signatureScheme: S;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): Promise<Transaction> {
	const {
		config,
		tx,
		ikaClient,
		userShareEncryptionKeys,
		dWallet,
		verifiedPresignCap,
		presign,
		encryptedUserSecretKeyShare,
		secretShare,
		publicOutput,
		message,
		hashScheme,
		signatureScheme,
		ikaCoin,
		suiCoin,
	} = params;

	validateHashSignatureCombination(hashScheme, signatureScheme);
	validateCurveSignatureAlgorithm(fromNumberToCurve(dWallet.curve), signatureScheme);

	const hasPublicShares = !!dWallet.public_user_secret_key_share;

	let userSignatureInputs: UserSignatureInputs;

	if (encryptedUserSecretKeyShare) {
		userSignatureInputs = {
			activeDWallet: dWallet,
			presign,
			encryptedUserSecretKeyShare,
			message,
			hash: hashScheme,
			signatureScheme,
			curve: fromNumberToCurve(dWallet.curve),
		};
	} else if (secretShare && publicOutput) {
		userSignatureInputs = {
			activeDWallet: dWallet,
			presign,
			secretShare,
			publicOutput,
			message,
			hash: hashScheme,
			signatureScheme,
			curve: fromNumberToCurve(dWallet.curve),
		};
	} else if (hasPublicShares) {
		assertDWalletPublicUserSecretKeyShareSet(dWallet);
		assertDWalletPublicOutputSet(dWallet);

		userSignatureInputs = {
			activeDWallet: dWallet,
			presign,
			publicOutput: Uint8Array.from(dWallet.state.Active?.public_output),
			secretShare: Uint8Array.from(dWallet.public_user_secret_key_share),
			message,
			hash: hashScheme,
			signatureScheme,
			curve: fromNumberToCurve(dWallet.curve),
		};
	} else {
		throw new Error(
			'Imported Key DWallet future signing requires either encryptedUserSecretKeyShare, (secretShare + publicOutput), or public_user_secret_key_share on the DWallet',
		);
	}

	if (!userSignatureInputs.activeDWallet) {
		throw new Error('Active DWallet is required');
	}

	const userSignMessage = await getUserSignMessage({
		userSignatureInputs,
		ikaClient,
		userShareEncryptionKeys,
	});

	const { hashNumber } = fromCurveAndSignatureAlgorithmAndHashToNumbers(
		userSignatureInputs.curve,
		userSignatureInputs.signatureScheme,
		userSignatureInputs.hash,
	);

	const coordinatorRef = getCoordinatorObjectRef(config, tx);

	requestFutureSignTx(
		config,
		coordinatorRef,
		userSignatureInputs.activeDWallet.id,
		verifiedPresignCap,
		userSignatureInputs.message,
		hashNumber,
		userSignMessage,
		createSessionId(config, tx),
		ikaCoin,
		suiCoin,
		tx,
	);

	return tx;
}

/**
 * Complete a future sign operation using a previously created partial user signature.
 * Combines the partial signature with a message approval to create a full signature.
 */
export function futureSign(params: {
	config: IkaConfig;
	tx: Transaction;
	partialUserSignatureCap: TransactionObjectArgument | string;
	messageApproval: TransactionObjectArgument;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): TransactionObjectArgument {
	const { config, tx, partialUserSignatureCap, messageApproval, ikaCoin, suiCoin } = params;
	const coordinatorRef = getCoordinatorObjectRef(config, tx);

	return requestSignWithPartialUserSignatureAndReturnIdTx(
		config,
		coordinatorRef,
		verifyPartialUserSignatureCapTx(
			config,
			coordinatorRef,
			tx.object(partialUserSignatureCap),
			tx,
		),
		messageApproval,
		createSessionId(config, tx),
		ikaCoin,
		suiCoin,
		tx,
	);
}

/**
 * Complete a future sign operation for imported key using a previously created partial user signature.
 * Combines the partial signature with an imported key message approval to create a full signature.
 */
export function futureSignWithImportedKey(params: {
	config: IkaConfig;
	tx: Transaction;
	partialUserSignatureCap: TransactionObjectArgument | string;
	importedKeyMessageApproval: TransactionObjectArgument | string;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): TransactionObjectArgument {
	const { config, tx, partialUserSignatureCap, importedKeyMessageApproval, ikaCoin, suiCoin } =
		params;
	const coordinatorRef = getCoordinatorObjectRef(config, tx);

	return requestImportedKeySignWithPartialUserSignatureAndReturnIdTx(
		config,
		coordinatorRef,
		verifyPartialUserSignatureCapTx(
			config,
			coordinatorRef,
			tx.object(partialUserSignatureCap),
			tx,
		),
		importedKeyMessageApproval,
		createSessionId(config, tx),
		ikaCoin,
		suiCoin,
		tx,
	);
}

// =============================================================================
// PUBLIC TRANSACTION BUILDERS — Key Management
// =============================================================================

/**
 * Register an encryption key for the current user on the specified curve.
 */
export async function registerEncryptionKey(params: {
	config: IkaConfig;
	tx: Transaction;
	userShareEncryptionKeys: UserShareEncryptionKeys;
	curve: Curve;
}): Promise<Transaction> {
	const { config, tx, userShareEncryptionKeys, curve } = params;

	registerEncryptionKeyTx(
		config,
		getCoordinatorObjectRef(config, tx),
		fromCurveToNumber(curve),
		userShareEncryptionKeys.encryptionKey,
		await userShareEncryptionKeys.getEncryptionKeySignature(),
		userShareEncryptionKeys.getSigningPublicKeyBytes(),
		tx,
	);

	return tx;
}

/**
 * Accept an encrypted user share for a DWallet (after DKG or transfer).
 *
 * For a regular DWallet: provide `userPublicOutput` and `encryptedUserSecretKeyShareId`.
 * For a transferred DWallet: provide `sourceEncryptionKey`, `sourceEncryptedUserSecretKeyShare`,
 * and `destinationEncryptedUserSecretKeyShare`.
 */
export async function acceptEncryptedUserShare(params: {
	config: IkaConfig;
	tx: Transaction;
	userShareEncryptionKeys: UserShareEncryptionKeys;
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet;
	// Regular DWallet params
	userPublicOutput?: Uint8Array;
	encryptedUserSecretKeyShareId?: string;
	// Transferred DWallet params
	sourceEncryptionKey?: EncryptionKey;
	sourceEncryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
	destinationEncryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
}): Promise<Transaction> {
	const {
		config,
		tx,
		userShareEncryptionKeys,
		dWallet,
		userPublicOutput,
		encryptedUserSecretKeyShareId,
		sourceEncryptionKey,
		sourceEncryptedUserSecretKeyShare,
		destinationEncryptedUserSecretKeyShare,
	} = params;

	const coordinatorRef = getCoordinatorObjectRef(config, tx);

	// Regular DWallet encrypted user share acceptance
	if (userPublicOutput && encryptedUserSecretKeyShareId) {
		acceptEncryptedUserShareTx(
			config,
			coordinatorRef,
			dWallet.id,
			encryptedUserSecretKeyShareId,
			await userShareEncryptionKeys.getUserOutputSignature(dWallet, userPublicOutput),
			tx,
		);

		return tx;
	}

	// Transferred DWallet encrypted user share acceptance
	if (
		sourceEncryptionKey &&
		sourceEncryptedUserSecretKeyShare &&
		destinationEncryptedUserSecretKeyShare
	) {
		acceptEncryptedUserShareTx(
			config,
			coordinatorRef,
			dWallet.id,
			destinationEncryptedUserSecretKeyShare.id,
			await userShareEncryptionKeys.getUserOutputSignatureForTransferredDWallet(
				dWallet,
				sourceEncryptedUserSecretKeyShare,
				sourceEncryptionKey,
			),
			tx,
		);

		return tx;
	}

	throw new Error(
		'Invalid parameters: must provide either (userPublicOutput, encryptedUserSecretKeyShareId) for regular DWallet or (sourceEncryptionKey, sourceEncryptedUserSecretKeyShare, destinationEncryptedUserSecretKeyShare) for transferred DWallet',
	);
}

/**
 * Transfer an encrypted user share to another address by re-encrypting it.
 *
 * When `sourceSecretShare` is provided, it is used directly.
 * Otherwise, the encrypted share is decrypted automatically (requires `userShareEncryptionKeys`).
 */
export async function requestReEncryptUserShareFor(params: {
	config: IkaConfig;
	tx: Transaction;
	ikaClient: IkaClient;
	userShareEncryptionKeys?: UserShareEncryptionKeys;
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet;
	destinationEncryptionKeyAddress: string;
	sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
	sourceSecretShare?: Uint8Array;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): Promise<Transaction> {
	const {
		config,
		tx,
		ikaClient,
		userShareEncryptionKeys,
		dWallet,
		destinationEncryptionKeyAddress,
		sourceEncryptedUserSecretKeyShare,
		sourceSecretShare,
		ikaCoin,
		suiCoin,
	} = params;

	let finalSourceSecretShare: Uint8Array;

	if (sourceSecretShare) {
		finalSourceSecretShare = sourceSecretShare;
	} else {
		if (!userShareEncryptionKeys) {
			throw new Error('User share encryption keys are not set');
		}

		const { secretShare: decryptedSecretShare } =
			await userShareEncryptionKeys.decryptUserShare(
				dWallet,
				sourceEncryptedUserSecretKeyShare,
				await ikaClient.getProtocolPublicParameters(dWallet),
			);
		finalSourceSecretShare = decryptedSecretShare;
	}

	if (!sourceEncryptedUserSecretKeyShare.state.KeyHolderSigned?.user_output_signature) {
		throw new Error('User output signature is not set');
	}

	const publicParameters = await ikaClient.getProtocolPublicParameters(dWallet);
	const destinationEncryptionKeyObj = await ikaClient.getActiveEncryptionKey(
		destinationEncryptionKeyAddress,
	);

	const publicKey = new Ed25519PublicKey(
		new Uint8Array(destinationEncryptionKeyObj.signer_public_key),
	);

	if (
		!(await publicKey.verify(
			Uint8Array.from(destinationEncryptionKeyObj.encryption_key),
			Uint8Array.from(destinationEncryptionKeyObj.encryption_key_signature),
		))
	) {
		throw new Error('Destination encryption key signature is not valid');
	}

	if (publicKey.toSuiAddress() !== destinationEncryptionKeyObj.signer_address) {
		throw new Error('Destination encryption key address does not match the public key');
	}

	const coordinatorRef = getCoordinatorObjectRef(config, tx);

	requestReEncryptUserShareForTx(
		config,
		coordinatorRef,
		dWallet.id,
		destinationEncryptionKeyAddress,
		await encryptSecretShare(
			fromNumberToCurve(destinationEncryptionKeyObj.curve),
			finalSourceSecretShare,
			new Uint8Array(destinationEncryptionKeyObj.encryption_key),
			publicParameters,
		),
		sourceEncryptedUserSecretKeyShare.id,
		createSessionId(config, tx),
		ikaCoin,
		suiCoin,
		tx,
	);

	return tx;
}

/**
 * Make DWallet user secret key shares public, allowing signing without decryption.
 */
export function requestMakeDwalletUserSecretKeySharesPublic(params: {
	config: IkaConfig;
	tx: Transaction;
	dWallet: ZeroTrustDWallet | ImportedKeyDWallet;
	secretShare: Uint8Array;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): Transaction {
	const { config, tx, dWallet, secretShare, ikaCoin, suiCoin } = params;

	const coordinatorRef = getCoordinatorObjectRef(config, tx);

	requestMakeDwalletUserSecretKeySharesPublicTx(
		config,
		coordinatorRef,
		dWallet.id,
		secretShare,
		createSessionId(config, tx),
		ikaCoin,
		suiCoin,
		tx,
	);

	return tx;
}

/**
 * Request verification for an Imported Key DWallet.
 * Creates a DWallet from an existing cryptographic key that was generated outside the network.
 */
export async function requestImportedKeyDWalletVerification(params: {
	config: IkaConfig;
	tx: Transaction;
	ikaClient: IkaClient;
	userShareEncryptionKeys: UserShareEncryptionKeys;
	importDWalletVerificationRequestInput: ImportDWalletVerificationRequestInput;
	curve: Curve;
	signerPublicKey: Uint8Array;
	sessionIdentifier: TransactionObjectArgument;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): Promise<Transaction> {
	const {
		config,
		tx,
		ikaClient,
		userShareEncryptionKeys,
		importDWalletVerificationRequestInput,
		curve,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin,
		suiCoin,
	} = params;

	const networkEncryptionKey = await ikaClient.getConfiguredNetworkEncryptionKey();

	requestImportedKeyDwalletVerificationTx(
		config,
		getCoordinatorObjectRef(config, tx),
		networkEncryptionKey.id,
		fromCurveToNumber(curve),
		importDWalletVerificationRequestInput.userMessage,
		importDWalletVerificationRequestInput.encryptedUserShareAndProof,
		userShareEncryptionKeys.getSuiAddress(),
		importDWalletVerificationRequestInput.userPublicOutput,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin,
		suiCoin,
		tx,
	);

	return tx;
}

// =============================================================================
// PUBLIC TRANSACTION BUILDERS — Imported Key DWallet creation
// =============================================================================

/**
 * Request creation of an Imported Key DWallet.
 * This combines imported key verification with DKG in a single operation.
 */
export async function requestImportedKeyDWallet(params: {
	config: IkaConfig;
	tx: Transaction;
	ikaClient: IkaClient;
	userShareEncryptionKeys: UserShareEncryptionKeys;
	importDWalletVerificationRequestInput: ImportDWalletVerificationRequestInput;
	dkgRequestInput: DKGRequestInput;
	curve: Curve;
	signerPublicKey: Uint8Array;
	dwalletNetworkEncryptionKeyId: string;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): Promise<{ tx: Transaction; dwalletRef: TransactionResult }> {
	const {
		config,
		tx,
		ikaClient,
		userShareEncryptionKeys,
		importDWalletVerificationRequestInput,
		dkgRequestInput,
		curve,
		signerPublicKey,
		dwalletNetworkEncryptionKeyId,
		ikaCoin,
		suiCoin,
	} = params;

	const sessionIdentifier = createSessionId(config, tx);

	// First: imported key verification
	requestImportedKeyDwalletVerificationTx(
		config,
		getCoordinatorObjectRef(config, tx),
		(await ikaClient.getConfiguredNetworkEncryptionKey()).id,
		fromCurveToNumber(curve),
		importDWalletVerificationRequestInput.userMessage,
		importDWalletVerificationRequestInput.encryptedUserShareAndProof,
		userShareEncryptionKeys.getSuiAddress(),
		importDWalletVerificationRequestInput.userPublicOutput,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin,
		suiCoin,
		tx,
	);

	// Then: DKG with encrypted user share
	const dkgSessionIdentifier = createSessionId(config, tx);

	const dwalletRef = requestDWalletDKGTx(
		config,
		getCoordinatorObjectRef(config, tx),
		dwalletNetworkEncryptionKeyId,
		fromCurveToNumber(curve),
		dkgRequestInput.userDKGMessage,
		dkgRequestInput.encryptedUserShareAndProof,
		userShareEncryptionKeys.getSuiAddress(),
		dkgRequestInput.userPublicOutput,
		userShareEncryptionKeys.getSigningPublicKeyBytes(),
		dkgSessionIdentifier,
		null,
		ikaCoin,
		suiCoin,
		tx,
	);

	return { tx, dwalletRef };
}

/**
 * Request creation of an Imported Key DWallet with a public user share.
 */
export async function requestImportedKeyDWalletWithPublicUserShare(params: {
	config: IkaConfig;
	tx: Transaction;
	ikaClient: IkaClient;
	userShareEncryptionKeys: UserShareEncryptionKeys;
	importDWalletVerificationRequestInput: ImportDWalletVerificationRequestInput;
	curve: Curve;
	signerPublicKey: Uint8Array;
	dwalletNetworkEncryptionKeyId: string;
	publicKeyShareAndProof: Uint8Array;
	publicUserSecretKeyShare: Uint8Array;
	userPublicOutput: Uint8Array;
	ikaCoin: TransactionObjectArgument;
	suiCoin: TransactionObjectArgument;
}): Promise<{ tx: Transaction; dwalletRef: TransactionResult }> {
	const {
		config,
		tx,
		ikaClient,
		userShareEncryptionKeys,
		importDWalletVerificationRequestInput,
		curve,
		signerPublicKey,
		dwalletNetworkEncryptionKeyId,
		publicKeyShareAndProof,
		publicUserSecretKeyShare,
		userPublicOutput,
		ikaCoin,
		suiCoin,
	} = params;

	const sessionIdentifier = createSessionId(config, tx);

	// First: imported key verification
	requestImportedKeyDwalletVerificationTx(
		config,
		getCoordinatorObjectRef(config, tx),
		(await ikaClient.getConfiguredNetworkEncryptionKey()).id,
		fromCurveToNumber(curve),
		importDWalletVerificationRequestInput.userMessage,
		importDWalletVerificationRequestInput.encryptedUserShareAndProof,
		userShareEncryptionKeys.getSuiAddress(),
		importDWalletVerificationRequestInput.userPublicOutput,
		signerPublicKey,
		sessionIdentifier,
		ikaCoin,
		suiCoin,
		tx,
	);

	// Then: DKG with public user share
	const dkgSessionIdentifier = createSessionId(config, tx);

	const dwalletRef = requestDWalletDKGWithPublicUserSecretKeyShareTx(
		config,
		getCoordinatorObjectRef(config, tx),
		dwalletNetworkEncryptionKeyId,
		fromCurveToNumber(curve),
		publicKeyShareAndProof,
		publicUserSecretKeyShare,
		userPublicOutput,
		dkgSessionIdentifier,
		null,
		ikaCoin,
		suiCoin,
		tx,
	);

	return { tx, dwalletRef };
}

// =============================================================================
// PUBLIC TRANSACTION BUILDERS — Coordinator Queries
// =============================================================================

/**
 * Check if a DWallet with the specified ID exists in the coordinator.
 */
export function hasDWallet(params: {
	config: IkaConfig;
	tx: Transaction;
	dwalletId: string;
}): TransactionObjectArgument {
	const { config, tx, dwalletId } = params;
	return hasDWalletTx(config, getCoordinatorObjectRef(config, tx), dwalletId, tx);
}

/**
 * Get a reference to a DWallet object from the coordinator.
 */
export function getDWallet(params: {
	config: IkaConfig;
	tx: Transaction;
	dwalletId: string;
}): TransactionObjectArgument {
	const { config, tx, dwalletId } = params;
	return getDWalletTx(config, getCoordinatorObjectRef(config, tx), dwalletId, tx);
}

// =============================================================================
// PUBLIC TRANSACTION BUILDERS — Coordinator Admin Operations
// =============================================================================

export function processCheckpointMessageByQuorum(params: {
	config: IkaConfig;
	tx: Transaction;
	signature: Uint8Array;
	signersBitmap: Uint8Array;
	message: Uint8Array;
}): TransactionObjectArgument {
	const { config, tx, signature, signersBitmap, message } = params;
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::process_checkpoint_message_by_quorum`,
		arguments: [
			getCoordinatorObjectRef(config, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(signature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signersBitmap)),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

export function initiateMidEpochReconfiguration(params: {
	config: IkaConfig;
	tx: Transaction;
	systemCurrentStatusInfo: string;
}) {
	const { config, tx, systemCurrentStatusInfo } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::initiate_mid_epoch_reconfiguration`,
		arguments: [getCoordinatorObjectRef(config, tx), tx.object(systemCurrentStatusInfo)],
	});
}

export function requestNetworkEncryptionKeyMidEpochReconfiguration(params: {
	config: IkaConfig;
	tx: Transaction;
	dwalletNetworkEncryptionKeyId: string;
}) {
	const { config, tx, dwalletNetworkEncryptionKeyId } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_network_encryption_key_mid_epoch_reconfiguration`,
		arguments: [getCoordinatorObjectRef(config, tx), tx.pure.id(dwalletNetworkEncryptionKeyId)],
	});
}

export function advanceEpochCoordinator(params: {
	config: IkaConfig;
	tx: Transaction;
	advanceEpochApprover: string;
}) {
	const { config, tx, advanceEpochApprover } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::advance_epoch`,
		arguments: [getCoordinatorObjectRef(config, tx), tx.object(advanceEpochApprover)],
	});
}

export function requestDwalletNetworkEncryptionKeyDkgByCap(params: {
	config: IkaConfig;
	tx: Transaction;
	paramsForNetwork: Uint8Array;
	verifiedProtocolCap: TransactionObjectArgument;
}) {
	const { config, tx, paramsForNetwork, verifiedProtocolCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_dwallet_network_encryption_key_dkg_by_cap`,
		arguments: [
			getCoordinatorObjectRef(config, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(paramsForNetwork)),
			verifiedProtocolCap,
		],
	});
}

export function processCheckpointMessageByCap(params: {
	config: IkaConfig;
	tx: Transaction;
	message: Uint8Array;
	verifiedProtocolCap: string;
}): TransactionObjectArgument {
	const { config, tx, message, verifiedProtocolCap } = params;
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::process_checkpoint_message_by_cap`,
		arguments: [
			getCoordinatorObjectRef(config, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
			tx.object(verifiedProtocolCap),
		],
	});
}

export function setGasFeeReimbursementSuiSystemCallValueByCap(params: {
	config: IkaConfig;
	tx: Transaction;
	gasFeeReimbursementSuiSystemCallValue: number;
	verifiedProtocolCap: string;
}) {
	const { config, tx, gasFeeReimbursementSuiSystemCallValue, verifiedProtocolCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::set_gas_fee_reimbursement_sui_system_call_value_by_cap`,
		arguments: [
			getCoordinatorObjectRef(config, tx),
			tx.pure.u64(gasFeeReimbursementSuiSystemCallValue),
			tx.object(verifiedProtocolCap),
		],
	});
}

export function setSupportedAndPricing(params: {
	config: IkaConfig;
	tx: Transaction;
	defaultPricing: TransactionObjectArgument;
	supportedCurvesToSignatureAlgorithmsToHashSchemes: TransactionObjectArgument;
	verifiedProtocolCap: string;
}) {
	const { config, tx, defaultPricing, supportedCurvesToSignatureAlgorithmsToHashSchemes, verifiedProtocolCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::set_supported_and_pricing`,
		arguments: [
			getCoordinatorObjectRef(config, tx),
			defaultPricing,
			supportedCurvesToSignatureAlgorithmsToHashSchemes,
			tx.object(verifiedProtocolCap),
		],
	});
}

export function setPausedCurvesAndSignatureAlgorithms(params: {
	config: IkaConfig;
	tx: Transaction;
	pausedCurves: number[];
	pausedSignatureAlgorithms: number[];
	pausedHashSchemes: number[];
	verifiedProtocolCap: string;
}) {
	const { config, tx, pausedCurves, pausedSignatureAlgorithms, pausedHashSchemes, verifiedProtocolCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::set_paused_curves_and_signature_algorithms`,
		arguments: [
			getCoordinatorObjectRef(config, tx),
			tx.pure(bcs.vector(bcs.u32()).serialize(pausedCurves)),
			tx.pure(bcs.vector(bcs.u32()).serialize(pausedSignatureAlgorithms)),
			tx.pure(bcs.vector(bcs.u32()).serialize(pausedHashSchemes)),
			tx.object(verifiedProtocolCap),
		],
	});
}

export function setGlobalPresignConfig(params: {
	config: IkaConfig;
	tx: Transaction;
	curveToSignatureAlgorithmsForDkg: TransactionObjectArgument;
	curveToSignatureAlgorithmsForImportedKey: TransactionObjectArgument;
	verifiedProtocolCap: string;
}) {
	const { config, tx, curveToSignatureAlgorithmsForDkg, curveToSignatureAlgorithmsForImportedKey, verifiedProtocolCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::set_global_presign_config`,
		arguments: [
			getCoordinatorObjectRef(config, tx),
			curveToSignatureAlgorithmsForDkg,
			curveToSignatureAlgorithmsForImportedKey,
			tx.object(verifiedProtocolCap),
		],
	});
}

export function requestLockEpochSessions(params: {
	config: IkaConfig;
	tx: Transaction;
	systemCurrentStatusInfo: string;
}) {
	const { config, tx, systemCurrentStatusInfo } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::request_lock_epoch_sessions`,
		arguments: [getCoordinatorObjectRef(config, tx), tx.object(systemCurrentStatusInfo)],
	});
}

export function setPricingVote(params: {
	config: IkaConfig;
	tx: Transaction;
	pricing: TransactionObjectArgument;
	verifiedValidatorOperationCap: string;
}) {
	const { config, tx, pricing, verifiedValidatorOperationCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::set_pricing_vote`,
		arguments: [getCoordinatorObjectRef(config, tx), pricing, tx.object(verifiedValidatorOperationCap)],
	});
}

export function calculatePricingVotes(params: {
	config: IkaConfig;
	tx: Transaction;
	curve: number;
	signatureAlgorithm: TransactionObjectArgument;
	protocol: number;
}) {
	const { config, tx, curve, signatureAlgorithm, protocol } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::calculate_pricing_votes`,
		arguments: [
			getCoordinatorObjectRef(config, tx),
			tx.pure.u32(curve),
			signatureAlgorithm,
			tx.pure.u32(protocol),
		],
	});
}

export function isPresignValid(params: {
	config: IkaConfig;
	tx: Transaction;
	presignCap: string;
}): TransactionObjectArgument {
	const { config, tx, presignCap } = params;
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::is_presign_valid`,
		arguments: [getCoordinatorObjectRef(config, tx), tx.object(presignCap)],
	});
}

export function isPartialUserSignatureValid(params: {
	config: IkaConfig;
	tx: Transaction;
	unverifiedPartialUserSignatureCap: string;
}): TransactionObjectArgument {
	const { config, tx, unverifiedPartialUserSignatureCap } = params;
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::is_partial_user_signature_valid`,
		arguments: [getCoordinatorObjectRef(config, tx), tx.object(unverifiedPartialUserSignatureCap)],
	});
}

export function matchPartialUserSignatureWithMessageApproval(params: {
	config: IkaConfig;
	tx: Transaction;
	verifiedPartialUserSignatureCap: string;
	messageApproval: string;
}): TransactionObjectArgument {
	const { config, tx, verifiedPartialUserSignatureCap, messageApproval } = params;
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::match_partial_user_signature_with_message_approval`,
		arguments: [
			getCoordinatorObjectRef(config, tx),
			tx.object(verifiedPartialUserSignatureCap),
			tx.object(messageApproval),
		],
	});
}

export function matchPartialUserSignatureWithImportedKeyMessageApproval(params: {
	config: IkaConfig;
	tx: Transaction;
	verifiedPartialUserSignatureCap: string;
	importedKeyMessageApproval: string;
}): TransactionObjectArgument {
	const { config, tx, verifiedPartialUserSignatureCap, importedKeyMessageApproval } = params;
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::match_partial_user_signature_with_imported_key_message_approval`,
		arguments: [
			getCoordinatorObjectRef(config, tx),
			tx.object(verifiedPartialUserSignatureCap),
			tx.object(importedKeyMessageApproval),
		],
	});
}

export function currentPricing(params: {
	config: IkaConfig;
	tx: Transaction;
}): TransactionObjectArgument {
	const { config, tx } = params;
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::current_pricing`,
		arguments: [getCoordinatorObjectRef(config, tx)],
	});
}

export function subsidizeCoordinatorWithSui(params: {
	config: IkaConfig;
	tx: Transaction;
	suiCoin: TransactionObjectArgument;
}) {
	const { config, tx, suiCoin } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::subsidize_coordinator_with_sui`,
		arguments: [getCoordinatorObjectRef(config, tx), suiCoin],
	});
}

export function subsidizeCoordinatorWithIka(params: {
	config: IkaConfig;
	tx: Transaction;
	ikaCoin: TransactionObjectArgument;
}) {
	const { config, tx, ikaCoin } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::subsidize_coordinator_with_ika`,
		arguments: [getCoordinatorObjectRef(config, tx), ikaCoin],
	});
}

export function commitUpgradeCoordinator(params: {
	config: IkaConfig;
	tx: Transaction;
	upgradePackageApprover: string;
}) {
	const { config, tx, upgradePackageApprover } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::commit_upgrade`,
		arguments: [getCoordinatorObjectRef(config, tx), tx.object(upgradePackageApprover)],
	});
}

export function tryMigrateCoordinatorByCap(params: {
	config: IkaConfig;
	tx: Transaction;
	verifiedProtocolCap: string;
}) {
	const { config, tx, verifiedProtocolCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::try_migrate_by_cap`,
		arguments: [getCoordinatorObjectRef(config, tx), tx.object(verifiedProtocolCap)],
	});
}

export function tryMigrateCoordinator(params: {
	config: IkaConfig;
	tx: Transaction;
}) {
	const { config, tx } = params;
	tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::try_migrate`,
		arguments: [getCoordinatorObjectRef(config, tx)],
	});
}

export function coordinatorVersion(params: {
	config: IkaConfig;
	tx: Transaction;
}): TransactionObjectArgument {
	const { config, tx } = params;
	return tx.moveCall({
		target: `${config.packages.ikaDwallet2pcMpcPackage}::coordinator::version`,
		arguments: [getCoordinatorObjectRef(config, tx)],
	});
}

// =============================================================================
// PUBLIC TRANSACTION BUILDERS — System / Validator Operations (from system.ts)
// =============================================================================

export function requestAddValidatorCandidate(params: {
	config: IkaConfig;
	tx: Transaction;
	name: string;
	protocolPubkeyBytes: Uint8Array;
	networkPubkeyBytes: Uint8Array;
	consensusPubkeyBytes: Uint8Array;
	mpcDataBytes: Uint8Array[];
	proofOfPossessionBytes: Uint8Array;
	networkAddress: string;
	p2pAddress: string;
	consensusAddress: string;
	commissionRate: number;
	metadata: {
		name: string;
		description: string;
		imageUrl: string;
		projectUrl: string;
	};
}): {
	validatorCap: TransactionObjectArgument;
	validatorOperationCap: TransactionObjectArgument;
	validatorCommissionCap: TransactionObjectArgument;
} {
	const {
		config,
		tx,
		name,
		protocolPubkeyBytes,
		networkPubkeyBytes,
		consensusPubkeyBytes,
		mpcDataBytes,
		proofOfPossessionBytes,
		networkAddress,
		p2pAddress,
		consensusAddress,
		commissionRate,
		metadata,
	} = params;
	const systemRef = getSystemObjectRef(config, tx);

	const [validatorCap, validatorOperationCap, validatorCommissionCap] = tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::request_add_validator_candidate`,
		arguments: [
			systemRef,
			tx.pure.string(name),
			tx.pure(bcs.vector(bcs.u8()).serialize(protocolPubkeyBytes)),
			tx.pure(bcs.vector(bcs.u8()).serialize(networkPubkeyBytes)),
			tx.pure(bcs.vector(bcs.u8()).serialize(consensusPubkeyBytes)),
			tx.pure(bcs.vector(bcs.vector(bcs.u8())).serialize(mpcDataBytes)),
			tx.pure(bcs.vector(bcs.u8()).serialize(proofOfPossessionBytes)),
			tx.pure.string(networkAddress),
			tx.pure.string(p2pAddress),
			tx.pure.string(consensusAddress),
			tx.pure.u16(commissionRate),
			tx.moveCall({
				target: `${config.packages.ikaSystemPackage}::validator_metadata::new`,
				arguments: [
					tx.pure.string(metadata.imageUrl),
					tx.pure.string(metadata.projectUrl),
					tx.pure.string(metadata.description),
				],
			}),
		],
	});

	return { validatorCap, validatorOperationCap, validatorCommissionCap };
}

export function requestRemoveValidatorCandidate(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorCap: string;
}) {
	const { config, tx, validatorCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::request_remove_validator_candidate`,
		arguments: [getSystemObjectRef(config, tx), tx.object(validatorCap)],
	});
}

export function requestAddValidator(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorCap: string;
}) {
	const { config, tx, validatorCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::request_add_validator`,
		arguments: [getSystemObjectRef(config, tx), tx.object(validatorCap)],
	});
}

export function requestRemoveValidator(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorCap: string;
}) {
	const { config, tx, validatorCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::request_remove_validator`,
		arguments: [getSystemObjectRef(config, tx), tx.object(validatorCap)],
	});
}

export function setNextCommission(params: {
	config: IkaConfig;
	tx: Transaction;
	newCommissionRate: number;
	validatorOperationCap: string;
}) {
	const { config, tx, newCommissionRate, validatorOperationCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::set_next_commission`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.pure.u16(newCommissionRate),
			tx.object(validatorOperationCap),
		],
	});
}

export function requestAddStake(params: {
	config: IkaConfig;
	tx: Transaction;
	stakeCoin: TransactionObjectArgument;
	validatorId: string;
}): TransactionObjectArgument {
	const { config, tx, stakeCoin, validatorId } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::request_add_stake`,
		arguments: [getSystemObjectRef(config, tx), stakeCoin, tx.pure.id(validatorId)],
	});
}

export function requestWithdrawStake(params: {
	config: IkaConfig;
	tx: Transaction;
	stakedIka: string;
}) {
	const { config, tx, stakedIka } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::request_withdraw_stake`,
		arguments: [getSystemObjectRef(config, tx), tx.object(stakedIka)],
	});
}

export function withdrawStake(params: {
	config: IkaConfig;
	tx: Transaction;
	stakedIka: string;
}): TransactionObjectArgument {
	const { config, tx, stakedIka } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::withdraw_stake`,
		arguments: [getSystemObjectRef(config, tx), tx.object(stakedIka)],
	});
}

export function reportValidator(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorOperationCap: string;
	reporteeId: string;
}) {
	const { config, tx, validatorOperationCap, reporteeId } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::report_validator`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.object(validatorOperationCap),
			tx.pure.id(reporteeId),
		],
	});
}

export function undoReportValidator(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorOperationCap: string;
	reporteeId: string;
}) {
	const { config, tx, validatorOperationCap, reporteeId } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::undo_report_validator`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.object(validatorOperationCap),
			tx.pure.id(reporteeId),
		],
	});
}

export function rotateOperationCap(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorCap: string;
}): TransactionObjectArgument {
	const { config, tx, validatorCap } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::rotate_operation_cap`,
		arguments: [getSystemObjectRef(config, tx), tx.object(validatorCap)],
	});
}

export function rotateCommissionCap(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorCap: string;
}): TransactionObjectArgument {
	const { config, tx, validatorCap } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::rotate_commission_cap`,
		arguments: [getSystemObjectRef(config, tx), tx.object(validatorCap)],
	});
}

export function collectCommission(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorCommissionCap: string;
	amount: number | null;
}): TransactionObjectArgument {
	const { config, tx, validatorCommissionCap, amount } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::collect_commission`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.object(validatorCommissionCap),
			amount !== null
				? tx.pure(bcs.option(bcs.u64()).serialize(amount))
				: tx.pure(bcs.option(bcs.u64()).serialize(null)),
		],
	});
}

export function setValidatorName(params: {
	config: IkaConfig;
	tx: Transaction;
	name: string;
	validatorOperationCap: string;
}) {
	const { config, tx, name, validatorOperationCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::set_validator_name`,
		arguments: [getSystemObjectRef(config, tx), tx.pure.string(name), tx.object(validatorOperationCap)],
	});
}

export function validatorMetadata(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorId: string;
}): TransactionObjectArgument {
	const { config, tx, validatorId } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::validator_metadata`,
		arguments: [getSystemObjectRef(config, tx), tx.pure.id(validatorId)],
	});
}

export function setValidatorMetadata(params: {
	config: IkaConfig;
	tx: Transaction;
	metadata: {
		description: string;
		imageUrl: string;
		projectUrl: string;
	};
	validatorOperationCap: string;
}) {
	const { config, tx, metadata, validatorOperationCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::set_validator_metadata`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.moveCall({
				target: `${config.packages.ikaSystemPackage}::validator_metadata::new`,
				arguments: [
					tx.pure.string(metadata.imageUrl),
					tx.pure.string(metadata.projectUrl),
					tx.pure.string(metadata.description),
				],
			}),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochNetworkAddress(params: {
	config: IkaConfig;
	tx: Transaction;
	networkAddress: string;
	validatorOperationCap: string;
}) {
	const { config, tx, networkAddress, validatorOperationCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::set_next_epoch_network_address`,
		arguments: [getSystemObjectRef(config, tx), tx.pure.string(networkAddress), tx.object(validatorOperationCap)],
	});
}

export function setNextEpochP2pAddress(params: {
	config: IkaConfig;
	tx: Transaction;
	p2pAddress: string;
	validatorOperationCap: string;
}) {
	const { config, tx, p2pAddress, validatorOperationCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::set_next_epoch_p2p_address`,
		arguments: [getSystemObjectRef(config, tx), tx.pure.string(p2pAddress), tx.object(validatorOperationCap)],
	});
}

export function setNextEpochConsensusAddress(params: {
	config: IkaConfig;
	tx: Transaction;
	consensusAddress: string;
	validatorOperationCap: string;
}) {
	const { config, tx, consensusAddress, validatorOperationCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::set_next_epoch_consensus_address`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.pure.string(consensusAddress),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochProtocolPubkeyBytes(params: {
	config: IkaConfig;
	tx: Transaction;
	protocolPubkey: Uint8Array;
	proofOfPossessionBytes: Uint8Array;
	validatorOperationCap: string;
}) {
	const { config, tx, protocolPubkey, proofOfPossessionBytes, validatorOperationCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::set_next_epoch_protocol_pubkey_bytes`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(protocolPubkey)),
			tx.pure(bcs.vector(bcs.u8()).serialize(proofOfPossessionBytes)),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochNetworkPubkeyBytes(params: {
	config: IkaConfig;
	tx: Transaction;
	networkPubkey: Uint8Array;
	validatorOperationCap: string;
}) {
	const { config, tx, networkPubkey, validatorOperationCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::set_next_epoch_network_pubkey_bytes`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(networkPubkey)),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochConsensusPubkeyBytes(params: {
	config: IkaConfig;
	tx: Transaction;
	consensusPubkeyBytes: Uint8Array;
	validatorOperationCap: string;
}) {
	const { config, tx, consensusPubkeyBytes, validatorOperationCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::set_next_epoch_consensus_pubkey_bytes`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(consensusPubkeyBytes)),
			tx.object(validatorOperationCap),
		],
	});
}

export function setNextEpochMpcDataBytes(params: {
	config: IkaConfig;
	tx: Transaction;
	mpcData: Uint8Array[];
	validatorOperationCap: string;
}): TransactionObjectArgument {
	const { config, tx, mpcData, validatorOperationCap } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::set_next_epoch_mpc_data_bytes`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.pure(bcs.vector(bcs.vector(bcs.u8())).serialize(mpcData)),
			tx.object(validatorOperationCap),
		],
	});
}

export function activeCommittee(params: {
	config: IkaConfig;
	tx: Transaction;
}): TransactionObjectArgument {
	const { config, tx } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::active_committee`,
		arguments: [getSystemObjectRef(config, tx)],
	});
}

export function nextEpochActiveCommittee(params: {
	config: IkaConfig;
	tx: Transaction;
}): TransactionObjectArgument {
	const { config, tx } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::next_epoch_active_committee`,
		arguments: [getSystemObjectRef(config, tx)],
	});
}

export function initiateMidEpochReconfigurationSystem(params: {
	config: IkaConfig;
	tx: Transaction;
	clock: string;
}) {
	const { config, tx, clock } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::initiate_mid_epoch_reconfiguration`,
		arguments: [getSystemObjectRef(config, tx), tx.object(clock)],
	});
}

export function createSystemCurrentStatusInfo(params: {
	config: IkaConfig;
	tx: Transaction;
	clock: string;
}): TransactionObjectArgument {
	const { config, tx, clock } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::create_system_current_status_info`,
		arguments: [getSystemObjectRef(config, tx), tx.object(clock)],
	});
}

export function initiateAdvanceEpoch(params: {
	config: IkaConfig;
	tx: Transaction;
	clock: string;
}): TransactionObjectArgument {
	const { config, tx, clock } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::initiate_advance_epoch`,
		arguments: [getSystemObjectRef(config, tx), tx.object(clock)],
	});
}

export function advanceEpochSystem(params: {
	config: IkaConfig;
	tx: Transaction;
	advanceEpochApprover: string;
	clock: string;
}) {
	const { config, tx, advanceEpochApprover, clock } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::advance_epoch`,
		arguments: [getSystemObjectRef(config, tx), tx.object(advanceEpochApprover), tx.object(clock)],
	});
}

export function verifyValidatorCap(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorCap: string;
}): TransactionObjectArgument {
	const { config, tx, validatorCap } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::verify_validator_cap`,
		arguments: [getSystemObjectRef(config, tx), tx.object(validatorCap)],
	});
}

export function verifyOperationCap(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorOperationCap: string;
}): TransactionObjectArgument {
	const { config, tx, validatorOperationCap } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::verify_operation_cap`,
		arguments: [getSystemObjectRef(config, tx), tx.object(validatorOperationCap)],
	});
}

export function verifyCommissionCap(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorCommissionCap: string;
}): TransactionObjectArgument {
	const { config, tx, validatorCommissionCap } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::verify_commission_cap`,
		arguments: [getSystemObjectRef(config, tx), tx.object(validatorCommissionCap)],
	});
}

export function authorizeUpgrade(params: {
	config: IkaConfig;
	tx: Transaction;
	packageId: string;
}): {
	upgradeTicket: TransactionObjectArgument;
	upgradePackageApprover: TransactionObjectArgument;
} {
	const { config, tx, packageId } = params;
	const [upgradeTicket, upgradePackageApprover] = tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::authorize_upgrade`,
		arguments: [getSystemObjectRef(config, tx), tx.pure.id(packageId)],
	});
	return { upgradeTicket, upgradePackageApprover };
}

export function commitUpgradeSystem(params: {
	config: IkaConfig;
	tx: Transaction;
	upgradeReceipt: string;
	upgradePackageApprover: string;
}) {
	const { config, tx, upgradeReceipt, upgradePackageApprover } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::commit_upgrade`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.object(upgradeReceipt),
			tx.object(upgradePackageApprover),
		],
	});
}

export function finalizeUpgrade(params: {
	config: IkaConfig;
	tx: Transaction;
	upgradePackageApprover: string;
}) {
	const { config, tx, upgradePackageApprover } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::finalize_upgrade`,
		arguments: [getSystemObjectRef(config, tx), tx.object(upgradePackageApprover)],
	});
}

export function processCheckpointMessageByQuorumSystem(params: {
	config: IkaConfig;
	tx: Transaction;
	signature: Uint8Array;
	signersBitmap: Uint8Array;
	message: Uint8Array;
}) {
	const { config, tx, signature, signersBitmap, message } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::process_checkpoint_message_by_quorum`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(signature)),
			tx.pure(bcs.vector(bcs.u8()).serialize(signersBitmap)),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
		],
	});
}

export function addUpgradeCapByCap(params: {
	config: IkaConfig;
	tx: Transaction;
	upgradeCap: string;
	protocolCap: string;
}) {
	const { config, tx, upgradeCap, protocolCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::add_upgrade_cap_by_cap`,
		arguments: [getSystemObjectRef(config, tx), tx.object(upgradeCap), tx.object(protocolCap)],
	});
}

export function verifyProtocolCap(params: {
	config: IkaConfig;
	tx: Transaction;
	protocolCap: string;
}): TransactionObjectArgument {
	const { config, tx, protocolCap } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::verify_protocol_cap`,
		arguments: [getSystemObjectRef(config, tx), tx.object(protocolCap)],
	});
}

export function processCheckpointMessageByCapSystem(params: {
	config: IkaConfig;
	tx: Transaction;
	message: Uint8Array;
	protocolCap: string;
}) {
	const { config, tx, message, protocolCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::process_checkpoint_message_by_cap`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.pure(bcs.vector(bcs.u8()).serialize(message)),
			tx.object(protocolCap),
		],
	});
}

export function setApprovedUpgradeByCap(params: {
	config: IkaConfig;
	tx: Transaction;
	packageId: string;
	digest: Uint8Array | null;
	protocolCap: string;
}) {
	const { config, tx, packageId, digest, protocolCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::set_approved_upgrade_by_cap`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.pure.id(packageId),
			digest !== null
				? tx.pure(bcs.option(bcs.vector(bcs.u8())).serialize(digest))
				: tx.pure(bcs.option(bcs.vector(bcs.u8())).serialize(null)),
			tx.object(protocolCap),
		],
	});
}

export function setOrRemoveWitnessApprovingAdvanceEpochByCap(params: {
	config: IkaConfig;
	tx: Transaction;
	witnessType: string;
	remove: boolean;
	protocolCap: string;
}) {
	const { config, tx, witnessType, remove, protocolCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::set_or_remove_witness_approving_advance_epoch_by_cap`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.pure.string(witnessType),
			tx.pure.bool(remove),
			tx.object(protocolCap),
		],
	});
}

export function tryMigrateSystemByCap(params: {
	config: IkaConfig;
	tx: Transaction;
	protocolCap: string;
}) {
	const { config, tx, protocolCap } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::try_migrate_by_cap`,
		arguments: [getSystemObjectRef(config, tx), tx.object(protocolCap)],
	});
}

export function tryMigrateSystem(params: {
	config: IkaConfig;
	tx: Transaction;
}) {
	const { config, tx } = params;
	tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::try_migrate`,
		arguments: [getSystemObjectRef(config, tx)],
	});
}

export function calculateRewards(params: {
	config: IkaConfig;
	tx: Transaction;
	validatorId: string;
	stakedPrincipal: number;
	activationEpoch: number;
	withdrawEpoch: number;
}): TransactionObjectArgument {
	const { config, tx, validatorId, stakedPrincipal, activationEpoch, withdrawEpoch } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::calculate_rewards`,
		arguments: [
			getSystemObjectRef(config, tx),
			tx.pure.id(validatorId),
			tx.pure.u64(stakedPrincipal),
			tx.pure.u64(activationEpoch),
			tx.pure.u64(withdrawEpoch),
		],
	});
}

export function canWithdrawStakedIkaEarly(params: {
	config: IkaConfig;
	tx: Transaction;
	stakedIka: string;
}): TransactionObjectArgument {
	const { config, tx, stakedIka } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::can_withdraw_staked_ika_early`,
		arguments: [getSystemObjectRef(config, tx), tx.object(stakedIka)],
	});
}

export function systemVersion(params: {
	config: IkaConfig;
	tx: Transaction;
}): TransactionObjectArgument {
	const { config, tx } = params;
	return tx.moveCall({
		target: `${config.packages.ikaSystemPackage}::system::version`,
		arguments: [getSystemObjectRef(config, tx)],
	});
}
