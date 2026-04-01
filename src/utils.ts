// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { ClientWithCoreApi, SuiClientTypes } from '@mysten/sui/client';

import { InvalidObjectError } from './errors.ts';

/**
 * Extract BCS (Binary Canonical Serialization) bytes from a Sui object response.
 * This function validates the response and extracts the serialized object data.
 */
export function objResToBcs(
	resp:
		| SuiClientTypes.Object<{
				content: true;
		  }>
		| SuiClientTypes.GetObjectResponse<{
				content: true;
		  }>
		| Error,
): Uint8Array<ArrayBuffer> {
	if (resp instanceof Error) {
		throw resp;
	}

	if ('object' in resp) {
		resp = resp.object;
	}

	if (!resp.content) {
		throw new InvalidObjectError(`Response bcs missing: ${JSON.stringify(resp.type, null, 2)}`);
	}

	return new Uint8Array(resp.content);
}

export async function fetchAllDynamicFields(
	suiClient: ClientWithCoreApi,
	parentId: string,
): Promise<SuiClientTypes.DynamicFieldEntry[]> {
	const allFields: SuiClientTypes.DynamicFieldEntry[] = [];
	let cursor: string | null = null;

	while (true) {
		const response = await suiClient.core.listDynamicFields({
			parentId,
			cursor,
		});

		allFields.push(...response.dynamicFields);

		if (response.cursor === cursor) {
			break;
		}

		cursor = response.cursor;
	}

	return allFields;
}

/**
 * Encode a string to ASCII bytes.
 */
export function encodeToASCII(input: string): Uint8Array {
	const asciiValues: number[] = [];
	for (let i = 0; i < input.length; i++) {
		asciiValues.push(input.charCodeAt(i));
	}
	return Uint8Array.from(asciiValues);
}

/**
 * Convert a 64-bit unsigned integer to bytes in big-endian format.
 */
export function u64ToBytesBigEndian(value: number | bigint): Uint8Array {
	const bigIntValue = BigInt(value);
	const buffer = new ArrayBuffer(8);
	const view = new DataView(buffer);
	view.setBigUint64(0, bigIntValue, false);
	return new Uint8Array(buffer);
}

/**
 * Converts a string to a Uint8Array by encoding each character as its ASCII value.
 */
export function stringToUint8Array(input: string): Uint8Array {
	const asciiValues: number[] = [];
	for (let i = 0; i < input.length; i++) {
		asciiValues.push(input.charCodeAt(i));
	}
	return Uint8Array.from(asciiValues);
}
