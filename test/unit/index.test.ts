// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import {
	createClassGroupsKeypair,
	encodeToASCII,
	getNetworkConfig,
	IkaClient,
	IkaClientError,
	ika,
	UserShareEncryptionKeys,
	requestDWalletDKG,
} from '../../src/index.ts';

describe('Index Exports', () => {
	it('should export IkaClient', () => {
		expect(IkaClient).toBeDefined();
		expect(typeof IkaClient).toBe('function');
	});

	it('should export ika', () => {
		expect(ika).toBeDefined();
		expect(typeof ika).toBe('function');
	});

	it('should export error classes', () => {
		expect(IkaClientError).toBeDefined();
		expect(typeof IkaClientError).toBe('function');
	});

	it('should export UserShareEncryptionKeys', () => {
		expect(UserShareEncryptionKeys).toBeDefined();
		expect(typeof UserShareEncryptionKeys).toBe('function');
	});

	it('should export cryptography functions', () => {
		expect(createClassGroupsKeypair).toBeDefined();
		expect(typeof createClassGroupsKeypair).toBe('function');
	});

	it('should export utility functions', () => {
		expect(encodeToASCII).toBeDefined();
		expect(typeof encodeToASCII).toBe('function');
	});

	it('should export network config functions', () => {
		expect(getNetworkConfig).toBeDefined();
		expect(typeof getNetworkConfig).toBe('function');
	});

	it('should export transaction functions', () => {
		expect(requestDWalletDKG).toBeDefined();
		expect(typeof requestDWalletDKG).toBe('function');
	});
});
