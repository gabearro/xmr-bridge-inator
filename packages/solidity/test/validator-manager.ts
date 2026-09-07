import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { network } from 'hardhat'
import { keccak256, stringToHex } from 'viem'

import { ValidatorManagerClient } from '../lib/validator-manager-client.js'
import { sortSignaturesBySigner } from '../lib/sort-signatures-by-signer.js'

function nonce(label: string) {
	return keccak256(stringToHex(label))
}

describe('ValidatorManager', async function() {
	const { viem, networkHelpers } = await network.create()
	const publicClient = await viem.getPublicClient()
	const chainId = await publicClient.getChainId()
	type TestWallet = Awaited<ReturnType<typeof viem.getWalletClients>>[number]

	async function deployThreeValidators() {
		const [ a, b, c, d ] = await viem.getWalletClients()
		const contract = await viem.deployContract('ValidatorManager', [
			[ a.account.address, b.account.address, c.account.address ],
			2
		])
		return { client: new ValidatorManagerClient(contract), a: a, b: b, c: c, d: d }
	}

	it('deploys with three validators and quorum 2', async function() {
		const { client, a, b, c, d } = await networkHelpers.loadFixture(deployThreeValidators)

		assert.equal(await client.contract.read.getValidatorCount(), 3)
		assert.equal(await client.contract.read.getValidatorQuorum(), 2)
		assert.equal(await client.contract.read.isValidator([ a.account.address ]), true)
		assert.equal(await client.contract.read.isValidator([ b.account.address ]), true)
		assert.equal(await client.contract.read.isValidator([ c.account.address ]), true)
		assert.equal(await client.contract.read.isValidator([ d.account.address ]), false)
	})

	it('exposes an EIP-712 domain that matches viem typed data', async function() {
		const { client } = await networkHelpers.loadFixture(deployThreeValidators)
		const [ , name, version, domainChainId, verifyingContract ] = await client.contract.read.eip712Domain()

		assert.equal(name, 'ValidatorManager')
		assert.equal(version, '1')
		assert.equal(domainChainId, BigInt(chainId))
		assert.equal(verifyingContract.toLowerCase(), client.contract.address.toLowerCase())
	})

	it('sorts shuffled signatures into increasing signer order', async function() {
		const { client, a, b, c, d } = await networkHelpers.loadFixture(deployThreeValidators)
		const now = await networkHelpers.time.latest()
		const request = { validator: d.account.address, isValidator: true, expiry: BigInt(now) + 3600n, nonce: nonce('add-dave') }
		const hash = await client.hash('ChangeValidatorRequest', request)

		const [ sigA, sigB, sigC ] = await Promise.all([
			client.sign(a, 'ChangeValidatorRequest', request),
			client.sign(b, 'ChangeValidatorRequest', request),
			client.sign(c, 'ChangeValidatorRequest', request)
		])
		const sorted = await sortSignaturesBySigner(hash, [ sigC, sigA, sigB ])

		function byAddress(left: TestWallet, right: TestWallet) {
			if (BigInt(left.account.address) < BigInt(right.account.address)) {
				return -1
			}
			if (BigInt(left.account.address) > BigInt(right.account.address)) {
				return 1
			}
			return 0
		}

		function signExpected(wallet: TestWallet) {
			return client.sign(wallet, 'ChangeValidatorRequest', request)
		}

		const expected = await Promise.all([ a, b, c ].sort(byAddress).map(signExpected))
		assert.deepEqual(sorted, expected)
		assert.deepEqual(await sortSignaturesBySigner(hash, []), [])
		assert.deepEqual(await sortSignaturesBySigner(hash, [ sigA ]), [ sigA ])
	})

	it('adds a fourth validator with quorum signatures plus the subject signature', async function() {
		const { client, a, b, d } = await networkHelpers.loadFixture(deployThreeValidators)
		const now = await networkHelpers.time.latest()
		const request = { validator: d.account.address, isValidator: true, expiry: BigInt(now) + 3600n, nonce: nonce('add-dave') }
		const signatures = await client.packedSignatures('ChangeValidatorRequest', request, [ a, b ])
		const subjectSignature = await client.sign(d, 'ChangeValidatorRequest', request)

		await viem.assertions.emitWithArgs(
			client.contract.write.changeValidator([ request, signatures, subjectSignature ]),
			client.contract,
			'ValidatorAdded',
			[ d.account.address ]
		)
		assert.equal(await client.contract.read.isValidator([ d.account.address ]), true)
		assert.equal(await client.contract.read.getValidatorCount(), 4)
	})

	it('removes a validator without the departing validator\'s signature', async function() {
		const { client, a, b, c } = await networkHelpers.loadFixture(deployThreeValidators)
		const now = await networkHelpers.time.latest()
		const quorumRequest = { quorum: 1, expiry: BigInt(now) + 3600n, nonce: nonce('quorum-1') }
		await client.contract.write.changeValidatorQuorum([
			quorumRequest,
			await client.packedSignatures('ChangeValidatorQuorumRequest', quorumRequest, [ a, b ])
		])

		const request = { validator: c.account.address, isValidator: false, expiry: BigInt(now) + 3600n, nonce: nonce('remove-c') }
		const signatures = await client.packedSignatures('ChangeValidatorRequest', request, [ a, b ])

		await viem.assertions.emitWithArgs(
			client.contract.write.changeValidator([ request, signatures, '0x' ]),
			client.contract,
			'ValidatorRemoved',
			[ c.account.address ]
		)
		assert.equal(await client.contract.read.isValidator([ c.account.address ]), false)
		assert.equal(await client.contract.read.getValidatorCount(), 2)
	})

	it('lowers quorum then removes down to two validators', async function() {
		const { client, a, b, c } = await networkHelpers.loadFixture(deployThreeValidators)
		const now = await networkHelpers.time.latest()
		const quorumRequest = { quorum: 1, expiry: BigInt(now) + 3600n, nonce: nonce('quorum-1') }

		await viem.assertions.emitWithArgs(
			client.contract.write.changeValidatorQuorum([
				quorumRequest,
				await client.packedSignatures('ChangeValidatorQuorumRequest', quorumRequest, [ a, b ])
			]),
			client.contract,
			'ValidatorQuorumSet',
			[ 1 ]
		)

		const removeRequest = { validator: c.account.address, isValidator: false, expiry: BigInt(now) + 3600n, nonce: nonce('remove-c') }
		await client.contract.write.changeValidator([
			removeRequest,
			await client.packedSignatures('ChangeValidatorRequest', removeRequest, [ a, b ]),
			'0x'
		])

		assert.equal(await client.contract.read.getValidatorCount(), 2)
		assert.equal(await client.contract.read.getValidatorQuorum(), 1)
	})

	it('reverts when the request is expired', async function() {
		const { client, a, b, d } = await networkHelpers.loadFixture(deployThreeValidators)
		const now = await networkHelpers.time.latest()
		const expiry = BigInt(now) + 30n
		const request = { validator: d.account.address, isValidator: true, expiry: expiry, nonce: nonce('expired') }
		const signatures = await client.packedSignatures('ChangeValidatorRequest', request, [ a, b ])
		const subjectSignature = await client.sign(d, 'ChangeValidatorRequest', request)

		await networkHelpers.time.setNextBlockTimestamp(Number(expiry) + 1)

		await viem.assertions.revertWithCustomErrorWithArgs(
			client.contract.write.changeValidator([ request, signatures, subjectSignature ]),
			client.contract,
			'RequestExpired',
			[ expiry, expiry + 1n ]
		)
	})

	it('reverts when a signer reuses a nonce', async function() {
		const { client, a, b, d } = await networkHelpers.loadFixture(deployThreeValidators)
		const now = await networkHelpers.time.latest()
		const request = { validator: d.account.address, isValidator: true, expiry: BigInt(now) + 3600n, nonce: nonce('reuse') }
		const signatures = await client.packedSignatures('ChangeValidatorRequest', request, [ a, b ])
		const subjectSignature = await client.sign(d, 'ChangeValidatorRequest', request)
		await client.contract.write.changeValidator([ request, signatures, subjectSignature ])

		const firstSigner = BigInt(a.account.address) < BigInt(b.account.address) ? a.account.address : b.account.address
		await viem.assertions.revertWithCustomErrorWithArgs(
			client.contract.write.changeValidator([ request, signatures, subjectSignature ]),
			client.contract,
			'SignatureInvalidated',
			[ firstSigner, request.nonce ]
		)
	})

	it('reverts when setting a unanimous quorum', async function() {
		const { client, a, b } = await networkHelpers.loadFixture(deployThreeValidators)
		const now = await networkHelpers.time.latest()
		const request = { quorum: 3, expiry: BigInt(now) + 3600n, nonce: nonce('unanimous') }

		await viem.assertions.revertWithCustomError(
			client.contract.write.changeValidatorQuorum([
				request,
				await client.packedSignatures('ChangeValidatorQuorumRequest', request, [ a, b ])
			]),
			client.contract,
			'InvalidValidatorQuorum'
		)
	})

	it('lets a validator invalidate their signature on the current nonce', async function() {
		const { client, a, b, c, d } = await networkHelpers.loadFixture(deployThreeValidators)
		const now = await networkHelpers.time.latest()
		const request = { validator: d.account.address, isValidator: true, expiry: BigInt(now) + 3600n, nonce: nonce('add-dave') }
		const revokedSignatures = await client.packedSignatures('ChangeValidatorRequest', request, [ a, b ])
		const remainingSignatures = await client.packedSignatures('ChangeValidatorRequest', request, [ b, c ])
		const subjectSignature = await client.sign(d, 'ChangeValidatorRequest', request)

		await viem.assertions.emitWithArgs(
			client.contract.write.invalidateNonce([ request.nonce ], { account: a.account }),
			client.contract,
			'ValidatorNonceInvalidated',
			[ a.account.address, request.nonce ]
		)
		assert.equal(await client.contract.read.usedNonces([ a.account.address, request.nonce ]), true)
		assert.equal(await client.contract.read.usedNonces([ a.account.address, nonce('other') ]), false)

		await viem.assertions.revertWithCustomErrorWithArgs(
			client.contract.write.changeValidator([ request, revokedSignatures, subjectSignature ]),
			client.contract,
			'SignatureInvalidated',
			[ a.account.address, request.nonce ]
		)

		await client.contract.write.changeValidator([ request, remainingSignatures, subjectSignature ])
		assert.equal(await client.contract.read.isValidator([ d.account.address ]), true)
	})

	it('reverts when the new validator does not sign the add', async function() {
		const { client, a, b, d } = await networkHelpers.loadFixture(deployThreeValidators)
		const now = await networkHelpers.time.latest()
		const request = { validator: d.account.address, isValidator: true, expiry: BigInt(now) + 3600n, nonce: nonce('add-dave') }

		await viem.assertions.revertWithCustomError(
			client.contract.write.changeValidator([
				request,
				await client.packedSignatures('ChangeValidatorRequest', request, [ a, b ]),
				'0x'
			]),
			client.contract,
			'InvalidSignatureLength'
		)
	})
})
