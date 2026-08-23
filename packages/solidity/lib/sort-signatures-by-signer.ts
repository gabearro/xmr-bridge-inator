import { concatHex, recoverAddress } from 'viem'
import type { Hex } from 'viem'

export async function sortSignaturesBySigner(hash: Hex, signatures: readonly Hex[]): Promise<Hex[]> {
	if (signatures.length <= 1) {
		return signatures.slice()
	}

	async function withSigner(signature: Hex) {
		const signer = await recoverAddress({ hash: hash, signature: signature })
		return { signature: signature, signer: BigInt(signer) }
	}

	function compare(left: { signer: bigint }, right: { signer: bigint }) {
		if (left.signer < right.signer) {
			return -1
		}
		if (left.signer > right.signer) {
			return 1
		}
		return 0
	}

	function signatureOf(entry: { signature: Hex }) {
		return entry.signature
	}

	const withSigners = await Promise.all(signatures.map(withSigner))
	withSigners.sort(compare)
	return withSigners.map(signatureOf)
}

export async function encodeSortedSignatures(hash: Hex, signatures: readonly Hex[]): Promise<Hex> {
	return concatHex(await sortSignaturesBySigner(hash, signatures))
}
