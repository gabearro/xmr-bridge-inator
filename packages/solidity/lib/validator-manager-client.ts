import { hashTypedData } from 'viem'
import type { Account, Hex, TypedData, WalletClient } from 'viem'

import { encodeSortedSignatures } from './sort-signatures-by-signer.js'

type AbiComponent = {
	name: string
	type: string
}

type AbiItem = {
	type?: string
	name?: string
	inputs?: readonly {
		type?: string
		internalType?: string
		components?: readonly AbiComponent[]
	}[]
}

type FirstWriteArg<C, M extends string> = C extends { write: infer W }
	? M extends keyof W
		? W[M] extends (...args: infer Params) => unknown
			? Params[0] extends readonly [infer Request, ...unknown[]]
				? Request
				: never
			: never
		: never
	: never

type SignerWallet = {
	account: Account
	signTypedData: WalletClient['signTypedData']
}

function eip712TypesFromAbi(abi: readonly unknown[], primaryType: string) {
	let index = 0
	while (index < abi.length) {
		const item = abi[index] as AbiItem
		const input = item.inputs === undefined ? undefined : item.inputs[0]
		if (item.type === 'function' && input !== undefined && input.type === 'tuple' && input.components !== undefined) {
			const internalType = input.internalType === undefined ? '' : input.internalType
			if (internalType === primaryType || internalType.endsWith('.' + primaryType)) {
				function toField(component: AbiComponent) {
					return { name: component.name, type: component.type }
				}
				return { [primaryType]: input.components.map(toField) }
			}
		}
		index = index + 1
	}
	throw new Error('Unknown EIP-712 type: ' + primaryType)
}

export class ValidatorManagerClient<
	TContract extends {
		address: Hex
		abi: readonly unknown[]
		read: { eip712Domain: () => Promise<readonly unknown[]> }
	}
> {
	readonly contract: TContract

	constructor(contract: TContract) {
		this.contract = contract
	}

	async domain() {
		const eip712Domain = await this.contract.read.eip712Domain()
		return {
			name: eip712Domain[1] as string,
			version: eip712Domain[2] as string,
			chainId: eip712Domain[3] as bigint,
			verifyingContract: eip712Domain[4] as Hex
		}
	}

	async typedData(primaryType: string, message: Record<string, unknown>) {
		return {
			domain: await this.domain(),
			types: eip712TypesFromAbi(this.contract.abi, primaryType) as unknown as TypedData,
			primaryType: primaryType,
			message: message
		}
	}

	async hash(primaryType: string, message: Record<string, unknown>) {
		return hashTypedData(await this.typedData(primaryType, message))
	}

	async sign(
		wallet: SignerWallet,
		primaryType: 'ChangeValidatorRequest',
		message: FirstWriteArg<TContract, 'changeValidator'>
	): Promise<Hex>
	async sign(
		wallet: SignerWallet,
		primaryType: 'ChangeValidatorQuorumRequest',
		message: FirstWriteArg<TContract, 'changeValidatorQuorum'>
	): Promise<Hex>
	async sign(wallet: SignerWallet, primaryType: string, message: Record<string, unknown>): Promise<Hex> {
		const typedData = await this.typedData(primaryType, message)
		return wallet.signTypedData({
			account: wallet.account,
			domain: typedData.domain,
			types: typedData.types,
			primaryType: typedData.primaryType,
			message: typedData.message
		})
	}

	async packedSignatures(
		primaryType: 'ChangeValidatorRequest',
		message: FirstWriteArg<TContract, 'changeValidator'>,
		wallets: SignerWallet[]
	): Promise<Hex>
	async packedSignatures(
		primaryType: 'ChangeValidatorQuorumRequest',
		message: FirstWriteArg<TContract, 'changeValidatorQuorum'>,
		wallets: SignerWallet[]
	): Promise<Hex>
	async packedSignatures(primaryType: string, message: Record<string, unknown>, wallets: SignerWallet[]): Promise<Hex> {
		const client = this
		async function signOne(wallet: SignerWallet) {
			return client.sign(wallet, primaryType as 'ChangeValidatorRequest', message as FirstWriteArg<TContract, 'changeValidator'>)
		}
		const signatures = await Promise.all(wallets.map(signOne))
		return encodeSortedSignatures(await client.hash(primaryType, message), signatures)
	}
}
