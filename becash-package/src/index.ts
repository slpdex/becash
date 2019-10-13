import { bufferToHex, hexToBuffer } from './hex'

declare type becash_wasm = typeof import('becash-wasm')
declare type bitcoin = typeof import('bitcoin-ts')
declare type Secp256k1 = import('bitcoin-ts').Secp256k1

const INITIAL_NONCE = -0x7fff_ffff
const SATS_PER_BCH = 100_000_000
const DUST_LIMIT = 0x222
const ADDRESS_PREFIX = "bitcoincash"

let _global_bitcoin: bitcoin | undefined = undefined
let _global_curve: Secp256k1 | undefined = undefined
let _global_becash_wasm: becash_wasm | undefined = undefined

async function _becash_wasm(): Promise<becash_wasm> {
    if (_global_becash_wasm === undefined)
        _global_becash_wasm = await import('becash-wasm')
    return _global_becash_wasm
}

async function _bitcoin(): Promise<bitcoin> {
    if (_global_bitcoin === undefined)
        _global_bitcoin = await import('bitcoin-ts')
    return _global_bitcoin
}

async function _curve(): Promise<Secp256k1> {
    if (_global_curve === undefined)
        _global_curve = await (await _bitcoin()).instantiateSecp256k1()
    return _global_curve
}

export class Wallet {
    private _pubkey: Uint8Array

    private constructor(
        private _curve: Secp256k1,
        private _becash_wasm: becash_wasm,
        private _secret: Uint8Array,
        private _nonce: number,
    ) {
        this._pubkey = this._curve.derivePublicKeyCompressed(this._secret)
    }

    static async loadFromStorage(): Promise<Wallet> {
        const secretHex = localStorage.getItem('be.cash/secret')
        const nonceStr = localStorage.getItem('be.cash/nonce')
        if (secretHex === null || nonceStr === null)
            throw "No secret/nonce in localStorage"
        const secret = hexToBuffer(secretHex)
        const nonce = parseInt(nonceStr)
        return new Wallet(await _curve(), await _becash_wasm(), secret, nonce)
    }

    static async createNew(secret: Uint8Array): Promise<Wallet> {
        return new Wallet(await _curve(), await _becash_wasm(), secret, INITIAL_NONCE)
    }

    static async generateNew(): Promise<Wallet> {
        const secret = new Uint8Array(32);
        window.crypto.getRandomValues(secret)
        return new Wallet(await _curve(), await _becash_wasm(), secret, INITIAL_NONCE)
    }

    static async generateOrLoad(): Promise<Wallet> {
        if (localStorage.getItem('be.cash/secret') === null) {
            const wallet = await Wallet.generateNew()
            wallet.saveToStorage()
            return wallet
        } else {
            return await Wallet.loadFromStorage()
        }
    }

    saveToStorage(): void {
        localStorage.setItem('be.cash/secret', bufferToHex(this._secret))
        localStorage.setItem('be.cash/nonce', this._nonce.toFixed())
    }

    nonce(): number {
        return this._nonce
    }

    offlineGenesisAddress(): string {
        return this._becash_wasm.current_address(this._pubkey, INITIAL_NONCE, DUST_LIMIT)
    }

    address(): string {
        return this._becash_wasm.pub_key_cash_addr(ADDRESS_PREFIX, this._pubkey)
    }

    payOffline(address: string, amountBCH: number): PaymentResponse {
        const amount = amountBCH * SATS_PER_BCH
        this._nonce += 1
        const messageHash = this._becash_wasm.owner_message_hash(address, amount, this._nonce)
        const sig = this._curve.signMessageHashSchnorr(this._secret, messageHash)
        return new PaymentResponse(address, this._pubkey, sig, this._nonce)
    }

    payOfflineJson(paymentRequestJson: string): PaymentResponse {
        const paymentRequestObj: {address: string, amountBCH: number} = JSON.parse(paymentRequestJson)
        return this.payOffline(paymentRequestObj.address, paymentRequestObj.amountBCH)
    }

    async refillOnline(ownerPk: Uint8Array, nonce: number, refillAmountBCH: number, feePerKb: number): Promise<string> {
        const utxo = await Endpoint.findNonceUtxo(ownerPk, nonce + 1)
        const fundingUtxos = new this._becash_wasm.Utxos()
        const fundingAddress = this.address()
        const paymentAmount = -refillAmountBCH * SATS_PER_BCH
        for (const fundingUtxo of await Endpoint.fetchUtxos(fundingAddress)) {
            this._becash_wasm.add_utxo(fundingUtxos, fundingUtxo.tx_hash, fundingUtxo.vout, fundingUtxo.value)
        }
        const messageHash = this._becash_wasm.refill_nonce_utxo_message_hash(
            ownerPk,
            utxo.tx_hash,
            utxo.vout,
            utxo.value,
            nonce,
            paymentAmount,
            fundingUtxos,
            fundingAddress,
            feePerKb,
            DUST_LIMIT,
        )
        const sig = this._curve.signMessageHashSchnorr(this._secret, messageHash)
        const rawTx = this._becash_wasm.refill_nonce_utxo_sign(
            ownerPk,
            utxo.tx_hash,
            utxo.vout,
            utxo.value,
            nonce,
            paymentAmount,
            fundingUtxos,
            fundingAddress,
            feePerKb,
            DUST_LIMIT,
            this._pubkey,
            sig,
        )
        const rawTxHex = bufferToHex(rawTx)
        console.log(rawTxHex)
        const txHash = await Endpoint.broadcastTx(rawTxHex)
        console.log('tx hash', txHash)
        return txHash
    }

    async sweepToOnline(address: string, feePerKb: number): Promise<string> {
        const utxo = await Endpoint.findNonceUtxo(this._pubkey, this._nonce + 1)
        const messageHash = this._becash_wasm.spend_p2pk_utxo_message_hash(
            this._pubkey,
            utxo.tx_hash,
            utxo.vout,
            utxo.value,
            this._nonce,
            address,
            feePerKb,
            DUST_LIMIT,
        )
        const sig = this._curve.signMessageHashSchnorr(this._secret, messageHash)
        const rawTx = this._becash_wasm.spend_p2pk_utxo_sign(
            this._pubkey,
            sig,
            utxo.tx_hash,
            utxo.vout,
            utxo.value,
            this._nonce,
            address,
            feePerKb,
            DUST_LIMIT,
        )
        const rawTxHex = bufferToHex(rawTx)
        console.log(rawTxHex)
        const txHash = await Endpoint.broadcastTx(rawTxHex)
        console.log('tx hash', txHash)
        return txHash
    }
}

interface EndpointUtxoResult {
    "data": {
        [key: string]: {    
            "utxo": {
                "transaction_hash": string
                "index": number
                "value": number
            }[]
        }
    }
}

interface UtxoEntry {
    tx_hash: string
    vout: number
    value: number
}

interface EndpointTxResult {
    "data": {
        [key: string]: { 
            "raw_transaction": string
        }
    }
}

class Endpoint {
    static async fetchUtxos(address: string): Promise<UtxoEntry[]> {
        const endpoint = 'https://api.blockchair.com/bitcoin-cash/dashboards/address/'
        const result: EndpointUtxoResult = await (await fetch(endpoint + address)).json()
        return result.data[address].utxo.map(utxo => ({
            tx_hash: utxo.transaction_hash,
            vout: utxo.index,
            value: utxo.value,
        } as UtxoEntry))
    }

    static async fetchTxHex(tx_hash: string): Promise<string> {
        const endpoint = 'https://api.blockchair.com/bitcoin-cash/raw/transaction/'
        const result: EndpointTxResult = await (await fetch(endpoint + tx_hash)).json()
        return result.data[tx_hash].raw_transaction
    }

    static async broadcastTx(rawTxHex: string): Promise<string> {
        const endpoint = 'https://api.blockchair.com/bitcoin-cash/push/transaction'
        const result = await (await fetch(endpoint, {
            credentials: "omit",
            headers: {
                "Content-Type": "application/json;charset=utf-8"
            },
            body: `{"data":"${rawTxHex}"}`,
            method: "POST",
        })).text()

        return result
    }

    static async findNonceUtxo(ownerPk: Uint8Array, startNonce: number): Promise<UtxoEntry> {
        const becash_wasm = await _becash_wasm()
        const maxTries = 10
        for (let i = 1; i <= maxTries; ++i) {
            const address = becash_wasm.current_address(ownerPk, startNonce - i, DUST_LIMIT)
            const utxos = await Endpoint.fetchUtxos(address)
            if (utxos.length > 0)
                return utxos[0]
        }
        throw "Tried 10 nonces back, but found no UTXO"
    }
}

export class PaymentRequest {
    constructor(
        private _address: String,
        private _secret: Uint8Array,
        private _pubkey: Uint8Array,
        private _merchant_address: string,
        private _amountBCH: number,
    ) {}

    paymentRequestJson(): string {
        return JSON.stringify({
            address: this._address,
            amountBCH: this._amountBCH,
        })
    }

    encode(): string {
        return JSON.stringify({
            address: this._address,
            secret: bufferToHex(this._secret),
            pubkey: bufferToHex(this._pubkey),
            merchant_address: this._merchant_address,
            amountBCH: this._amountBCH,
        })
    }

    static decode(json: string): PaymentRequest {
        const obj = JSON.parse(json)
        return new PaymentRequest(
            obj.address,
            hexToBuffer(obj.secret),
            hexToBuffer(obj.pubkey),
            obj.merchant_address,
            obj.amountBCH,
        )
    }

    async redeemResponse(response: PaymentResponse, fee_per_kb: number): Promise<string> {
        const curve = await _curve()
        const becash_wasm = await _becash_wasm()
        const utxo = await Endpoint.findNonceUtxo(response.customer_pk, response.payment_nonce)
        const raw_tx_hex = await Endpoint.fetchTxHex(utxo.tx_hash)
        let nonce = becash_wasm.find_nonce_in_tx(raw_tx_hex)
        if (nonce === undefined) {
            nonce = INITIAL_NONCE
        }
        const messageHash = becash_wasm.redeem_nonce_utxo_message_hash(
            response.customer_pk,
            utxo.tx_hash,
            utxo.vout,
            utxo.value,
            nonce,
            this._amountBCH * SATS_PER_BCH,
            response.payment_nonce,
            response.payment_sig,
            this._merchant_address,
            fee_per_kb,
            DUST_LIMIT,
        )
        const sig = curve.signMessageHashSchnorr(this._secret, messageHash)
        const rawTx = becash_wasm.redeem_nonce_utxo_sign(
            response.customer_pk,
            utxo.tx_hash,
            utxo.vout,
            utxo.value,
            nonce,
            this._amountBCH * SATS_PER_BCH,
            response.payment_nonce,
            response.payment_sig,
            this._merchant_address,
            fee_per_kb,
            DUST_LIMIT,
            this._pubkey,
            sig,
        )
        const rawTxHex = bufferToHex(rawTx)
        console.log(rawTxHex)
        const txHash = await Endpoint.broadcastTx(rawTxHex)
        console.log('tx hash', txHash)
        return txHash
    }
}

export class PaymentResponse {
    constructor(
        public address: string,
        public customer_pk: Uint8Array,
        public payment_sig: Uint8Array,
        public payment_nonce: number,
    ) {}

    encode(): string {
        return JSON.stringify({
            address: this.address,
            customerPk: bufferToHex(this.customer_pk),
            paymentSig: bufferToHex(this.payment_sig),
            paymentNonce: this.payment_nonce,
        })
    }

    static decode(paymentResponseJson: string): PaymentResponse {
        const obj = JSON.parse(paymentResponseJson)
        return new PaymentResponse(
            obj.address,
            hexToBuffer(obj.customerPk),
            hexToBuffer(obj.paymentSig),
            obj.paymentNonce,
        )
    }
}

export class Merchant {
    private constructor(
        private _curve: Secp256k1,
        private _becash_wasm: becash_wasm,
        private _merchant_address: string,
    ) {
    }

    static async fromMerchantAddress(merchant_address: string): Promise<Merchant> {
        return new Merchant(await _curve(), await _becash_wasm(), merchant_address)
    }

    makePaymentRequest(amountBCH: number): PaymentRequest {
        const secret = new Uint8Array(32)
        window.crypto.getRandomValues(secret)
        const pubkey = this._curve.derivePublicKeyCompressed(secret)
        const address = this._becash_wasm.pub_key_cash_addr(ADDRESS_PREFIX, pubkey)
        return new PaymentRequest(address, secret, pubkey, this._merchant_address, amountBCH)
    }
}
