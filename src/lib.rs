pub mod contract;
mod utils;

use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn init() {
    utils::set_panic_hook();
}

fn _tx_hex_to_hash(tx_hash_hex: &str) -> Result<[u8; 32], JsValue> {
    let mut tx_hash = [0; 32];
    tx_hash.copy_from_slice(
        &cashcontracts::tx_hex_to_hash(tx_hash_hex)
            .ok_or_else(|| format!("Hex error: {}", tx_hash_hex))?,
    );
    Ok(tx_hash)
}

#[allow(clippy::too_many_arguments)]
fn _spend_nonce_utxo(
    owner_pk: Vec<u8>,
    utxo_tx_hash_hex: String,
    utxo_vout: u32,
    utxo_value: u32,
    utxo_nonce: i32,
    payment_amount: i32,
    new_nonce: Option<i32>,
    owner_sig: Option<Vec<u8>>,
    dust_limit: i32,
) -> Result<cashcontracts::UnsignedTx, JsValue> {
    Ok(contract::spend_nonce_utxo(
        owner_pk,
        cashcontracts::TxOutpoint {
            tx_hash: _tx_hex_to_hash(&utxo_tx_hash_hex)?,
            vout: utxo_vout,
        },
        utxo_value as u64,
        utxo_nonce,
        if payment_amount >= 0 {
            contract::SendData::Redeem {
                payment_amount,
                new_nonce: new_nonce.expect("must provide new_nonce to redeem"),
                owner_sig: owner_sig.expect("must provide owner_sig to redeem"),
            }
        } else {
            contract::SendData::Refill { payment_amount }
        },
        dust_limit,
    ))
}

fn _add_leftover_outputs(
    unsigned_tx: &mut cashcontracts::UnsignedTx,
    recipient_address: String,
    fee_per_kb: u32,
    dust_limit: i32,
) -> Result<(), JsValue> {
    unsigned_tx.add_leftover_output(
        cashcontracts::Address::from_cash_addr(recipient_address)
            .map_err(|err| format!("{:?}", err))?,
        fee_per_kb as u64,
        dust_limit as u64,
    ).map_err(|amount| format!("Insufficient funds: {} missing", amount))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn redeem_nonce_utxo_message_hash(
    owner_pk: Vec<u8>,
    utxo_tx_hash_hex: String,
    utxo_vout: u32,
    utxo_value: u32,
    utxo_nonce: i32,
    payment_amount: i32,
    new_nonce: i32,
    owner_sig: Vec<u8>,
    recipient_address: String,
    fee_per_kb: u32,
    dust_limit: i32,
) -> Result<Vec<u8>, JsValue> {
    let mut unsigned_tx = _spend_nonce_utxo(
        owner_pk,
        utxo_tx_hash_hex,
        utxo_vout,
        utxo_value,
        utxo_nonce,
        payment_amount,
        Some(new_nonce),
        Some(owner_sig),
        dust_limit,
    )?;
    _add_leftover_outputs(&mut unsigned_tx, recipient_address, fee_per_kb, dust_limit)?;
    let preimages = unsigned_tx.pre_images(0x41);
    let mut preimage_ser = Vec::new();
    preimages[0].write_to_stream(&mut preimage_ser).unwrap();
    Ok(cashcontracts::double_sha256(&preimage_ser).to_vec())
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn redeem_nonce_utxo_sign(
    owner_pk: Vec<u8>,
    utxo_tx_hash_hex: String,
    utxo_vout: u32,
    utxo_value: u32,
    utxo_nonce: i32,
    payment_amount: i32,
    new_nonce: i32,
    owner_sig: Vec<u8>,
    recipient_address: String,
    fee_per_kb: u32,
    dust_limit: i32,
    covenant_pk: Vec<u8>,
    covenant_sig: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let mut unsigned_tx = _spend_nonce_utxo(
        owner_pk,
        utxo_tx_hash_hex,
        utxo_vout,
        utxo_value,
        utxo_nonce,
        payment_amount,
        Some(new_nonce),
        Some(owner_sig),
        dust_limit,
    )?;
    _add_leftover_outputs(&mut unsigned_tx, recipient_address, fee_per_kb, dust_limit)?;
    let tx = unsigned_tx.sign(vec![covenant_sig], vec![covenant_pk]);
    let mut tx_ser = Vec::new();
    tx.write_to_stream(&mut tx_ser).unwrap();
    Ok(tx_ser)
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn spend_p2pk_utxo_message_hash(
    owner_pk: Vec<u8>,
    utxo_tx_hash_hex: &str,
    utxo_vout: u32,
    utxo_value: u32,
    utxo_nonce: i32,
    recipient_address: String,
    fee_per_kb: u32,
    dust_limit: i32,
) -> Result<Vec<u8>, JsValue> {
    let mut unsigned_tx = contract::spend_nonce_utxo_p2pk(
        owner_pk,
        cashcontracts::TxOutpoint {
            tx_hash: _tx_hex_to_hash(utxo_tx_hash_hex)?,
            vout: utxo_vout,
        },
        utxo_value as u64,
        utxo_nonce,
        dust_limit,
    );
    _add_leftover_outputs(&mut unsigned_tx, recipient_address, fee_per_kb, dust_limit)?;
    let preimages = unsigned_tx.pre_images(0x41);
    let mut preimage_ser = Vec::new();
    preimages[0].write_to_stream(&mut preimage_ser).unwrap();
    Ok(cashcontracts::double_sha256(&preimage_ser).to_vec())
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn spend_p2pk_utxo_sign(
    owner_pk: Vec<u8>,
    owner_sig: Vec<u8>,
    utxo_tx_hash_hex: &str,
    utxo_vout: u32,
    utxo_value: u32,
    utxo_nonce: i32,
    recipient_address: String,
    fee_per_kb: u32,
    dust_limit: i32,
) -> Result<Vec<u8>, JsValue> {
    let mut unsigned_tx = contract::spend_nonce_utxo_p2pk(
        owner_pk.clone(),
        cashcontracts::TxOutpoint {
            tx_hash: _tx_hex_to_hash(utxo_tx_hash_hex)?,
            vout: utxo_vout,
        },
        utxo_value as u64,
        utxo_nonce,
        dust_limit,
    );
    _add_leftover_outputs(&mut unsigned_tx, recipient_address, fee_per_kb, dust_limit)?;
    let tx = unsigned_tx.sign(vec![owner_sig], vec![owner_pk]);
    let mut tx_ser = Vec::new();
    tx.write_to_stream(&mut tx_ser).unwrap();
    Ok(tx_ser)
}

pub struct Utxo {
    pub tx_outpoint: cashcontracts::TxOutpoint,
    pub value: u64,
}

#[wasm_bindgen]
#[derive(Default)]
pub struct Utxos {
    utxos: Vec<Utxo>,
}

impl Utxos {
    pub fn add_utxos_to_tx(&self, unsigned_tx: &mut cashcontracts::UnsignedTx, address: String) -> Result<(), JsValue> {
        let address = cashcontracts::Address::from_cash_addr(address)
            .map_err(|err| format!("{:?}", err))?;
        for utxo in &self.utxos {
            unsigned_tx.add_input(cashcontracts::UnsignedInput {
                outpoint: utxo.tx_outpoint.clone(),
                sequence: 0xffff_ffff,
                output: Box::new(cashcontracts::P2PKHOutput {
                    address: address.clone(),
                    value: utxo.value,
                }),
            });
        }
        Ok(())
    }

    pub fn add_utxo(&mut self, utxo: Utxo) {
        self.utxos.push(utxo);
    }
}

#[wasm_bindgen]
pub fn add_utxo(utxos: &mut Utxos, tx_hash_hex: &str, vout: u32, value: u32) -> Result<(), JsValue> {
    utxos.add_utxo(Utxo {
        tx_outpoint: cashcontracts::TxOutpoint {
            tx_hash: cashcontracts::tx_hex_to_hash(tx_hash_hex)
                .ok_or_else(|| "Invalid tx_hash_hex")?,
            vout,
        },
        value: value as u64,
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn refill_nonce_utxo_message_hash(
    owner_pk: Vec<u8>,
    utxo_tx_hash_hex: String,
    utxo_vout: u32,
    utxo_value: u32,
    utxo_nonce: i32,
    payment_amount: i32,
    funding_utxos: &Utxos,
    funding_address: String,
    fee_per_kb: u32,
    dust_limit: i32,
) -> Result<Vec<u8>, JsValue> {
    let mut unsigned_tx = _spend_nonce_utxo(
        owner_pk,
        utxo_tx_hash_hex,
        utxo_vout,
        utxo_value,
        utxo_nonce,
        payment_amount,
        None,
        None,
        dust_limit,
    )?;
    funding_utxos.add_utxos_to_tx(&mut unsigned_tx, funding_address.clone())?;
    _add_leftover_outputs(&mut unsigned_tx, funding_address, fee_per_kb, dust_limit)?;
    let preimages = unsigned_tx.pre_images(0x41);
    let mut preimage_ser = Vec::new();
    preimages[0].write_to_stream(&mut preimage_ser).unwrap();
    Ok(cashcontracts::double_sha256(&preimage_ser).to_vec())
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn refill_nonce_utxo_sign(
    owner_pk: Vec<u8>,
    utxo_tx_hash_hex: String,
    utxo_vout: u32,
    utxo_value: u32,
    utxo_nonce: i32,
    payment_amount: i32,
    funding_utxos: &Utxos,
    funding_address: String,
    fee_per_kb: u32,
    dust_limit: i32,
    covenant_pk: Vec<u8>,
    covenant_sig: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let mut unsigned_tx = _spend_nonce_utxo(
        owner_pk,
        utxo_tx_hash_hex,
        utxo_vout,
        utxo_value,
        utxo_nonce,
        payment_amount,
        None,
        None,
        dust_limit,
    )?;
    funding_utxos.add_utxos_to_tx(&mut unsigned_tx, funding_address.clone())?;
    _add_leftover_outputs(&mut unsigned_tx, funding_address, fee_per_kb, dust_limit)?;
    let tx = unsigned_tx.sign(vec![covenant_sig], vec![covenant_pk]);
    let mut tx_ser = Vec::new();
    tx.write_to_stream(&mut tx_ser).unwrap();
    Ok(tx_ser)
}

#[wasm_bindgen]
pub fn current_address(owner_pk: Vec<u8>, current_nonce: i32, dust_limit: i32) -> String {
    contract::current_address(owner_pk, current_nonce, dust_limit)
        .cash_addr()
        .to_string()
}

#[wasm_bindgen]
pub fn owner_message_hash(
    recipient_address: String,
    payment_amount: i32,
    new_nonce: i32,
) -> Result<Vec<u8>, JsValue> {
    Ok(cashcontracts::single_sha256(&contract::owner_preimage(
        cashcontracts::Address::from_cash_addr(recipient_address)
            .map_err(|err| format!("{:?}", err))?,
        payment_amount,
        new_nonce,
    ))
    .to_vec())
}

#[wasm_bindgen]
pub fn pub_key_cash_addr(prefix: &str, pubkey: Vec<u8>) -> String {
    cashcontracts::Address::from_serialized_pub_key(
        prefix,
        cashcontracts::AddressType::P2PKH,
        &pubkey,
    )
    .cash_addr()
    .to_string()
}

#[wasm_bindgen]
pub fn find_nonce_in_tx(raw_tx_hex: &str) -> Result<Option<i32>, JsValue> {
    let raw_tx = hex::decode(raw_tx_hex)
        .map_err(|err| format!("hex error: {}", err))?;
    let tx = cashcontracts::Tx::read_from_stream(&mut std::io::Cursor::new(raw_tx))
        .map_err(|err| format!("io error: {}", err))?;
    Ok(contract::find_nonce(&tx))
}
