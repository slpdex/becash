use cashcontracts::*;

use hex_literal::hex;

pub enum SendData {
    Redeem {
        payment_amount: i32,
        new_nonce: i32,
        owner_sig: Vec<u8>,
    },
    Refill {
        payment_amount: i32,
    },
}

#[allow(clippy::too_many_arguments)]
pub fn spend_nonce_utxo(
    owner_pk: Vec<u8>,
    utxo: TxOutpoint,
    utxo_value: u64,
    utxo_nonce: i32,
    send_data: SendData,
    dust_limit: i32,
) -> UnsignedTx {
    let (spend_params, payment_amount, new_nonce) = match send_data {
        SendData::Redeem { payment_amount, new_nonce, owner_sig } => {
            (
                P2AscendingNonceSpendParams::NonceRedeem {
                    payment_amount,
                    new_nonce,
                    owner_sig,
                    is_terminal: (utxo_value as i32 - payment_amount as i32) < dust_limit,
                },
                payment_amount,
                new_nonce,
            )
        },
        SendData::Refill { payment_amount } => {
            (P2AscendingNonceSpendParams::NonceRefill { payment_amount }, payment_amount, utxo_nonce)
        },
    };
    let new_utxo_value = (utxo_value as i64 - payment_amount as i64) as u64;
    let old_nonce_output = P2AscendingNonce {
        lokad_id: hex!("b17c012c").to_vec(),
        old_value: utxo_value,
        owner_pk: owner_pk.clone(),
        old_nonce: utxo_nonce,
        spend_params: Some(spend_params),
        dust_limit: dust_limit as i32,
    };
    let new_nonce_output = P2AscendingNonce {
        lokad_id: hex!("b17c012c").to_vec(),
        old_value: new_utxo_value,
        owner_pk,
        old_nonce: new_nonce,
        spend_params: None,
        dust_limit: dust_limit as i32,
    };
    let mut tx_build = UnsignedTx::new_simple();
    tx_build.add_input(UnsignedInput {
        output: Box::new(P2SHOutput {
            output: Box::new(old_nonce_output.clone()),
        }),
        outpoint: utxo,
        sequence: 0xffff_ffff,
    });
    if new_utxo_value >= dust_limit as u64 {
        tx_build.add_output(TxOutput {
            value: new_utxo_value,
            script: P2SHOutput {
                output: Box::new(new_nonce_output),
            }
            .script(),
        });
    }
    tx_build
}

pub fn spend_nonce_utxo_p2pk(
    owner_pk: Vec<u8>,
    utxo: TxOutpoint,
    utxo_value: u64,
    utxo_nonce: i32,
    dust_limit: i32,
) -> UnsignedTx {
    let old_nonce_output = P2AscendingNonce {
        lokad_id: hex!("b17c012c").to_vec(),
        old_value: utxo_value,
        owner_pk: owner_pk.clone(),
        old_nonce: utxo_nonce,
        spend_params: Some(P2AscendingNonceSpendParams::P2pk),
        dust_limit: dust_limit as i32,
    };
    let mut tx_build = UnsignedTx::new_simple();
    tx_build.add_input(UnsignedInput {
        output: Box::new(P2SHOutput {
            output: Box::new(old_nonce_output.clone()),
        }),
        outpoint: utxo,
        sequence: 0xffff_ffff,
    });
    tx_build
}

pub fn owner_preimage(recipient_address: Address, payment_amount: i32, new_nonce: i32) -> Vec<u8> {
    let mut owner_preimage = Vec::with_capacity(20 + 8 + 8);
    owner_preimage.extend_from_slice(recipient_address.bytes());
    owner_preimage.extend_from_slice(&serialize::encode_int_n(payment_amount, 8));
    owner_preimage.extend_from_slice(&serialize::encode_int_n(new_nonce, 8));
    owner_preimage
}

pub fn current_address(owner_pk: Vec<u8>, current_nonce: i32, dust_limit: i32) -> Address {
    Address::from_bytes(
        AddressType::P2SH,
        hash160(&P2AscendingNonce {
            lokad_id: hex!("b17c012c").to_vec(),
            old_value: 0,
            owner_pk,
            old_nonce: current_nonce,
            spend_params: None,
            dust_limit,
        }.script().to_vec())
    )
}

pub fn find_nonce(tx: &cashcontracts::Tx) -> Option<i32> {
    for tx_input in tx.inputs() {
        let ops = tx_input.script().ops();
        let lokad_id = ops.first()?;
        if let cashcontracts::Op::Push(lokad_id) = lokad_id {
            if lokad_id != &hex!("b17c012c") { continue }
            if let cashcontracts::Op::Push(nonce_bytes) = ops.get(ops.len() - 3)? {
                return Some(cashcontracts::serialize::vec_to_int(nonce_bytes));
            }
        }
    }
    None
}
