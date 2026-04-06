use crate::{
    errors::CryptoError,
    session::protocol_version,
    types::{MessageEnvelopeHeader, SessionRole},
};

pub fn build_message_aad(
    session_id: &str,
    sender_role: SessionRole,
    sequence_number: u64,
) -> Result<Vec<u8>, CryptoError> {
    ensure_hex_len(session_id, 32, CryptoError::InvalidSessionIdLength)?;

    let header = MessageEnvelopeHeader {
        protocol_version: String::from_utf8_lossy(protocol_version()).into_owned(),
        session_id: session_id.to_owned(),
        sender_role,
        sequence_number,
    };

    Ok(format!(
        "{}|{}|{}|{}",
        header.protocol_version,
        header.session_id,
        header.sender_role.label(),
        header.sequence_number
    )
    .into_bytes())
}

pub fn build_file_chunk_aad(
    session_id: &str,
    sender_role: SessionRole,
    transfer_id: &str,
    chunk_index: u32,
    declared_size: u64,
    total_chunks: u32,
    file_sha256: &str,
) -> Result<Vec<u8>, CryptoError> {
    ensure_hex_len(session_id, 32, CryptoError::InvalidSessionIdLength)?;
    ensure_hex_len(transfer_id, 16, CryptoError::InvalidTransferIdLength)?;
    ensure_hex_len(file_sha256, 32, CryptoError::InvalidFileDigestLength)?;

    Ok(format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        String::from_utf8_lossy(protocol_version()),
        session_id,
        sender_role.label(),
        transfer_id,
        chunk_index,
        declared_size,
        total_chunks,
        file_sha256
    )
    .into_bytes())
}

fn ensure_hex_len(
    value: &str,
    expected_bytes: usize,
    error: CryptoError,
) -> Result<(), CryptoError> {
    if value.len() != expected_bytes * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(error);
    }

    Ok(())
}
