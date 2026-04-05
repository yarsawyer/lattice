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
    if session_id.len() != 64 || !session_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CryptoError::InvalidSessionIdLength);
    }

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
