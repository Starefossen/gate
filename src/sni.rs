const TLS_HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const SNI_EXTENSION: u16 = 0x0000;

/// Extract the SNI hostname from a TLS ClientHello message.
///
/// Parses the TLS record header, handshake header, and walks through
/// extensions looking for the Server Name Indication (type 0x0000).
/// Returns `None` if the data is not a valid ClientHello or contains
/// no SNI extension with a hostname entry.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    if data[0] != TLS_HANDSHAKE {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let record_end = 5 + record_len.min(data.len() - 5);
    let record = &data[5..record_end];

    if record.is_empty() || record[0] != CLIENT_HELLO {
        return None;
    }

    if record.len() < 4 {
        return None;
    }

    let mut pos = 4;

    // client version (2) + random (32)
    pos += 2 + 32;

    if pos >= record.len() {
        return None;
    }

    // session ID (variable)
    let session_id_len = record[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > record.len() {
        return None;
    }

    // cipher suites (variable)
    let cipher_suites_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if pos >= record.len() {
        return None;
    }

    // compression methods (variable)
    let compression_len = record[pos] as usize;
    pos += 1 + compression_len;

    if pos + 2 > record.len() {
        return None;
    }

    // extensions
    let extensions_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = (pos + extensions_len).min(record.len());

    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        pos += 4;

        if ext_type == SNI_EXTENSION && ext_len >= 5 && pos + ext_len <= extensions_end {
            let name_type = record[pos + 2];
            let name_len = u16::from_be_bytes([record[pos + 3], record[pos + 4]]) as usize;

            if name_type == 0 && pos + 5 + name_len <= extensions_end {
                let name = &record[pos + 5..pos + 5 + name_len];
                return String::from_utf8(name.to_vec()).ok();
            }
        }

        pos += ext_len;
    }

    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn valid_hostname() {
        let hello = build_client_hello("example.com", &[]);
        assert_eq!(extract_sni(&hello), Some("example.com".to_string()));
    }

    #[test]
    fn long_hostname() {
        let long = format!("{}.example.com", "a".repeat(200));
        let hello = build_client_hello(&long, &[]);
        assert_eq!(extract_sni(&hello), Some(long));
    }

    #[test]
    fn subdomain() {
        let hello = build_client_hello("hello.hello.fn.flaatten.org", &[]);
        assert_eq!(
            extract_sni(&hello),
            Some("hello.hello.fn.flaatten.org".to_string())
        );
    }

    #[test]
    fn with_session_id() {
        let hello = build_client_hello_with_session_id("example.com", &[0xAB; 32]);
        assert_eq!(extract_sni(&hello), Some("example.com".to_string()));
    }

    #[test]
    fn with_preceding_extensions() {
        let dummy_ext = build_extension(0x0010, &[0x00, 0x02, 0x02, 0x68, 0x32]);
        let hello = build_client_hello("example.com", &[&dummy_ext]);
        assert_eq!(extract_sni(&hello), Some("example.com".to_string()));
    }

    #[test]
    fn with_many_extensions() {
        let ext1 = build_extension(0x0010, &[0x00, 0x02, 0x02, 0x68, 0x32]);
        let ext2 = build_extension(0x000d, &[0x00, 0x04, 0x04, 0x01, 0x05, 0x01]);
        let ext3 = build_extension(0x000a, &[0x00, 0x04, 0x00, 0x17, 0x00, 0x18]);
        let hello = build_client_hello("example.com", &[&ext1, &ext2, &ext3]);
        assert_eq!(extract_sni(&hello), Some("example.com".to_string()));
    }

    #[test]
    fn empty_data() {
        assert_eq!(extract_sni(&[]), None);
    }

    #[test]
    fn too_short() {
        assert_eq!(extract_sni(&[0x16, 0x03]), None);
    }

    #[test]
    fn just_record_header() {
        assert_eq!(extract_sni(&[0x16, 0x03, 0x01, 0x00, 0x00]), None);
    }

    #[test]
    fn not_handshake_content_type() {
        assert_eq!(extract_sni(&[0x17, 0x03, 0x01, 0x00, 0x00]), None);
    }

    #[test]
    fn server_hello_not_client_hello() {
        assert_eq!(
            extract_sni(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x03]),
            None
        );
    }

    #[test]
    fn no_extensions() {
        assert_eq!(
            extract_sni(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03]),
            None
        );
    }

    #[test]
    fn truncated_before_extensions() {
        let mut hello = build_client_hello("example.com", &[]);
        hello.truncate(5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1);
        assert_eq!(extract_sni(&hello), None);
    }

    #[test]
    fn truncated_mid_extension() {
        let mut hello = build_client_hello("example.com", &[]);
        hello.truncate(hello.len() - 5);
        assert_eq!(extract_sni(&hello), None);
    }

    #[test]
    fn non_hostname_type() {
        let name = b"example.com";
        let mut sni_payload = Vec::new();
        let sni_list_len = 1 + 2 + name.len();
        sni_payload.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        sni_payload.push(1); // NOT hostname (0)
        sni_payload.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_payload.extend_from_slice(name);

        let ext = build_extension(0x0000, &sni_payload);
        let hello = build_client_hello_no_sni(&[&ext]);
        assert_eq!(extract_sni(&hello), None);
    }

    #[test]
    fn invalid_utf8() {
        let bad_name = &[0xFF, 0xFE, 0x80, 0x81];
        let mut sni_payload = Vec::new();
        let sni_list_len = 1 + 2 + bad_name.len();
        sni_payload.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        sni_payload.push(0);
        sni_payload.extend_from_slice(&(bad_name.len() as u16).to_be_bytes());
        sni_payload.extend_from_slice(bad_name);

        let ext = build_extension(0x0000, &sni_payload);
        let hello = build_client_hello_no_sni(&[&ext]);
        assert_eq!(extract_sni(&hello), None);
    }

    #[test]
    fn record_length_shorter_than_data() {
        let mut hello = build_client_hello("example.com", &[]);
        let orig_len = u16::from_be_bytes([hello[3], hello[4]]);
        let new_len = orig_len - 10;
        hello[3] = (new_len >> 8) as u8;
        hello[4] = (new_len & 0xFF) as u8;
        let _ = extract_sni(&hello); // must not panic
    }

    #[test]
    fn many_cipher_suites() {
        let hello = build_client_hello_with_ciphers("example.com", 100);
        assert_eq!(extract_sni(&hello), Some("example.com".to_string()));
    }

    // =========================================================
    // Test helpers
    // =========================================================

    pub fn build_client_hello(hostname: &str, preceding_exts: &[&[u8]]) -> Vec<u8> {
        build_client_hello_inner(hostname, preceding_exts, 0, 1)
    }

    fn build_client_hello_with_session_id(hostname: &str, session_id: &[u8]) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len();

        let sni_payload_len = 2 + 1 + 2 + name_len;
        let ext_len = 4 + sni_payload_len;
        let extensions_total = 2 + ext_len;
        let ch_body_len = 2 + 32 + 1 + session_id.len() + 2 + 2 + 1 + 1 + extensions_total;
        let hs_len = 1 + 3 + ch_body_len;
        let mut buf = Vec::with_capacity(5 + hs_len);

        buf.push(TLS_HANDSHAKE);
        buf.extend_from_slice(&[0x03, 0x01]);
        buf.extend_from_slice(&(hs_len as u16).to_be_bytes());
        buf.push(CLIENT_HELLO);
        buf.push(0);
        buf.extend_from_slice(&(ch_body_len as u16).to_be_bytes());
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(session_id.len() as u8);
        buf.extend_from_slice(session_id);
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x2f]);
        buf.push(1);
        buf.push(0);
        buf.extend_from_slice(&(ext_len as u16).to_be_bytes());
        buf.extend_from_slice(&SNI_EXTENSION.to_be_bytes());
        buf.extend_from_slice(&(sni_payload_len as u16).to_be_bytes());
        buf.extend_from_slice(&((sni_payload_len - 2) as u16).to_be_bytes());
        buf.push(0);
        buf.extend_from_slice(&(name_len as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);

        buf
    }

    fn build_client_hello_with_ciphers(hostname: &str, num_ciphers: usize) -> Vec<u8> {
        build_client_hello_inner(hostname, &[], 0, num_ciphers)
    }

    fn build_client_hello_inner(
        hostname: &str,
        preceding_exts: &[&[u8]],
        session_id_len: usize,
        num_ciphers: usize,
    ) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len();

        let sni_payload_len = 2 + 1 + 2 + name_len;
        let sni_ext_len = 4 + sni_payload_len;
        let preceding_total: usize = preceding_exts.iter().map(|e| e.len()).sum();
        let all_extensions = preceding_total + sni_ext_len;
        let extensions_total = 2 + all_extensions;

        let cipher_suites_bytes = num_ciphers * 2;
        let ch_body_len =
            2 + 32 + 1 + session_id_len + 2 + cipher_suites_bytes + 1 + 1 + extensions_total;
        let hs_len = 1 + 3 + ch_body_len;
        let mut buf = Vec::with_capacity(5 + hs_len);

        buf.push(TLS_HANDSHAKE);
        buf.extend_from_slice(&[0x03, 0x01]);
        buf.extend_from_slice(&(hs_len as u16).to_be_bytes());
        buf.push(CLIENT_HELLO);
        buf.push(0);
        buf.extend_from_slice(&(ch_body_len as u16).to_be_bytes());
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(session_id_len as u8);
        buf.extend_from_slice(&vec![0xABu8; session_id_len]);

        buf.extend_from_slice(&(cipher_suites_bytes as u16).to_be_bytes());
        for i in 0..num_ciphers {
            buf.extend_from_slice(&(i as u16).to_be_bytes());
        }

        buf.push(1);
        buf.push(0);

        buf.extend_from_slice(&(all_extensions as u16).to_be_bytes());
        for ext in preceding_exts {
            buf.extend_from_slice(ext);
        }

        buf.extend_from_slice(&SNI_EXTENSION.to_be_bytes());
        buf.extend_from_slice(&(sni_payload_len as u16).to_be_bytes());
        buf.extend_from_slice(&((sni_payload_len - 2) as u16).to_be_bytes());
        buf.push(0);
        buf.extend_from_slice(&(name_len as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);

        buf
    }

    fn build_client_hello_no_sni(extensions: &[&[u8]]) -> Vec<u8> {
        let ext_total: usize = extensions.iter().map(|e| e.len()).sum();
        let extensions_block = 2 + ext_total;

        let ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + extensions_block;
        let hs_len = 1 + 3 + ch_body_len;
        let mut buf = Vec::with_capacity(5 + hs_len);

        buf.push(TLS_HANDSHAKE);
        buf.extend_from_slice(&[0x03, 0x01]);
        buf.extend_from_slice(&(hs_len as u16).to_be_bytes());
        buf.push(CLIENT_HELLO);
        buf.push(0);
        buf.extend_from_slice(&(ch_body_len as u16).to_be_bytes());
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0);
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x2f]);
        buf.push(1);
        buf.push(0);
        buf.extend_from_slice(&(ext_total as u16).to_be_bytes());
        for ext in extensions {
            buf.extend_from_slice(ext);
        }

        buf
    }

    fn build_extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + data.len());
        buf.extend_from_slice(&ext_type.to_be_bytes());
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        buf
    }
}
