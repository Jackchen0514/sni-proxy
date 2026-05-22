/// 从 TLS Client Hello 中解析 SNI（优化版本）
#[inline]
pub fn parse_sni(data: &[u8]) -> Option<String> {
    // 最小 TLS Client Hello 大小检查
    if data.len() < 43 {
        return None;
    }

    // 检查是否是 TLS 握手消息 (0x16)
    if data[0] != 0x16 {
        return None;
    }

    // 检查 TLS 版本 (3.x)
    if data[1] != 0x03 {
        return None;
    }

    // 跳过记录头部 (5 字节)
    let mut pos = 5;

    // 检查握手类型 (Client Hello = 0x01)
    if pos >= data.len() || data[pos] != 0x01 {
        return None;
    }
    pos += 1;

    // 读取握手长度 (3 字节)
    if pos + 3 > data.len() {
        return None;
    }
    let handshake_len = ((data[pos] as usize) << 16)
        | ((data[pos + 1] as usize) << 8)
        | (data[pos + 2] as usize);
    pos += 3;

    // 验证握手长度
    if pos + handshake_len > data.len() {
        return None;
    }

    // 跳过 TLS 版本 (2 字节)
    if pos + 2 > data.len() {
        return None;
    }
    pos += 2;

    // 跳过随机数 (32 字节)
    if pos + 32 > data.len() {
        return None;
    }
    pos += 32;

    // 读取 Session ID 长度
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1;

    // 跳过 Session ID
    if pos + session_id_len > data.len() {
        return None;
    }
    pos += session_id_len;

    // 读取 Cipher Suites 长度
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    // 跳过 Cipher Suites
    if pos + cipher_suites_len > data.len() {
        return None;
    }
    pos += cipher_suites_len;

    // 读取 Compression Methods 长度
    if pos >= data.len() {
        return None;
    }
    let compression_methods_len = data[pos] as usize;
    pos += 1;

    // 跳过 Compression Methods
    if pos + compression_methods_len > data.len() {
        return None;
    }
    pos += compression_methods_len;

    // 检查是否有 Extensions
    if pos + 2 > data.len() {
        return None;
    }

    // 读取 Extensions 长度
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > data.len() {
        return None;
    }

    // 遍历 Extensions
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > extensions_end {
            return None;
        }

        // SNI Extension (type = 0)
        if ext_type == 0 {
            return parse_sni_extension(&data[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    None
}

/// 解析 SNI Extension（优化版本）
#[inline]
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // 读取 Server Name List 长度
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;

    if 2 + list_len > data.len() {
        return None;
    }

    let mut pos = 2;

    // 读取 Server Name Type (应该是 0 = host_name)
    if data[pos] != 0 {
        return None;
    }
    pos += 1;

    // 读取 Server Name 长度
    if pos + 2 > data.len() {
        return None;
    }
    let name_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    // 验证长度（DNS 主机名最长 253 字符，RFC 1035）
    if pos + name_len > data.len() || name_len == 0 || name_len > 253 {
        return None;
    }

    // 提取域名并验证格式
    let name = String::from_utf8(data[pos..pos + name_len].to_vec()).ok()?;
    if !is_valid_sni_hostname(&name) {
        return None;
    }
    Some(name)
}

/// 验证 SNI 主机名格式（RFC 1123）
/// - 每个 label 1–63 字符，只含字母/数字/连字符
/// - label 不以连字符开头或结尾
/// - 总长度 ≤ 253（不含根域名点）
fn is_valid_sni_hostname(name: &str) -> bool {
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sni() {
        let data = vec![0x16, 0x03, 0x01]; // 截断的 TLS 握手
        assert!(parse_sni(&data).is_none());
    }

    #[test]
    fn test_valid_sni_hostnames() {
        assert!(is_valid_sni_hostname("example.com"));
        assert!(is_valid_sni_hostname("www.example.com"));
        assert!(is_valid_sni_hostname("api.v2.example.com"));
        assert!(is_valid_sni_hostname("xn--nxasmq6b.com")); // punycode
        assert!(is_valid_sni_hostname("a"));
        assert!(is_valid_sni_hostname("my-host.example.com"));
    }

    #[test]
    fn test_invalid_sni_hostnames() {
        assert!(!is_valid_sni_hostname(""));              // 空
        assert!(!is_valid_sni_hostname("-example.com"));  // label 以 - 开头
        assert!(!is_valid_sni_hostname("example-.com"));  // label 以 - 结尾
        assert!(!is_valid_sni_hostname("exam ple.com"));  // 含空格
        assert!(!is_valid_sni_hostname("example..com"));  // 空 label
        assert!(!is_valid_sni_hostname("example.com."));  // 末尾点（空 label）
        assert!(!is_valid_sni_hostname("exam_ple.com"));  // 含下划线
    }
}
