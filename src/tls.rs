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

    // 验证长度并提取域名
    if pos + name_len > data.len() || name_len == 0 || name_len > 255 {
        return None;
    }

    // 提取域名并验证 UTF-8
    String::from_utf8(data[pos..pos + name_len].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sni() {
        // 这是一个简化的测试，实际的 TLS Client Hello 会更复杂
        // 在实际使用中，你需要用真实的 TLS 握手数据来测试
        let data = vec![0x16, 0x03, 0x01]; // TLS 握手开始
        let result = parse_sni(&data);
        assert!(result.is_none());
    }
}
