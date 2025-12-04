#![no_std]
#![no_main]

use aya_bpf::{
    bindings::BPF_F_INGRESS,
    macros::{map, sk_msg},
    maps::{HashMap, SockHash},
    programs::SkMsgContext,
};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

/// Socket Hash Map: 用于存储 socket 文件描述符
/// Key: socket cookie (u64)
/// Value: socket 本身
#[map]
static SOCK_MAP: SockHash<u64> = SockHash::with_max_entries(65536, 0);

/// 连接映射表: client socket → target socket
/// Key: client socket cookie (u64)
/// Value: target socket cookie (u64)
#[map]
static CONNECTION_MAP: HashMap<u64, u64> = HashMap::with_max_entries(65536, 0);

/// Socket 消息重定向程序
/// 当数据包到达时，将其重定向到对端 socket
#[sk_msg]
pub fn redirect_msg(ctx: SkMsgContext) -> u32 {
    match try_redirect_msg(&ctx) {
        Ok(action) => action,
        Err(_) => 1, // SK_PASS: 交给用户态处理
    }
}

#[inline(always)]
fn try_redirect_msg(ctx: &SkMsgContext) -> Result<u32, i64> {
    // 获取当前 socket 的唯一标识符 (cookie)
    let sock_cookie = unsafe {
        match aya_bpf::helpers::bpf_get_socket_cookie(ctx.as_ptr() as *mut _) {
            cookie if cookie > 0 => cookie,
            _ => return Ok(1), // 获取失败，交给用户态处理
        }
    };

    // 在连接映射表中查找对端 socket
    unsafe {
        let peer_cookie = CONNECTION_MAP.get(&sock_cookie).ok_or(-1i64)?;

        // 重定向消息到对端 socket（零拷贝）
        // BPF_F_INGRESS: 数据包进入对端的接收队列
        ctx.sk_redirect_map(&SOCK_MAP, *peer_cookie, BPF_F_INGRESS as u64)
            .map_err(|_| -1i64)?;

        // SK_PASS: 虽然返回 PASS，但数据已被重定向
        // 原始数据将被丢弃
        Ok(1)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
