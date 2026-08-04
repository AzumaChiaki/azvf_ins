// 安装页的统一请求出口。
//
// 服务端可以在任意响应上要求页面回到核销页重新核销。这条指令走响应头而不是
// HTTP 重定向：本页的接口调用全部是 fetch()，而重定向只驱动文档导航——默认的
// redirect:'follow' 会让 fetch 自己跟过去、把核销页 HTML 当成响应体返回，地址栏
// 原地不动。所以由页面读到头之后自己跳转。
//
// 跳转前必须先关闭设备会话：导航时强行中断串口在部分浏览器上会让标签页崩溃。

export const REAUTH_HEADER = 'x-azvf-reauth'
export const REAUTH_REASON_HEADER = 'x-azvf-reauth-reason'
export type ReauthReason = 'order_bound_to_other_device' | 'authorization_context_changed'

/** 页面已开始跳转。调用方不必再提示错误，等待导航即可。 */
export class ReauthRedirect extends Error {
  constructor(readonly target: string, readonly reason?: ReauthReason) {
    super('需要重新核销')
    this.name = 'ReauthRedirect'
  }
}

type Teardown = () => Promise<void> | void
type ReauthHandler = (target: string, reason?: ReauthReason) => Promise<void> | void

let teardown: Teardown | undefined
let reauthHandler: ReauthHandler | undefined

/** 注册跳转前的清理动作（关闭设备会话）。 */
export function onBeforeReauth(handler: Teardown | undefined): void {
  teardown = handler
}

/** Registers UI-owned guidance. Without a handler the safe legacy navigation remains available. */
export function onReauthRequired(handler: ReauthHandler | undefined): void {
  reauthHandler = handler
}

/** 目标只接受同源绝对路径或 http(s) 地址，避免被诱导跳到 javascript: 之类的方案。 */
function safeTarget(raw: string): string | undefined {
  const value = raw.trim()
  if (!value || value.length > 2048) return undefined
  if (value.startsWith('//')) return undefined
  if (value.startsWith('/')) return value
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : undefined
  } catch { return undefined }
}

export async function apiFetch(input: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(input, { credentials: 'same-origin', cache: 'no-store', ...init })
  const instruction = response.headers.get(REAUTH_HEADER)
  if (!instruction) return response
  const target = safeTarget(instruction)
  if (!target) return response
  const rawReason = response.headers.get(REAUTH_REASON_HEADER)
  const reason: ReauthReason | undefined = rawReason === 'order_bound_to_other_device'
    || rawReason === 'authorization_context_changed' ? rawReason : undefined
  try { await teardown?.() } catch { /* 清理失败也要跳转 */ }
  if (reauthHandler) await reauthHandler(target, reason)
  else window.location.href = target
  throw new ReauthRedirect(target, reason)
}
