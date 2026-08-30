import { describe, expect, it } from 'vitest'
import { EntitlementDecisionError, UpstreamHttpError } from '@azvf/internal-client'
import { isTransientUpstreamFailure, refusalMessage } from './routes.js'

describe('isTransientUpstreamFailure', () => {
  it('把 5xx/网络故障判为瞬时,不终结安装会话', () => {
    // internal-client 把所有未知状态归一成 502。
    expect(isTransientUpstreamFailure(new UpstreamHttpError(502, '授权安装额度核销失败'))).toBe(true)
    expect(isTransientUpstreamFailure(new TypeError('fetch failed'))).toBe(true)
  })

  it('把 Console 的确定性拒绝判为终局', () => {
    for (const status of [400, 401, 403, 404, 409, 410, 422, 426, 429]) {
      expect(isTransientUpstreamFailure(new UpstreamHttpError(status, '授权安装额度核销失败'))).toBe(false)
    }
  })

  it('风控决策永远是终局,即使它带着 5xx', () => {
    const decision = new EntitlementDecisionError(502, { action: 'terminate', reason: '风控终止' })
    expect(isTransientUpstreamFailure(decision)).toBe(false)
  })
})

describe('refusalMessage', () => {
  it('按 Console 的错误码分开说,不再一律报「授权已撤销」', () => {
    const message = (code?: string) => refusalMessage(new UpstreamHttpError(403, '授权安装额度核销失败', code))
    expect(message('authorization_superseded')).toContain('更新的安装会话')
    expect(message('authorization_device_mismatch')).toContain('另一台设备')
    expect(message('install_quota_exhausted')).toContain('额度')
  })

  it('没有码或不认识的码回落到原来的说法', () => {
    expect(refusalMessage(new UpstreamHttpError(403, 'x'))).toBe('授权已撤销、过期或不再可用')
    expect(refusalMessage(new UpstreamHttpError(403, 'x', 'entitlement_unavailable'))).toBe('授权已撤销、过期或不再可用')
    expect(refusalMessage(new Error('boom'))).toBe('授权已撤销、过期或不再可用')
  })
})
