// 跨项目共享的领域类型

/** 资源类型，数值与逆向还原的 MiWear 设备协议 res_type 对齐。 */
export enum ResType {
  Watchface = 16,
  Firmware = 32,
  QuickApp = 64,
}

/** 资源元数据（随会话头下发；size/sha256 对齐原始明文） */
export interface ResourceMeta {
  /** Only signed resource manifest v2 is accepted by Installer. */
  formatVersion?: 2
  id: string
  name: string
  resType: ResType
  /** 快应用需要包名；表盘/固件可为空 */
  packageName?: string | null
  /** 原始明文字节数 */
  size: number
  /** 原始明文 SHA-256（hex），前端重组后可校验 */
  sha256: string
  /** 原始明文 MD5（hex）。MiWear MASS 传输头需在传输前预知，故服务端预先计算下发 */
  md5: string
  /** 表盘(resType=16)专用：从文件头解析出的表盘 ID，供安装 Prepare 阶段使用 */
  watchfaceId?: string | null
  version: string
  /** 分片大小（字节） */
  chunkSize: number
  /** 总分片数 */
  totalChunks: number
  /** 每个真实明文分片的 SHA-256（hex），顺序与安装 realSeq 一致。 */
  chunkSha256?: string[]
  /** 固定 canonical JSON 的 SHA-256（hex）。 */
  manifestHash?: string
  /** Ed25519(raw 32-byte manifestHash)，base64url。 */
  manifestSignature?: string
  /** 用于从 Installer 公钥环选择验签密钥。 */
  manifestKeyId?: string
}

/** Installer protocol v2 only accepts this fully signed, non-downgradable form. */
export interface SignedResourceMeta extends ResourceMeta {
  formatVersion: 2
  chunkSha256: string[]
  manifestHash: string
  manifestSignature: string
  manifestKeyId: string
}

/** Per-session watchface rewrite applied only to the plaintext sent to the device. */
export interface WatchfaceInstallTransform {
  /** Fresh 12-digit identity sent in both WatchFace Prepare and the resource header. */
  id: string
  /** MD5 of the rewritten resource, used by MiWear MASS Prepare/header. */
  md5: string
  /** Absolute byte offset at which the replacement ID starts. */
  idOffset: number
  /** Exclusive end of the fixed watchface ID field; bytes after the ID are cleared. */
  fieldEnd: number
}

/** installer 后端在建立安装会话时返回给浏览器的会话头 */
export interface SessionInitResponse {
  sessionId: string
  /** 会话控制能力令牌；只允许放在 x-session-control 请求头，禁止写入 URL。 */
  controlToken: string
  /** 当前持久化安装租约的 Unix 毫秒到期时间。 */
  leaseExpiresAt: number
  /** 传输协议版本。 */
  protocolVersion: 3
  /** 会话主密钥，以浏览器本次会话公钥包裹，base64。 */
  wrappedKey: string
  /** 服务器 Unix 秒时间戳。 */
  serverEpoch: number
  /** 本次会话经传输层发送的帧总数。 */
  transportTotal: number
  /** 应写入设备的分片总数。 */
  realTotal: number
  /** 每帧的固定数据区大小。 */
  padTo: number
  /** 会话控制字段的 HMAC-SHA-256，base64。 */
  controlMac: string
  meta: SignedResourceMeta
  /** Present only for watchfaces; authenticated by controlMac. */
  watchfaceTransform?: WatchfaceInstallTransform
  /** 拉取分片流的地址（相对 installer 后端） */
  streamUrl: string
}

/** 浏览器发起安装会话的请求 */
export interface SessionInitRequest {
  /** console 签发的授权令牌 (JWT) */
  authToken: string
  /** 浏览器本次会话公钥 base64(SPKI)，用于服务端包裹会话密钥 */
  clientPublicKey: string
  resourceId: string
  /** 规范化前的目标设备 MAC；服务端必须规范化并严格匹配授权绑定。 */
  deviceAddr: string
  /** 用户同意后采集的低熵运行环境属性；服务端只负责原样转交授权服务。 */
  clientAttributes?: {
    timeZone: string
    language: string
    screen: string
    hardwareConcurrency: number
    platform: string
    engine: 'Chrome' | 'Firefox' | 'Safari' | 'Edge' | 'Other'
  }
}

/**
 * 安装授权令牌的载荷（JWT claims）。
 *
 * 这是安装器**实际使用**的最小集合。签发方可以在同一个 JWT 中附带其他
 * claims——JWT 本就允许未知字段，安装器一律忽略，不做校验也不做判断。因此本
 * 接口不描述任何签发方的业务模型。
 */
export interface InstallerAuthorizationClaims {
  /** 授权主体标识；安装器只做长度校验，不解释其含义 */
  sub: string
  /** 授权可访问的资源 id 列表 */
  resourceIds: string[]
  /** 授权记录 id（用于撤销/审计/额度核销） */
  entitlementId: string
  /** 签名的安装等级；安装器用本地阶梯配置映射并发，缺失时拒绝令牌 */
  tier: 'basic' | 'standard' | 'premium' | 'internal'
  /** 签名授权并发；安装器只允许它收紧本地 tier/entitlement 上限 */
  installConcurrency: number
  /** 客户端同意/采集上下文版本；缺失按旧版处理并要求重新登录。 */
  clientContextVersion: number
  /** 可选：绑定设备地址 */
  deviceAddr?: string
  iss: string
  aud: string
  jti: string
  iat: number
  exp: number
}

/** @deprecated 用 {@link InstallerAuthorizationClaims}。保留以免下游一次性断裂。 */
export type AuthTokenPayload = InstallerAuthorizationClaims

/**
 * 令牌的 issuer / audience 缺省值。签发方与安装器必须取值一致。
 *
 * 这里只能是编译期常量——本模块会被浏览器 bundle 引用，不可读取 `process.env`。
 * 若部署方需要自定义，应在各自的服务端配置层覆盖后传入，不要改动本文件。
 */
export const DEFAULT_TOKEN_ISSUER = 'azvf-console'
export const DEFAULT_TOKEN_AUDIENCE = 'azvf-installer'

/** 当前 Console ↔ Installer/Redeem 线协议版本。破坏性字段变化必须递增。 */
export const WIRE_PROTOCOL_VERSION = 3

/** 已冻结的新同意协议版本；在生产激活前可以存在于代码中但不得自动抬高数据库 minimum。 */
export const SUPPORTED_CLIENT_CONTEXT_VERSION = 1

/** @deprecated 服务端应从运行配置读取；仅保留为默认值兼容旧调用方。 */
export const TOKEN_ISSUER = DEFAULT_TOKEN_ISSUER
/** @deprecated 服务端应从运行配置读取；仅保留为默认值兼容旧调用方。 */
export const TOKEN_AUDIENCE = DEFAULT_TOKEN_AUDIENCE
