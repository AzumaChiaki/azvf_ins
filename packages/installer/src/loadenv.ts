// 在读取 config 之前加载 .env（Node 20.12+ / 25 内置，无需 dotenv）
try {
  ;(process as any).loadEnvFile?.()
} catch {
  // .env 不存在时忽略（可用真实环境变量）
}
