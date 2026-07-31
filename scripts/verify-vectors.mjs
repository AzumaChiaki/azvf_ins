// 校验 wire-v3.json 与其 sha256 摘要文件是否一致，防止两者被分别改动后脱节。
// 夹具能否正确复现 contract 的实际行为由 wire-vectors.test.ts 断言。
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const vectorsDir = resolve(root, 'packages/contract/test/vectors')
const fixturePath = resolve(vectorsDir, 'wire-v3.json')
const checksumPath = resolve(vectorsDir, 'wire-vectors.sha256')

const [fixtureBytes, checksumText] = await Promise.all([
  readFile(fixturePath),
  readFile(checksumPath, 'utf8'),
])

const expected = checksumText.trim()
const actual = `${createHash('sha256').update(fixtureBytes).digest('hex')}  wire-v3.json`
if (expected !== actual) {
  process.stderr.write(
    `黄金向量摘要不匹配：\n  wire-vectors.sha256: ${expected}\n  实际计算值:          ${actual}\n`
    + 'wire-v3.json 与其摘要文件已经不同步；若确认改动有意，请重新生成 wire-vectors.sha256。\n',
  )
  process.exitCode = 1
} else {
  process.stdout.write(`黄金向量摘要一致：${actual}\n`)
}

let fixture
try {
  fixture = JSON.parse(fixtureBytes.toString('utf8'))
} catch (error) {
  process.stderr.write(`wire-v3.json 不是合法 JSON：${error.message}\n`)
  process.exit(1)
}
if (fixture.fixtureVersion !== 1) {
  process.stderr.write(`wire-v3.json fixtureVersion 非预期：${JSON.stringify(fixture.fixtureVersion)}\n`)
  process.exitCode = 1
}

// 如指定了另一份仓库路径，做一次本地字节比对，方便在改动夹具、发新 tag 前提前发现漂移。
const mainRepoPath = process.env.AZVF_MAIN_REPO_PATH?.trim()
if (mainRepoPath) {
  const mainFixturePath = resolve(mainRepoPath, 'packages/contract/test/vectors/wire-v3.json')
  try {
    const mainFixtureBytes = await readFile(mainFixturePath)
    if (Buffer.compare(mainFixtureBytes, fixtureBytes) !== 0) {
      process.stderr.write(`跨仓黄金向量不一致：${mainFixturePath} 与本仓 wire-v3.json 字节不同。\n`)
      process.exitCode = 1
    } else {
      process.stdout.write(`跨仓黄金向量一致：${mainFixturePath}\n`)
    }
  } catch (error) {
    process.stderr.write(`未能读取 AZVF_MAIN_REPO_PATH 指向的夹具（${mainFixturePath}）：${error.message}\n`)
    process.exitCode = 1
  }
} else {
  process.stdout.write('未设置 AZVF_MAIN_REPO_PATH，跳过本地跨仓比对（非强制）。\n')
}
