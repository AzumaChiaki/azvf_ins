import { rm } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const generated = [
  'packages/contract/dist',
  'packages/installer/dist',
  'packages/installer/dist-web',
  'packages/reference-authorizer/dist',
  'artifacts',
]

await Promise.all(generated.map((path) => rm(resolve(root, path), { recursive: true, force: true })))
