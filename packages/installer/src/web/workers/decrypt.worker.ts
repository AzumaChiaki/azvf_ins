/// <reference lib="webworker" />
// Thread 2: authenticate/decrypt v2 frames, perform the same cryptographic work
// for decoys, and only forward authenticated real payloads to the device queue.
import { toHex } from '@azvf/contract'
import {
  createChunkSequenceState,
  decryptChunkV2,
  deriveSessionKeys,
  finalizeChunkSequenceState,
  verifyControlMac,
  type SessionControlContext,
} from '../../crypto/index.js'
interface InitMsg {
  sessionMasterKey: CryptoKey
  context: SessionControlContext
  controlMac: Uint8Array
  resourceSize: number
  expectedChunkHashes: string[]
  port: MessagePort
}
interface AcceptMsg { type: 'accept'; transportSeq: number }

type PortMessage = { type: 'frame'; frame: Uint8Array } | { type: 'end' } | { type: 'abort'; reason?: string }

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource)))
}

self.onmessage = (event: MessageEvent<InitMsg>) => {
  const { sessionMasterKey, context, controlMac, resourceSize, expectedChunkHashes, port } = event.data
  let chain: Promise<void> = Promise.resolve()
  let failed = false
  let realProcessed = 0
  let decoysProcessed = 0
  let nextAcceptedTransportSeq = 0
  const state = createChunkSequenceState()

  const fail = (error: unknown): void => {
    if (failed) return
    failed = true
    const message = errorMessage(error)
    port.postMessage({ type: 'abort', reason: message })
    self.postMessage({ type: 'error', stage: 'decrypt', message })
  }

  const ready = (async () => {
    if (!Number.isSafeInteger(resourceSize) || resourceSize < 1) throw new Error('资源大小无效')
    if (context.realTotal !== Math.ceil(resourceSize / context.padTo)) throw new Error('资源大小与真实分片数不一致')
    if (expectedChunkHashes.length !== context.realTotal
      || expectedChunkHashes.some((hash) => !/^[a-f0-9]{64}$/.test(hash))) {
      throw new Error('资源分片摘要数量不一致')
    }
    const keys = await deriveSessionKeys(sessionMasterKey)
    if (!(await verifyControlMac(keys.controlKey, context, controlMac))) {
      throw new Error('安装会话控制信息认证失败')
    }
    return keys
  })()

  const handle = async (message: PortMessage): Promise<void> => {
    if (failed) return
    if (message?.type === 'abort') throw new Error(message.reason || '下载线程中止')
    if (message?.type === 'end') {
      finalizeChunkSequenceState(state)
      if (realProcessed !== context.realTotal) throw new Error('真实资源分片数量不完整')
      self.postMessage({
        type: 'done',
        stage: 'decrypt',
        decrypted: realProcessed,
        decoys: decoysProcessed,
      })
      return
    }
    if (message?.type !== 'frame' || !(message.frame instanceof Uint8Array)) {
      throw new Error('解密线程收到无效消息')
    }

    const keys = await ready
    const chunk = await decryptChunkV2(keys, context, message.frame, state)
    if (chunk.shouldInstall) {
      const seq = chunk.realSeq!
      const expectedLength = seq === context.realTotal - 1
        ? resourceSize - context.padTo * (context.realTotal - 1)
        : context.padTo
      if (chunk.data.length !== expectedLength) throw new Error(`真实分片 ${seq} 长度不匹配`)
      const expectedHash = expectedChunkHashes[seq]!
      if ((await sha256Hex(chunk.data)) !== expectedHash) {
        throw new Error(`真实分片 ${seq} 的 SHA-256 不匹配`)
      }
      realProcessed++
      const payload = chunk.data
      self.postMessage(
        { type: 'chunk', seq, total: context.realTotal, transportSeq: chunk.transportSeq, payload },
        [payload.buffer],
      )
    } else {
      // Deliberately execute a digest for authenticated decoys before dropping
      // them. They never enter PlaintextQueue or the MiWear transport.
      await crypto.subtle.digest('SHA-256', chunk.data as BufferSource)
      decoysProcessed++
      self.postMessage({ type: 'decoy', processed: decoysProcessed, transportSeq: chunk.transportSeq })
    }
    self.postMessage({
      type: 'progress',
      stage: 'decrypt',
      decrypted: realProcessed,
      decoys: decoysProcessed,
      transportProcessed: state.nextTransportSeq,
      transportTotal: context.transportTotal,
    })
  }

  void ready.catch(fail)
  // Download credit is returned only after the main thread has actually
  // accepted the corresponding plaintext/decoy event. A direct worker-to-
  // worker ACK would let browser event dispatch queue an entire resource
  // outside PlaintextQueue's measured hard bound.
  self.onmessage = (ackEvent: MessageEvent<AcceptMsg>) => {
    const accepted = ackEvent.data
    if (accepted?.type !== 'accept'
      || accepted.transportSeq !== nextAcceptedTransportSeq
      || accepted.transportSeq >= context.transportTotal) {
      fail(new Error('主线程返回了无效的传输接收序号'))
      return
    }
    nextAcceptedTransportSeq++
    port.postMessage({ type: 'ack', transportSeq: accepted.transportSeq })
  }
  port.onmessage = (portEvent: MessageEvent<PortMessage>) => {
    chain = chain.then(() => handle(portEvent.data)).catch(fail)
  }
  port.start?.()
}
