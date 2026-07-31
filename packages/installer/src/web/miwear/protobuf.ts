import { concatBytes } from './bytes'

export interface ProtoField {
  number: number
  wireType: number
  value: bigint | Uint8Array
}

export function encodeVarint(value: number | bigint): Uint8Array {
  let remaining = BigInt(value)
  if (remaining < 0n) throw new Error('不支持负数 varint')
  const bytes: number[] = []
  do {
    let byte = Number(remaining & 0x7fn)
    remaining >>= 7n
    if (remaining !== 0n) byte |= 0x80
    bytes.push(byte)
  } while (remaining !== 0n)
  return Uint8Array.from(bytes)
}

export function varintField(number: number, value: number | bigint): Uint8Array {
  return concatBytes(encodeVarint((number << 3) | 0), encodeVarint(value))
}

export function bytesField(number: number, value: Uint8Array): Uint8Array {
  return concatBytes(encodeVarint((number << 3) | 2), encodeVarint(value.length), value)
}

export function stringField(number: number, value: string): Uint8Array {
  return bytesField(number, new TextEncoder().encode(value))
}

export function message(...fields: Uint8Array[]): Uint8Array {
  return concatBytes(...fields)
}

function decodeVarint(data: Uint8Array, start: number): [bigint, number] {
  let value = 0n
  let shift = 0n
  let offset = start
  while (offset < data.length && shift <= 63n) {
    const byte = data[offset++]
    value |= BigInt(byte & 0x7f) << shift
    if ((byte & 0x80) === 0) return [value, offset]
    shift += 7n
  }
  throw new Error('protobuf varint 截断')
}

export function decodeFields(data: Uint8Array): ProtoField[] {
  const fields: ProtoField[] = []
  let offset = 0
  while (offset < data.length) {
    const [key, afterKey] = decodeVarint(data, offset)
    offset = afterKey
    const number = Number(key >> 3n)
    const wireType = Number(key & 7n)
    if (number === 0) throw new Error('protobuf 字段号不能为 0')
    if (wireType === 0) {
      const [value, next] = decodeVarint(data, offset)
      fields.push({ number, wireType, value })
      offset = next
    } else if (wireType === 2) {
      const [lengthValue, afterLength] = decodeVarint(data, offset)
      const length = Number(lengthValue)
      const end = afterLength + length
      if (end > data.length) throw new Error('protobuf length-delimited 字段截断')
      fields.push({ number, wireType, value: data.slice(afterLength, end) })
      offset = end
    } else if (wireType === 1) {
      const end = offset + 8
      if (end > data.length) throw new Error('protobuf fixed64 字段截断')
      fields.push({ number, wireType, value: data.slice(offset, end) })
      offset = end
    } else if (wireType === 5) {
      const end = offset + 4
      if (end > data.length) throw new Error('protobuf fixed32 字段截断')
      fields.push({ number, wireType, value: data.slice(offset, end) })
      offset = end
    } else {
      throw new Error(`暂不支持 protobuf wire type ${wireType}`)
    }
  }
  return fields
}

export function fieldBytes(fields: ProtoField[], number: number): Uint8Array | undefined {
  const field = fields.find(item => item.number === number && item.value instanceof Uint8Array)
  return field?.value as Uint8Array | undefined
}

export function fieldNumber(fields: ProtoField[], number: number): number | undefined {
  const field = fields.find(item => item.number === number && typeof item.value === 'bigint')
  return field ? Number(field.value) : undefined
}

export type IncomingMessage =
  | { kind: 'auth-device-verify'; deviceRandom: Uint8Array; deviceSign: Uint8Array }
  | { kind: 'auth-device-confirm'; confirmed: boolean }
  | { kind: 'watchface-prepare'; status: number }
  | { kind: 'watchface-result'; code: number }
  | { kind: 'app-prepare'; status: number }
  | { kind: 'app-result'; code: number }
  | { kind: 'firmware-prepare'; status: number }
  | { kind: 'mass-prepare'; status: number; expectedSliceLength: number; remainedDataLength: number }
  | { kind: 'device-info'; data: Record<string, string> }
  | { kind: 'device-status'; data: Record<string, any> }
  | { kind: 'storage-info'; data: { used: number; total: number } }
  | { kind: 'watchface-list'; data: Array<Record<string, any>> }
  | { kind: 'app-list'; data: Array<Record<string, any>> }
  | { kind: 'unknown'; type?: number; id?: number }

function wrapWearPacket(type: number, id: number, payloadField: number, payload: Uint8Array): Uint8Array {
  return payloadField > 0
    ? message(varintField(1, type), varintField(2, id), bytesField(payloadField, payload))
    : message(varintField(1, type), varintField(2, id))
}

export function buildAuthAppVerify(random: Uint8Array): Uint8Array {
  const appVerify = bytesField(1, random)
  return wrapWearPacket(1, 26, 3, bytesField(30, appVerify))
}

export function buildAuthAppConfirm(appSign: Uint8Array, encryptedDevice: Uint8Array): Uint8Array {
  const appConfirm = message(bytesField(1, appSign), bytesField(2, encryptedDevice))
  return wrapWearPacket(1, 27, 3, bytesField(32, appConfirm))
}

export function buildCompanionDevice(deviceType: number): Uint8Array {
  return message(
    varintField(1, deviceType),
    stringField(3, 'BandBurg'),
    varintField(4, 0xffffffff)
  )
}

export function buildWatchfaceInstall(id: string, size: number): Uint8Array {
  const prepare = message(stringField(1, id), varintField(2, size), varintField(3, 65536))
  return wrapWearPacket(4, 4, 6, bytesField(6, prepare))
}

export function buildAppInstall(packageName: string, size: number): Uint8Array {
  const request = message(stringField(1, packageName), varintField(2, 114514), varintField(3, size))
  return wrapWearPacket(20, 1, 22, bytesField(2, request))
}

export function buildFirmwareInstall(md5Hex: string, size: number): Uint8Array {
  const request = message(
    varintField(1, 1),
    varintField(2, 0),
    stringField(3, '99.99.99'),
    stringField(4, md5Hex),
    stringField(5, 'BandBurg Firmware Update'),
    stringField(6, ''),
    varintField(7, size)
  )
  return wrapWearPacket(2, 5, 4, bytesField(16, request))
}

export function buildMassPrepare(dataType: number, digest: Uint8Array, size: number): Uint8Array {
  const request = message(varintField(1, dataType), bytesField(2, digest), varintField(3, size))
  return wrapWearPacket(22, 0, 24, bytesField(1, request))
}

export function buildSystemRequest(id: number): Uint8Array {
  return wrapWearPacket(2, id, 0, new Uint8Array())
}

export function buildWatchfaceGetList(): Uint8Array {
  return wrapWearPacket(4, 0, 0, new Uint8Array())
}

export function buildWatchfaceAction(id: number, watchfaceId: string): Uint8Array {
  return wrapWearPacket(4, id, 6, bytesField(2, new TextEncoder().encode(watchfaceId)))
}

function basicInfo(packageName: string, fingerprint: Uint8Array): Uint8Array {
  return message(stringField(1, packageName), bytesField(2, fingerprint))
}

export function buildAppGetList(): Uint8Array {
  return wrapWearPacket(20, 0, 0, new Uint8Array())
}

export function buildAppAction(id: number, packageName: string, fingerprint: Uint8Array, page?: string, content?: Uint8Array): Uint8Array {
  const inner = page !== undefined
    ? bytesField(6, message(bytesField(1, basicInfo(packageName, fingerprint)), stringField(2, page)))
    : content !== undefined
      ? bytesField(9, message(bytesField(1, basicInfo(packageName, fingerprint)), bytesField(2, content)))
      : bytesField(5, basicInfo(packageName, fingerprint))
  return wrapWearPacket(20, id, 22, inner)
}

function textField(fields: ProtoField[], number: number): string {
  const value = fieldBytes(fields, number)
  return value ? new TextDecoder().decode(value) : ''
}

function parseWatchfaceItems(data: Uint8Array): Array<Record<string, any>> {
  const list = fieldBytes(decodeFields(data), 1)
  if (!list) return []
  return decodeFields(list)
    .filter(field => field.number === 1 && field.value instanceof Uint8Array)
    .map(field => {
      const fields = decodeFields(field.value as Uint8Array)
      return {
        id: textField(fields, 1),
        name: textField(fields, 2),
        isCurrent: fieldNumber(fields, 3) === 1,
        canRemove: fieldNumber(fields, 4) === 1,
        versionCode: fieldNumber(fields, 5) ?? 0
      }
    })
}

function parseAppItems(data: Uint8Array): Array<Record<string, any>> {
  const list = fieldBytes(decodeFields(data), 1)
  if (!list) return []
  return decodeFields(list)
    .filter(field => field.number === 1 && field.value instanceof Uint8Array)
    .map(field => {
      const fields = decodeFields(field.value as Uint8Array)
      return {
        packageName: textField(fields, 1),
        fingerprint: Array.from(fieldBytes(fields, 2) ?? []),
        version: fieldNumber(fields, 3) ?? 0,
        canRemove: fieldNumber(fields, 4) === 1,
        name: textField(fields, 5)
      }
    })
}

export function parseWearPacket(data: Uint8Array): IncomingMessage {
  const wear = decodeFields(data)
  const type = fieldNumber(wear, 1)
  const id = fieldNumber(wear, 2)

  if (type === 1) {
    const account = fieldBytes(wear, 3)
    if (!account) return { kind: 'unknown', type, id }
    const fields = decodeFields(account)
    const verify = fieldBytes(fields, 31)
    if (verify) {
      const values = decodeFields(verify)
      const deviceRandom = fieldBytes(values, 1)
      const deviceSign = fieldBytes(values, 2)
      if (deviceRandom && deviceSign) return { kind: 'auth-device-verify', deviceRandom, deviceSign }
    }
    const confirm = fieldBytes(fields, 33)
    if (confirm) {
      return { kind: 'auth-device-confirm', confirmed: fieldNumber(decodeFields(confirm), 1) !== 0 }
    }
  }

  if (type === 4) {
    const payload = fieldBytes(wear, 6)
    if (payload) {
      const fields = decodeFields(payload)
      const status = fieldNumber(fields, 5)
      if (status !== undefined) return { kind: 'watchface-prepare', status }
      const result = fieldBytes(fields, 7)
      if (result) return { kind: 'watchface-result', code: fieldNumber(decodeFields(result), 2) ?? -1 }
    }
  }

  if (type === 20) {
    const payload = fieldBytes(wear, 22)
    if (payload) {
      const fields = decodeFields(payload)
      const response = fieldBytes(fields, 3)
      if (response) return { kind: 'app-prepare', status: fieldNumber(decodeFields(response), 1) ?? -1 }
      const result = fieldBytes(fields, 4)
      if (result) return { kind: 'app-result', code: fieldNumber(decodeFields(result), 1) ?? -1 }
    }
  }

  if (type === 2) {
    const payload = fieldBytes(wear, 4)
    if (payload) {
      const fields = decodeFields(payload)
      const response = fieldBytes(fields, 17)
      if (response) return { kind: 'firmware-prepare', status: fieldNumber(decodeFields(response), 1) ?? -1 }
      const info = fieldBytes(fields, 3)
      if (info) {
        const values = decodeFields(info)
        return {
          kind: 'device-info',
          data: {
            serialNumber: textField(values, 1),
            firmwareVersion: textField(values, 2),
            imei: textField(values, 3),
            model: textField(values, 4),
            productDevice: textField(values, 5)
          }
        }
      }
      const status = fieldBytes(fields, 2)
      if (status) {
        const battery = fieldBytes(decodeFields(status), 1)
        const values = battery ? decodeFields(battery) : []
        return { kind: 'device-status', data: { battery: fieldNumber(values, 1) ?? 0, chargeStatus: fieldNumber(values, 2) ?? 0 } }
      }
      const storage = fieldBytes(fields, 44)
      if (storage) {
        const values = decodeFields(storage)
        return { kind: 'storage-info', data: { used: fieldNumber(values, 1) ?? 0, total: fieldNumber(values, 2) ?? 0 } }
      }
    }
  }

  if (type === 22) {
    const payload = fieldBytes(wear, 24)
    const response = payload && fieldBytes(decodeFields(payload), 2)
    if (response) {
      const fields = decodeFields(response)
      return {
        kind: 'mass-prepare',
        status: fieldNumber(fields, 2) ?? -1,
        remainedDataLength: fieldNumber(fields, 4) ?? 0,
        expectedSliceLength: fieldNumber(fields, 5) ?? 0
      }
    }
  }

  if (type === 4 && id === 0) {
    const payload = fieldBytes(wear, 6)
    const list = payload && fieldBytes(decodeFields(payload), 1)
    if (list) return { kind: 'watchface-list', data: parseWatchfaceItems(payload) }
  }

  if (type === 20 && id === 0) {
    const payload = fieldBytes(wear, 22)
    const list = payload && fieldBytes(decodeFields(payload), 1)
    if (list) return { kind: 'app-list', data: parseAppItems(payload) }
  }

  return { kind: 'unknown', type, id }
}
