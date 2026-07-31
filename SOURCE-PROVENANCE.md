# Source provenance

The MiWear transport implementation in `packages/installer/src/web/miwear/`
is a TypeScript adaptation informed by AstroBox-NG and its module repositories.
The reviewed upstream revisions are recorded in `NOTICE`.

Known direct adaptation:

- `sar.ts` corresponds to the layer-1/layer-2 packet definitions in
  `AstroBox-NG-Module-Core` under
  `src/device/xiaomi/packet/v2/{layer1,layer2}.rs`.

Files requiring symbol-level evidence before a public release:

- `bytes.ts`
- `crypto.ts`
- `protobuf.ts`
- `session.ts`

This repository remains private until that evidence and the release checklist
are complete. `packages/reference-authorizer` is an original interoperability
fixture and is not production authorization software.
