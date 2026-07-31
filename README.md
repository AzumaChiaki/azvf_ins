# AZVF Installer

开源的流式设备安装器，基于纯 TypeScript 实现 MiWear 通信与分片安装。项目以
GNU AGPL-3.0-only 授权，并遵守上游 AstroBox-NG 的署名附加要求。

上游署名：

- AstroBox-NG — AstralSight Studios:
  <https://github.com/AstralSightStudios/AstroBox-NG>
- AstroBox-NG-Module-Core:
  <https://github.com/AstralSightStudios/AstroBox-NG-Module-Core>
- AstroBox-NG-Module-AppWasm:
  <https://github.com/AstralSightStudios/AstroBox-NG-Module-AppWasm>
- AstroBox-NG-Module-Pb:
  <https://github.com/AstralSightStudios/AstroBox-NG-Module-Pb>

详细来源、固定 commit 与移植范围见 [NOTICE](NOTICE) 和
[SOURCE-PROVENANCE.md](SOURCE-PROVENANCE.md)。

## 资源作者权益保护声明

AZVF 提供的是设备通信与分片安装协议的实现，用于按授权安装资源；本项目的存在
不代表、也不构成对绕过资源作者授权控制、破解付费资源、或未经授权二次分发资源
行为的许可或背书。

本项目著作权人明确反对并不鼓励任何人利用本项目实施包括但不限于破解、逆向工程、
绕过授权校验、盗版分发等侵犯资源作者合法权益的行为。此类使用超出本项目许可证
授权的本意范围；著作权人保留在著作权法及其他适用法律允许的范围内，对相关侵权
行为追究法律责任、拒绝提供后续协助与支持的权利。

本项目采用 GNU AGPL-3.0-only 严格授权，使用者获得的权利始终以该许可证条款为
准；上述声明是著作权人对滥用行为的态度表达和权利保留，不改变许可证本身对代码
使用、修改、分发所约定的条款。

## 包结构

- `packages/contract`：线协议与签名资源契约；
- `packages/ui`：无业务语义的视觉基础；
- `packages/installer`：安装服务与浏览器安装页；
- `packages/reference-authorizer`：本地演示授权器，不用于生产。

## 本地验证

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm verify
```

`pnpm verify` 会执行独立构建、类型检查、全部测试、跨仓 golden vector 校验、
商业边界扫描、秘密扫描、许可证清单、CycloneDX SBOM 和双进程启动烟测。

## 生成式人工智能代码使用情况

本项目部分代码由 Claude Opus 5、GPT-5.6-sol 等生成式人工智能工具辅助生成，
经人工审阅后纳入。
