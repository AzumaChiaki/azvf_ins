import { runtimeConfig } from '@azvf/ui/runtime-config'

/**
 * 安装页页脚。三项内容都是必需的：返回核销页的入口、本程序的源码地址，以及
 * 上游项目署名。地址全部来自运行时配置。
 */
export function InstallFooter() {
  return (
    <footer className="az-footer">
      <div className="az-footer-panel">
        <div className="az-footer-grid">
          <div className="az-footer-col">
            <span className="az-footer-title">导航</span>
            <a className="az-footer-link" href={runtimeConfig.redeemUrl}>返回核销页</a>
          </div>
          <div className="az-footer-col">
            <span className="az-footer-title">源代码</span>
            <a className="az-footer-link" href={runtimeConfig.sourceUrl} target="_blank" rel="noopener">
              获取本程序的完整源代码 ↗
            </a>
            <span className="az-footer-desc">本程序以 GNU AGPL-3.0 授权发布。</span>
          </div>
          <div className="az-footer-col">
            <span className="az-footer-title">上游项目署名</span>
            {runtimeConfig.upstream.map((item) => (
              <a key={item.url} className="az-footer-link" href={item.url} target="_blank" rel="noopener">
                {item.name} ↗
              </a>
            ))}
          </div>
        </div>
        <div className="az-footer-bottom">
          <span className="az-footer-copyright">
            本程序基于 AstroBox-NG（AGPL-3.0，含署名附加条款）实现的设备通信协议。
          </span>
        </div>
      </div>
    </footer>
  )
}
