import { useState } from 'react'
import { runtimeConfig } from '@azvf/ui/runtime-config'

/**
 * 安装页页脚。所有法律/源代码链接与上游署名收进「开源项目许可」弹窗，
 * 页脚底部只保留版权信息（含许可证要求的 AstroBox-NG 署名），不再散落
 * 链接列；返回核销页入口在页面顶部页眉处（见 InstallApp）。
 */
export function InstallFooter() {
  const [showLicenses, setShowLicenses] = useState(false)
  return (
    <>
      <footer className="az-footer">
        <div className="az-footer-panel">
          <div className="az-footer-bottom">
            <span className="az-footer-copyright">
              本程序基于 AstroBox-NG（AGPL-3.0，含署名附加条款）实现的设备通信协议。
            </span>
            <button type="button" className="az-footer-linkbtn" onClick={() => setShowLicenses(true)}>
              开源项目许可
            </button>
          </div>
        </div>
      </footer>
      {showLicenses && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="开源项目许可" onClick={() => setShowLicenses(false)}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-head">
              <h3>开源项目许可</h3>
              <button type="button" onClick={() => setShowLicenses(false)} aria-label="关闭">关闭</button>
            </div>
            <p className="modal-intro">
              本程序以 GNU AGPL-3.0 授权发布（含署名附加条款）。以下为本程序的源代码地址与上游项目署名。
            </p>
            <div className="license-section">
              <span className="az-footer-title">源代码</span>
              <a className="az-footer-link" href={runtimeConfig.sourceUrl} target="_blank" rel="noopener">
                获取本程序的完整源代码 ↗
              </a>
            </div>
            <div className="license-section">
              <span className="az-footer-title">上游项目署名</span>
              {runtimeConfig.upstream.map((item) => (
                <a key={item.url} className="az-footer-link" href={item.url} target="_blank" rel="noopener">
                  {item.name} ↗
                </a>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  )
}
