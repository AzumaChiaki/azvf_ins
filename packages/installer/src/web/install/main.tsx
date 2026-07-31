import React, { useState } from 'react'
import { createRoot } from 'react-dom/client'
import { InstallApp } from './InstallApp.js'
import { BrowserNotice, didBypassBrowserCheck } from '../BrowserNotice.js'
import '@azvf/ui/styles.css'

declare global {
  interface Window {
    __APP_MOUNTED__?: boolean
    __azBootFailed?: () => void
  }
}

function Root() {
  const serialSupported = typeof navigator !== 'undefined' && 'serial' in navigator
  const [bypassed, setBypassed] = useState(() => !serialSupported && didBypassBrowserCheck())

  if (serialSupported || bypassed) return <InstallApp />
  return <BrowserNotice onBypass={() => setBypassed(true)} />
}

const rootElement = document.getElementById('root')
if (rootElement) {
  try {
    createRoot(rootElement).render(
      <React.StrictMode><Root /></React.StrictMode>,
    )
    window.__APP_MOUNTED__ = true
  } catch {
    window.__azBootFailed?.()
  }
}
