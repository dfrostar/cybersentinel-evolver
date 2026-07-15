import { registerSW } from 'virtual:pwa-register'

export function registerServiceWorker() {
  // Don't register in dev unless explicitly wanted
  if (import.meta.env.DEV) return

  // Check for updates every hour
  registerSW({
    onOfflineReady() {
      console.log('[PWA] App ready to work offline')
    },
    onNeedRefresh() {
      console.log('[PWA] New content available, refresh to update')
    },
  })
}
