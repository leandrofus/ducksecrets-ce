import { useEffect, useState } from 'react'
import { invalidate } from './store'

// Live updates: the gateway sends {type, id} when something changes
// (note.changed) and the cached resources of that type refetch.
// WebSocket, reconnecting with backoff.

export type LiveState = 'connecting' | 'live' | 'offline'
type Ev = { type: string; id?: string }

let state: LiveState = 'connecting'
const listeners = new Set<() => void>()
const eventListeners = new Set<(ev: Ev) => void>()
export function onLiveEvent(fn: (ev: Ev) => void) {
  eventListeners.add(fn)
  return () => {
    eventListeners.delete(fn)
  }
}
const setState = (s: LiveState) => {
  state = s
  listeners.forEach((l) => l())
}

// Which API path an event's object type lives under.
const PATHS: Record<string, string> = {
  project: '/projects',
  secret: '/projects',
  // ducktpl:live
}

function onEvent(ev: Ev) {
  const kind = ev.type.split('.')[0] // project.changed → project
  invalidate(PATHS[kind] ?? `/${kind}s`)
  eventListeners.forEach((fn) => fn(ev))
}

let started = false
let activeWS: WebSocket | null = null
let reconnectTimer: ReturnType<typeof setTimeout> | null = null

export function stopLive() {
  started = false
  if (reconnectTimer !== null) {
    clearTimeout(reconnectTimer)
    reconnectTimer = null
  }
  if (activeWS) {
    activeWS.onopen = null
    activeWS.onmessage = null
    activeWS.onclose = null
    try {
      activeWS.close()
    } catch {}
    activeWS = null
  }
  setState('offline')
}

export function startLive(onUnauthorized?: () => void) {
  if (started) return
  started = true
  let delay = 1000

  const scheduleReconnect = () => {
    if (!started || reconnectTimer !== null) return
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null
      connect()
    }, delay)
    delay = Math.min(delay * 2, 30000)
  }

  const connect = () => {
    if (!started) return
    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/v1/ws`)
    activeWS = ws
    ws.onopen = () => {
      delay = 1000
      setState('live')
      invalidate() // catch up on what changed while away
    }
    ws.onmessage = (m) => {
      try {
        const parsed = JSON.parse(m.data)
        if (parsed && typeof parsed.type === 'string') {
          onEvent(parsed)
        }
      } catch {
        // Ignore malformed server push payloads
      }
    }
    ws.onclose = () => {
      if (activeWS === ws) activeWS = null
      setState('offline')
      if (!started) return
      fetch('/api/v1/auth/me', { credentials: 'same-origin' })
        .then((res) => {
          if (res.status === 401) {
            stopLive()
            onUnauthorized?.()
            return
          }
          scheduleReconnect()
        })
        .catch(() => {
          scheduleReconnect()
        })
    }
  }
  connect()
}

export function useLive(): LiveState {
  const [, f] = useState(0)
  useEffect(() => {
    const l = () => f((n) => n + 1)
    listeners.add(l)
    return () => {
      listeners.delete(l)
    }
  }, [])
  return state
}
