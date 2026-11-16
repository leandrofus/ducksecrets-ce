export interface SecretBundleItem {
  key: string
  value: string
  comment?: string
}

export interface SecretBundlePayload {
  __ducksecrets_bundle: boolean
  version?: number
  title?: string
  project?: string
  environment?: string
  created_at?: string
  secrets: SecretBundleItem[]
}

export interface ParsedSecretItem {
  id: string
  key: string
  value: string
  comment?: string
  selected: boolean
}

export function parseEnvContent(raw: string): Omit<ParsedSecretItem, 'id' | 'selected'>[] {
  const trimmed = raw.trim()
  if (!trimmed) return []

  // Check if JSON object
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const obj = JSON.parse(trimmed)
      return Object.entries(obj).map(([k, v]) => ({
        key: k.trim(),
        value: typeof v === 'object' ? JSON.stringify(v) : String(v),
      }))
    } catch {}
  }

  // Parse lines (.env / dotenv)
  const lines = raw.split(/\r?\n/)
  const result: Omit<ParsedSecretItem, 'id' | 'selected'>[] = []
  let pendingComment = ''

  for (let line of lines) {
    line = line.trim()
    if (!line) {
      pendingComment = ''
      continue
    }
    if (line.startsWith('#')) {
      pendingComment = line.replace(/^#+\s*/, '')
      continue
    }
    // Strip "export " prefix
    if (line.startsWith('export ')) {
      line = line.slice(7).trim()
    }
    const eqIdx = line.indexOf('=')
    const colonIdx = line.indexOf(':')

    let key = ''
    let val = ''

    const useColon =
      colonIdx !== -1 &&
      (eqIdx === -1 || colonIdx < eqIdx) &&
      /^[a-zA-Z_][a-zA-Z0-9_.-]*$/.test(line.slice(0, colonIdx).trim())

    if (useColon) {
      key = line.slice(0, colonIdx).trim()
      val = line.slice(colonIdx + 1).trim()
    } else if (eqIdx !== -1) {
      key = line.slice(0, eqIdx).trim()
      val = line.slice(eqIdx + 1).trim()
    } else if (colonIdx !== -1) {
      key = line.slice(0, colonIdx).trim()
      val = line.slice(colonIdx + 1).trim()
    } else {
      continue
    }

    // Strip surrounding quotes
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      const quote = val[0]
      val = val.slice(1, -1)
      if (quote === '"') {
        val = val.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"')
      }
    }

    if (key) {
      result.push({
        key,
        value: val,
        comment: pendingComment || undefined,
      })
      pendingComment = ''
    }
  }

  return result
}

export function isSecretBundlePayload(plain: string): SecretBundlePayload | null {
  try {
    const parsed = JSON.parse(plain)
    if (
      parsed &&
      typeof parsed === 'object' &&
      !Array.isArray(parsed) &&
      parsed.__ducksecrets_bundle === true &&
      Array.isArray(parsed.secrets)
    ) {
      return parsed as SecretBundlePayload
    }
  } catch {}
  return null
}

export function formatBundleAsEnv(bundleOrItems: SecretBundlePayload | SecretBundleItem[]): string {
  const items = Array.isArray(bundleOrItems) ? bundleOrItems : bundleOrItems.secrets
  return items
    .map((s) => {
      const val =
        s.value.includes('\n') || s.value.includes(' ') || s.value.includes('"')
          ? `"${s.value.replace(/"/g, '\\"')}"`
          : s.value
      return `${s.key}=${val}`
    })
    .join('\n')
}

export function formatBundleAsJson(bundleOrItems: SecretBundlePayload | SecretBundleItem[]): string {
  const items = Array.isArray(bundleOrItems) ? bundleOrItems : bundleOrItems.secrets
  const obj: Record<string, string> = {}
  items.forEach((s) => {
    obj[s.key] = s.value
  })
  return JSON.stringify(obj, null, 2)
}
