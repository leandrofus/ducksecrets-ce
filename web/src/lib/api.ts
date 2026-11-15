import { getLang } from '../i18n'
import type { components } from './api-types'

// Thin client for the gateway's /api/v1. Types come from the OpenAPI
// contract (make generate: Go comments → openapi.yaml → api-types.ts), so a
// changed DTO breaks the build here, not at runtime.

export type Schemas = components['schemas']
export interface Page<T> {
  items: T[]
  total: number
  page: number
  per_page: number
}

// ducktpl:types
export type Project = Schemas['Project']
export type ProjectList = Schemas['ProjectList']
export type ProjectPolicy = Schemas['ProjectPolicy']
export type CreateProjectPolicyRequest = Schemas['CreateProjectPolicyRequest']
export type UpdateProjectPolicyRequest = Schemas['UpdateProjectPolicyRequest']
export type Environment = Schemas['Environment']
export type Secret = Schemas['Secret']
export type SecretList = Schemas['SecretList']
export type SecretVersion = Schemas['SecretVersion']
export type SecretVersionList = Schemas['SecretVersionList']
export type ServiceToken = Schemas['ServiceToken']
export type CreatedServiceToken = Schemas['CreatedServiceToken']
export type ShareCreated = Schemas['ShareCreated']
export type ShareMetadata = Schemas['ShareMetadata']
export type ShareReveal = Schemas['ShareReveal']
export type CreateShareRequest = Schemas['CreateShareRequest']
export type DynamicProvider = Schemas['DynamicProvider']
export type CreateDynamicProviderRequest = Schemas['CreateDynamicProviderRequest']
export type DynamicLease = Schemas['DynamicLease']
export type IssuedLease = Schemas['IssuedLease']
export type TestProviderResponse = Schemas['TestProviderResponse']
export type RotationPolicy = Schemas['RotationPolicy']
export type SetRotationPolicyRequest = Schemas['SetRotationPolicyRequest']
export type RotationRunResponse = Schemas['RotationRunResponse']
export type ImportSecretsResponse = Schemas['ImportSecretsResponse']
export type ImportSecretItem = Schemas['ImportSecretItem']
export type Site = Schemas['Site']
export type CreatedSite = Schemas['CreatedSite']
export type CreateSiteRequest = Schemas['CreateSiteRequest']
export type DatabaseInfo = Schemas['DatabaseInfo']
export type TestDatabaseResponse = Schemas['TestDatabaseResponse']
export type MigrateDatabaseResponse = Schemas['MigrateDatabaseResponse']
export type LicenseStatus = Schemas['LicenseStatus']
export type LicenseFeature = Schemas['LicenseFeature']
export type UpdateLicenseRequest = Schemas['UpdateLicenseRequest']
export type UpdateStatus = Schemas['UpdateStatus']
export type ApplyUpdateResponse = Schemas['ApplyUpdateResponse']
export type SetupStatus = Schemas['SetupStatus']
export type TLSStatus = Schemas['TLSStatus']
export type User = Schemas['User']
export type PaginatedUsers = Schemas['PaginatedUsers']
export type Me = Schemas['Me']
export type Role = Schemas['Role']
export type Grant = Schemas['Grant']
export type Permission = Schemas['Permission']
export type AuditEvent = Schemas['AuditEvent']
export type PaginatedAuditEvents = Schemas['PaginatedAuditEvents']

export class ApiError extends Error {
  status: number
  code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

let onUnauthorized: () => void = () => {}
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}
export function triggerUnauthorized() {
  onUnauthorized()
}

const noRedirect = ['/auth/login', '/auth/me']

// X-Ducksecrets-Request: required on every state-changing request (CSRF).
const CSRF = { 'X-Ducksecrets-Request': '1' }

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch('/api/v1' + path, {
    method,
    headers: { ...CSRF, 'Accept-Language': getLang(), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  })
  if (res.status === 401 && !noRedirect.includes(path)) onUnauthorized()
  const text = await res.text()
  let data: any = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = text
  }
  if (!res.ok) throw new ApiError(res.status, data?.error || 'error', data?.message || data?.error || res.statusText)
  return data as T
}

export const api = {
  get: <T = any>(p: string) => request<T>('GET', p),
  post: <T = any>(p: string, body?: unknown) => request<T>('POST', p, body),
  put: <T = any>(p: string, body?: unknown) => request<T>('PUT', p, body),
  patch: <T = any>(p: string, body: unknown) => request<T>('PATCH', p, body),
  del: <T = any>(p: string, body?: unknown) => request<T>('DELETE', p, body),
}

export const enc = encodeURIComponent

