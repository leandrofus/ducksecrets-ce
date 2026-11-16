import { useCallback, useEffect, useState } from 'react'
import { api, enc } from './api'
import type {
  DynamicLease,
  DynamicProvider,
  Environment,
  Project,
  ProjectList,
  RotationPolicy,
  SecretList,
  ServiceToken,
  Site,
} from './api'
import { useResource } from './store'

export interface FleetSite extends Site {
  project_name: string
  project_slug: string
}

export interface FleetToken extends ServiceToken {
  project_name: string
  project_slug: string
}

export interface FleetProvider extends DynamicProvider {
  project_name: string
  project_slug: string
}

export interface FleetLease extends DynamicLease {
  project_id: string
  project_name: string
  project_slug: string
  environment_slug: string
  provider_name: string
  engine: string
}

export interface FleetRotation extends RotationPolicy {
  project_id: string
  project_name: string
  project_slug: string
  environment_slug: string
}

export interface FleetOptions {
  sites?: boolean
  tokens?: boolean
  providers?: boolean
  leases?: boolean
  rotations?: boolean
  secretsCount?: boolean
}

export interface FleetState {
  projects: Project[]
  sites: FleetSite[]
  tokens: FleetToken[]
  providers: FleetProvider[]
  leases: FleetLease[]
  rotations: FleetRotation[]
  envCount: number
  secretCount: number
  loading: boolean
  error: Error | null
  refresh: () => void
}

export function isLeaseActive(lease: Pick<DynamicLease, 'revoked_at' | 'expires_at'>): boolean {
  if (lease.revoked_at) return false
  return new Date(lease.expires_at).getTime() > Date.now()
}

export function isTokenActive(tok: Pick<ServiceToken, 'burned_at' | 'expires_at'>): boolean {
  if (tok.burned_at) return false
  if (tok.expires_at && new Date(tok.expires_at).getTime() <= Date.now()) return false
  return true
}

/**
 * Aggregates project-scoped resources across all accessible projects using the
 * existing per-project endpoints so RBAC permissions are respected per resource.
 */
export function useFleetInventory(opts: FleetOptions): FleetState {
  const { data: projectList, error: projErr, loading: projLoading } = useResource<ProjectList>('/projects')
  const [tick, setTick] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const [snapshot, setSnapshot] = useState<Omit<FleetState, 'projects' | 'loading' | 'error' | 'refresh'>>({
    sites: [],
    tokens: [],
    providers: [],
    leases: [],
    rotations: [],
    envCount: 0,
    secretCount: 0,
  })

  const refresh = useCallback(() => setTick((t) => t + 1), [])

  const projects = projectList?.items || []
  const wantSites = Boolean(opts.sites)
  const wantTokens = Boolean(opts.tokens)
  const wantProviders = Boolean(opts.providers || opts.leases)
  const wantLeases = Boolean(opts.leases)
  const wantRotations = Boolean(opts.rotations)
  const wantSecrets = Boolean(opts.secretsCount)
  const needEnvs = wantProviders || wantRotations || wantSecrets

  useEffect(() => {
    if (!projectList) return
    let cancelled = false
    setLoading(true)
    setError(null)

    const run = async () => {
      const nextSites: FleetSite[] = []
      const nextTokens: FleetToken[] = []
      const nextProviders: FleetProvider[] = []
      const nextLeases: FleetLease[] = []
      const nextRotations: FleetRotation[] = []
      let nextEnvs = 0
      let nextSecrets = 0

      await Promise.allSettled(
        projects.map(async (proj) => {
          const base = { project_name: proj.name, project_slug: proj.slug }
          const tasks: Promise<void>[] = []

          if (wantSites) {
            tasks.push(
              api.get<Site[]>(`/projects/${enc(proj.id)}/sites`).then((items) => {
                for (const s of items || []) nextSites.push({ ...s, ...base })
              }),
            )
          }

          if (wantTokens) {
            tasks.push(
              api.get<ServiceToken[]>(`/projects/${enc(proj.id)}/tokens`).then((items) => {
                for (const tk of items || []) nextTokens.push({ ...tk, ...base })
              }),
            )
          }

          if (needEnvs) {
            tasks.push(
              api.get<Environment[]>(`/projects/${enc(proj.id)}/environments`).then(async (envs) => {
                const envList = envs || []
                nextEnvs += envList.length
                await Promise.allSettled(
                  envList.map(async (env) => {
                    const envTasks: Promise<void>[] = []

                    if (wantSecrets) {
                      envTasks.push(
                        api
                          .get<SecretList>(`/projects/${enc(proj.id)}/environments/${enc(env.slug)}/secrets`)
                          .then((res) => {
                            nextSecrets += res?.total ?? res?.items?.length ?? 0
                          }),
                      )
                    }

                    if (wantRotations) {
                      envTasks.push(
                        api
                          .get<RotationPolicy[]>(`/projects/${enc(proj.id)}/environments/${enc(env.slug)}/rotation`)
                          .then((items) => {
                            for (const r of items || []) {
                              nextRotations.push({
                                ...r,
                                project_id: proj.id,
                                ...base,
                                environment_slug: env.slug,
                              })
                            }
                          }),
                      )
                    }

                    if (wantProviders) {
                      envTasks.push(
                        api
                          .get<DynamicProvider[]>(`/projects/${enc(proj.id)}/environments/${enc(env.slug)}/dynamic`)
                          .then(async (items) => {
                            const provs = items || []
                            for (const p of provs) nextProviders.push({ ...p, ...base })
                            if (wantLeases) {
                              await Promise.allSettled(
                                provs.map((p) =>
                                  api
                                    .get<DynamicLease[]>(
                                      `/projects/${enc(proj.id)}/environments/${enc(env.slug)}/dynamic/${enc(p.id)}/leases`,
                                    )
                                    .then((leaseItems) => {
                                      for (const l of leaseItems || []) {
                                        nextLeases.push({
                                          ...l,
                                          project_id: proj.id,
                                          ...base,
                                          environment_slug: env.slug,
                                          provider_name: p.name,
                                          engine: p.engine,
                                        })
                                      }
                                    }),
                                ),
                              )
                            }
                          }),
                      )
                    }

                    await Promise.allSettled(envTasks)
                  }),
                )
              }),
            )
          }

          await Promise.allSettled(tasks)
        }),
      )

      if (cancelled) return
      nextSites.sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name))
      nextTokens.sort((a, b) => b.created_at.localeCompare(a.created_at))
      nextProviders.sort((a, b) => a.name.localeCompare(b.name))
      nextLeases.sort((a, b) => b.created_at.localeCompare(a.created_at))
      nextRotations.sort((a, b) => a.next_rotation_at.localeCompare(b.next_rotation_at))
      setSnapshot({
        sites: nextSites,
        tokens: nextTokens,
        providers: nextProviders,
        leases: nextLeases,
        rotations: nextRotations,
        envCount: nextEnvs,
        secretCount: nextSecrets,
      })
      setLoading(false)
    }

    run().catch((err) => {
      if (cancelled) return
      setError(err instanceof Error ? err : new Error(String(err)))
      setLoading(false)
    })

    return () => {
      cancelled = true
    }
  }, [projectList, tick, wantSites, wantTokens, wantProviders, wantLeases, wantRotations, wantSecrets, needEnvs])

  return {
    projects,
    ...snapshot,
    loading: projLoading || loading,
    error: projErr || error,
    refresh,
  }
}
