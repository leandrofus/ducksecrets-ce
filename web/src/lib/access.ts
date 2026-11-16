import { can } from './session'

// May the signed-in user do this? The server decides; this hides what it would refuse.
export const allowed = (perm?: string) => !perm || can(perm)
