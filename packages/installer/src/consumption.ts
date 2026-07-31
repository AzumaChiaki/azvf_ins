import { createHash } from 'node:crypto'

/**
 * A signed grant may intentionally contain several resources. Bind its
 * one-shot replay key to the selected resource so each authorized resource is
 * installable once, while the same JWT cannot replay the same resource.
 */
export function resourceConsumptionId(tokenJti: string, resourceId: string): string {
  return createHash('sha256')
    .update('AZVF/install-consumption/v1\0', 'utf8')
    .update(tokenJti, 'utf8')
    .update('\0', 'utf8')
    .update(resourceId, 'utf8')
    .digest('base64url')
}
