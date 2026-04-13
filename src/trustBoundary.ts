/**
 * classifyTrustBoundary — determines the trust boundary category for a
 * NeuralMap node based on its type and subtype.
 *
 * Trust boundaries are security-relevant zone transitions. A chain that
 * crosses multiple boundaries is more severe than one that stays within
 * a single zone.
 */

export function classifyTrustBoundary(
  nodeType: string,
  subtype: string,
): string {
  if (nodeType === 'INGRESS') {
    if (subtype === 'env_read') return 'environment';
    if (subtype === 'file_read') return 'filesystem';
    return 'network_external';
  }

  if (nodeType === 'STORAGE') {
    if (/file/.test(subtype)) return 'filesystem';
    return 'storage';
  }

  if (nodeType === 'EXTERNAL') {
    if (subtype === 'system_exec') return 'subprocess';
    return 'network_external';
  }

  if (nodeType === 'EGRESS') {
    if (/file/.test(subtype)) return 'filesystem';
    return 'network_external';
  }

  if (nodeType === 'META') return 'app_config';
  if (nodeType === 'AUTH') return 'auth';
  if (nodeType === 'RESOURCE') return 'subprocess';

  return '';
}
