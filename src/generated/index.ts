/**
 * DST Generated Verifiers — Index
 * Re-exports all generated verifier batches and provides a unified registry.
 *
 * All entries are real verifiers (graph-pattern BFS, can detect vulnerabilities).
 * Stub CWEs (deprecated, categories, views, pillars, SFP clusters) have been
 * removed — they inflated the count dishonestly.
 *
 * IMPORTANT: Generated verifiers that have hand-written overrides in verifier.ts
 * are filtered out via HAND_WRITTEN_OVERRIDES below. This eliminates 385 shadowed
 * entries that were loaded but never executed (the hand-written versions always
 * took precedence via JS spread semantics). Only one version of each CWE now
 * exists in the final registry.
 */

export * from './_helpers';
export * from './batch_001';
export * from './batch_002';
export * from './batch_003';
export * from './batch_004';
export * from './batch_005';
export * from './batch_006';
export * from './batch_007';
export * from './batch_008';
export * from './batch_009';
export * from './batch_010';
export * from './batch_011';
export * from './batch_012';
export * from './batch_013';
export * from './batch_014';
export * from './batch_015';
export * from './batch_016';
export * from './batch_017';
export * from './batch_018';
export * from './batch_019';
export * from './batch_020';
export * from './batch_021';
export * from './batch_crypto_B2';
export * from './batch_crypto_A2';
import { BATCH_001_REGISTRY } from './batch_001';
import { BATCH_002_REGISTRY } from './batch_002';
import { BATCH_003_REGISTRY } from './batch_003';
import { BATCH_004_REGISTRY } from './batch_004';
import { BATCH_005_REGISTRY } from './batch_005';
import { BATCH_006_REGISTRY } from './batch_006';
import { BATCH_007_REGISTRY } from './batch_007';
import { BATCH_008_REGISTRY } from './batch_008';
import { BATCH_009_REGISTRY } from './batch_009';
import { BATCH_010_REGISTRY } from './batch_010';
import { BATCH_011_REGISTRY } from './batch_011';
import { BATCH_012_REGISTRY } from './batch_012';
import { BATCH_013_REGISTRY } from './batch_013';
import { BATCH_014_REGISTRY } from './batch_014';
import { BATCH_015_REGISTRY } from './batch_015';
import { BATCH_016_REGISTRY } from './batch_016';
import { BATCH_017_REGISTRY } from './batch_017';
import { BATCH_018_REGISTRY } from './batch_018';
import { BATCH_019_REGISTRY } from './batch_019';
import { BATCH_020_REGISTRY } from './batch_020';
import { BATCH_021_REGISTRY } from './batch_021';
import { BATCH_CRYPTO_B2_REGISTRY } from './batch_crypto_B2';
import { BATCH_CRYPTO_A2_REGISTRY } from './batch_crypto_A2';
import type { NeuralMap } from '../types';
import type { VerificationResult } from './_helpers';

/**
 * CWEs that have hand-written overrides in verifier.ts.
 * These are excluded from GENERATED_REGISTRY so only the hand-written
 * version is loaded — no shadowed dead code, no false-positive noise.
 *
 * To update: if you add a new hand-written verifier in verifier.ts for a CWE
 * that also has a generated version, add its key here.
 */
const HAND_WRITTEN_OVERRIDES: ReadonlySet<string> = new Set([
  // --- Injection, traversal, deserialization, SSRF, config control ---
  'CWE-15', 'CWE-20', 'CWE-22', 'CWE-23', 'CWE-36', 'CWE-74', 'CWE-77', 'CWE-78', 'CWE-79', 'CWE-81', 'CWE-83', 'CWE-89',
  'CWE-90', 'CWE-91', 'CWE-93', 'CWE-94', 'CWE-95', 'CWE-96', 'CWE-98',
  'CWE-99', 'CWE-111', 'CWE-114', 'CWE-116', 'CWE-117', 'CWE-134', 'CWE-158', 'CWE-170',
  'CWE-176', 'CWE-177', 'CWE-178', 'CWE-179', 'CWE-180', 'CWE-182',
  'CWE-183', 'CWE-185', 'CWE-186', 'CWE-187', 'CWE-188', 'CWE-192',
  'CWE-193', 'CWE-194', 'CWE-195', 'CWE-196', 'CWE-197', 'CWE-198', 'CWE-681',
  // --- Memory safety, arithmetic & array index ---
  'CWE-119', 'CWE-120', 'CWE-125', 'CWE-126', 'CWE-127', 'CWE-129', 'CWE-131',
  'CWE-190', 'CWE-191', 'CWE-369', 'CWE-476',
  // --- Side channel, error handling & info exposure ---
  'CWE-207', 'CWE-208', 'CWE-209', 'CWE-210', 'CWE-211', 'CWE-212',
  'CWE-213', 'CWE-214', 'CWE-215', 'CWE-222', 'CWE-223', 'CWE-224',
  'CWE-226', 'CWE-243', 'CWE-244', 'CWE-245', 'CWE-246', 'CWE-248',
  'CWE-252', 'CWE-253',
  // --- Sensitive data exposure ---
  'CWE-200', 'CWE-256', 'CWE-257', 'CWE-260', 'CWE-261', 'CWE-312',
  'CWE-313', 'CWE-314', 'CWE-315', 'CWE-316', 'CWE-319',
  // --- Privilege & permission ---
  'CWE-250', 'CWE-266', 'CWE-268', 'CWE-269', 'CWE-270', 'CWE-271',
  'CWE-272', 'CWE-273', 'CWE-274', 'CWE-276', 'CWE-277', 'CWE-279',
  // --- Access control & authentication ---
  'CWE-280', 'CWE-282', 'CWE-283', 'CWE-284', 'CWE-285', 'CWE-286',
  'CWE-287', 'CWE-288', 'CWE-289', 'CWE-290', 'CWE-291', 'CWE-294',
  'CWE-295', 'CWE-296', 'CWE-297', 'CWE-302', 'CWE-304', 'CWE-305',
  'CWE-306', 'CWE-307', 'CWE-308', 'CWE-309', 'CWE-311', 'CWE-317',
  'CWE-318', 'CWE-321', 'CWE-322',
  // --- Crypto & randomness ---
  'CWE-323', 'CWE-324', 'CWE-325', 'CWE-326', 'CWE-327', 'CWE-328',
  'CWE-329', 'CWE-330', 'CWE-331', 'CWE-335', 'CWE-336', 'CWE-337',
  'CWE-338', 'CWE-339', 'CWE-340', 'CWE-347', 'CWE-354', 'CWE-757',
  'CWE-759', 'CWE-760', 'CWE-916',
  // --- Predictability, UI security, trust boundary ---
  'CWE-341', 'CWE-342', 'CWE-343', 'CWE-344', 'CWE-351', 'CWE-355',
  'CWE-357', 'CWE-358', 'CWE-360',
  // --- Data authenticity & privacy ---
  'CWE-345', 'CWE-346', 'CWE-348', 'CWE-349', 'CWE-350', 'CWE-352',
  'CWE-353', 'CWE-356', 'CWE-359', 'CWE-402',
  // --- Race conditions & object mutability ---
  'CWE-362', 'CWE-363', 'CWE-364', 'CWE-365', 'CWE-366', 'CWE-367',
  'CWE-368', 'CWE-370', 'CWE-372', 'CWE-374', 'CWE-375', 'CWE-385',
  'CWE-386',
  // --- Concurrency, temp file, search path ---
  'CWE-377', 'CWE-378', 'CWE-379', 'CWE-382', 'CWE-383', 'CWE-384',
  'CWE-426', 'CWE-427', 'CWE-428', 'CWE-668',
  // --- Error handling & resource management ---
  'CWE-390', 'CWE-391', 'CWE-392', 'CWE-393', 'CWE-394', 'CWE-395',
  'CWE-396', 'CWE-397', 'CWE-401', 'CWE-403',
  // --- Resource CWEs ---
  'CWE-400', 'CWE-404', 'CWE-405', 'CWE-406', 'CWE-407', 'CWE-409',
  'CWE-410', 'CWE-770', 'CWE-771', 'CWE-772', 'CWE-775', 'CWE-1333',
  // --- Memory corruption & code quality ---
  'CWE-415', 'CWE-416', 'CWE-456', 'CWE-457', 'CWE-459', 'CWE-460',
  'CWE-462', 'CWE-463', 'CWE-464', 'CWE-467', 'CWE-468', 'CWE-469',
  'CWE-475', 'CWE-478', 'CWE-480', 'CWE-481', 'CWE-482', 'CWE-483',
  'CWE-484', 'CWE-486', 'CWE-489', 'CWE-491', 'CWE-495', 'CWE-496',
  'CWE-499',
  // --- Channel security & deployment ---
  'CWE-419', 'CWE-420', 'CWE-421', 'CWE-424', 'CWE-425', 'CWE-430',
  'CWE-431', 'CWE-432', 'CWE-433', 'CWE-439',
  // --- Access control, injection & file handling ---
  'CWE-434', 'CWE-436', 'CWE-470', 'CWE-501', 'CWE-502', 'CWE-610',
  'CWE-643', 'CWE-776', 'CWE-862', 'CWE-863',
  // --- HTTP smuggling, confused deputy, UI security, initialization ---
  'CWE-440', 'CWE-441', 'CWE-444', 'CWE-446', 'CWE-449', 'CWE-450',
  'CWE-451', 'CWE-453', 'CWE-454', 'CWE-455',
  // --- Web parameter, PHP, portability, session exposure ---
  'CWE-472', 'CWE-473', 'CWE-474', 'CWE-488', 'CWE-523', 'CWE-527',
  'CWE-529', 'CWE-531',
  // --- Malicious code & covert channel ---
  'CWE-494', 'CWE-506', 'CWE-507', 'CWE-508', 'CWE-509', 'CWE-510',
  'CWE-511', 'CWE-512', 'CWE-514', 'CWE-515',
  // --- Information disclosure ---
  'CWE-497', 'CWE-532', 'CWE-538', 'CWE-540', 'CWE-548', 'CWE-550',
  'CWE-598', 'CWE-600', 'CWE-615',
  // --- Authentication & credential ---
  'CWE-521', 'CWE-522', 'CWE-620', 'CWE-798', 'CWE-918',
  // --- Cache, cookie, session, access control ---
  'CWE-524', 'CWE-525', 'CWE-526', 'CWE-528', 'CWE-552', 'CWE-565',
  'CWE-566',
  // --- Shell/servlet/Java error messages, logs, persistent cookies ---
  'CWE-533', 'CWE-534', 'CWE-535', 'CWE-536', 'CWE-537', 'CWE-539',
  'CWE-541', 'CWE-543', 'CWE-544', 'CWE-546', 'CWE-547',
  // --- Authorization ordering, threading, Hibernate, finalize ---
  'CWE-551', 'CWE-558', 'CWE-560', 'CWE-564', 'CWE-567', 'CWE-568',
  'CWE-573', 'CWE-579', 'CWE-580', 'CWE-614',
  // --- Dead code, always-true/false, thread bugs, pointer misuse ---
  'CWE-561', 'CWE-562', 'CWE-563', 'CWE-570', 'CWE-571', 'CWE-572',
  'CWE-583', 'CWE-585', 'CWE-586', 'CWE-587',
  // --- Object model, finally, memory safety, API portability ---
  'CWE-581', 'CWE-584', 'CWE-588', 'CWE-589', 'CWE-590', 'CWE-591',
  // --- Comparison bugs, concurrency, regex, hook validation ---
  'CWE-595', 'CWE-597', 'CWE-606', 'CWE-607', 'CWE-609', 'CWE-617',
  'CWE-619', 'CWE-622', 'CWE-624', 'CWE-625',
  // --- Cross-language detection, open redirect ---
  'CWE-601', 'CWE-602', 'CWE-603',
  // --- Upload variable, null byte, dynamic eval, fail-open ---
  'CWE-616', 'CWE-621', 'CWE-626', 'CWE-627', 'CWE-636',
  // --- Port binding, search index, session expiration ---
  'CWE-605', 'CWE-612', 'CWE-613',
  // --- Trust boundary & authorization bypass ---
  'CWE-639', 'CWE-640', 'CWE-645', 'CWE-646', 'CWE-649', 'CWE-650',
  'CWE-653', 'CWE-654',
  // --- Resource management ---
  'CWE-662', 'CWE-667', 'CWE-672', 'CWE-674', 'CWE-676', 'CWE-694',
  'CWE-764', 'CWE-765', 'CWE-832', 'CWE-833',
  // --- Type confusion, permission issues, error handling ---
  'CWE-688', 'CWE-689', 'CWE-690', 'CWE-696', 'CWE-698', 'CWE-704', 'CWE-706',
  'CWE-732', 'CWE-749', 'CWE-754', 'CWE-755',
  // --- Logging, crypto padding, trust decisions, infinite loops ---
  'CWE-756', 'CWE-778', 'CWE-779', 'CWE-780', 'CWE-804', 'CWE-806',
  'CWE-807', 'CWE-829', 'CWE-834', 'CWE-835',
  // --- Encoding, initialization, hidden functionality, mass assignment ---
  'CWE-838', 'CWE-908', 'CWE-909', 'CWE-910', 'CWE-911', 'CWE-912',
  'CWE-913', 'CWE-915', 'CWE-920', 'CWE-921',
  // --- Insecure storage, message integrity, URL schemes, cross-domain ---
  'CWE-922', 'CWE-924', 'CWE-939', 'CWE-940', 'CWE-941', 'CWE-942',
  'CWE-943', 'CWE-1004', 'CWE-1007', 'CWE-1021',
  // --- Architecture & link safety ---
  'CWE-1022', 'CWE-1023', 'CWE-1024', 'CWE-1025', 'CWE-1036',
  'CWE-1044', 'CWE-1045', 'CWE-1046', 'CWE-1047', 'CWE-1048',
  // --- Architecture quality: resource, documentation, concurrency ---
  'CWE-1050', 'CWE-1051', 'CWE-1052', 'CWE-1053', 'CWE-1054',
  'CWE-1055', 'CWE-1056', 'CWE-1057', 'CWE-1058', 'CWE-1059',
  // --- Architecture & code quality (1060-1069) ---
  'CWE-1060', 'CWE-1061', 'CWE-1062', 'CWE-1063', 'CWE-1064',
  'CWE-1065', 'CWE-1066', 'CWE-1067', 'CWE-1068', 'CWE-1069',
  // --- Deep architecture CWEs ---
  'CWE-1070', 'CWE-1071', 'CWE-1073', 'CWE-1074', 'CWE-1075',
  'CWE-1076', 'CWE-1078', 'CWE-1079', 'CWE-1080', 'CWE-1082',
  // --- Architecture quality: data access, code structure (1083-1094) ---
  'CWE-1083', 'CWE-1084', 'CWE-1085', 'CWE-1086', 'CWE-1087',
  'CWE-1089', 'CWE-1090', 'CWE-1091', 'CWE-1092', 'CWE-1094',
  // --- Code quality and maintainability (1095-1107) ---
  'CWE-1095', 'CWE-1097', 'CWE-1098', 'CWE-1099', 'CWE-1100',
  'CWE-1101', 'CWE-1102', 'CWE-1104', 'CWE-1106', 'CWE-1107',
  // --- Documentation & code style ---
  'CWE-1108', 'CWE-1109', 'CWE-1110', 'CWE-1111', 'CWE-1112',
  'CWE-1113', 'CWE-1114', 'CWE-1115', 'CWE-1116', 'CWE-1117',
  // --- Complexity and attack surface (1118-1127) ---
  'CWE-1118', 'CWE-1119', 'CWE-1120', 'CWE-1121', 'CWE-1122',
  'CWE-1123', 'CWE-1124', 'CWE-1125', 'CWE-1126', 'CWE-1127',
  // --- Prototype pollution ---
  'CWE-1321',
]);

/**
 * Raw combined registry before filtering — internal only.
 */
const _RAW_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  ...BATCH_001_REGISTRY,
  ...BATCH_002_REGISTRY,
  ...BATCH_003_REGISTRY,
  ...BATCH_004_REGISTRY,
  ...BATCH_005_REGISTRY,
  ...BATCH_006_REGISTRY,
  ...BATCH_007_REGISTRY,
  ...BATCH_008_REGISTRY,
  ...BATCH_009_REGISTRY,
  ...BATCH_010_REGISTRY,
  ...BATCH_011_REGISTRY,
  ...BATCH_012_REGISTRY,
  ...BATCH_013_REGISTRY,
  ...BATCH_014_REGISTRY,
  ...BATCH_015_REGISTRY,
  ...BATCH_016_REGISTRY,
  ...BATCH_017_REGISTRY,
  ...BATCH_018_REGISTRY,
  ...BATCH_019_REGISTRY,
  ...BATCH_020_REGISTRY,
  ...BATCH_021_REGISTRY,
  ...BATCH_CRYPTO_B2_REGISTRY,
  ...BATCH_CRYPTO_A2_REGISTRY,
};

/**
 * Combined registry of generated verifiers, EXCLUDING those with hand-written
 * overrides in verifier.ts. Only generated-only CWEs remain here.
 *
 * Before this cleanup, 385 generated verifiers were loaded but shadowed by
 * hand-written overrides — dead code that contributed to false-positive noise.
 */
export const GENERATED_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> =
  Object.fromEntries(
    Object.entries(_RAW_REGISTRY).filter(([cwe]) => !HAND_WRITTEN_OVERRIDES.has(cwe))
  );

/**
 * Verify a specific CWE using generated verifiers only.
 */
export function verifyGenerated(map: NeuralMap, cwe: string): VerificationResult | null {
  const fn = GENERATED_REGISTRY[cwe];
  return fn ? fn(map) : null;
}

/**
 * List all CWEs covered by generated verifiers.
 */
export function generatedCWEs(): string[] {
  return Object.keys(GENERATED_REGISTRY);
}

/**
 * Expose the skip set for tests / diagnostics.
 */
export { HAND_WRITTEN_OVERRIDES };
