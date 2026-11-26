export { analyze, type AnalysisInput, type EngineDeps } from './pipeline.ts';
export { AnalysisError, LIMITS } from './intake/limits.ts';
export { readRawHeaders, headerValues, type RawHeaders } from './parse/raw-headers.ts';
export { parseMailboxes, readSender } from './parse/addresses.ts';
export { validateAuthName, type ValidatedDnsName } from './dns/name.ts';
export { LiveResolver, type DnsAnswer, type DnsResolver, type DnsStatus } from './dns/resolver.ts';
export { toMailauthResolver, type DnsLookup } from './dns/mailauth-adapter.ts';
export { rawDkimVerify } from './authentication/mailauth-dkim.ts';
export { keyFingerprint } from './authentication/fingerprint.ts';
export { evaluateDmarc, DMARC_LIMITATION } from './authentication/dmarc.ts';
export { parseAuthResults, readReceiverResults } from './authentication/receiver-results.ts';
export {
  analyzeDomain,
  matchesApproved,
  toAsciiHost,
  type DomainParts,
} from './identity/domain.ts';
export {
  confusableKey,
  confusablesVersion,
  describeCodePoints,
  skeleton,
} from './identity/confusables.ts';
export { compareLabels, charDiff, osaDistance } from './identity/similarity.ts';
export {
  emptyRegistry,
  inspectDomain,
  matchClaim,
  normalizeName,
  type RegistryPort,
} from './identity/matcher.ts';
export { extractLinks } from './parse/links.ts';
export { DEFAULT_RULE_CONFIG, RULE_IDS, type RuleConfig, type RuleId } from './rules/config.ts';
export { runRules, type RuleContext } from './rules/rules.ts';
export { decideVerdict } from './rules/verdict.ts';
