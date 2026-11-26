export { analyze, type AnalysisInput, type EngineDeps } from './pipeline.ts';
export { AnalysisError, LIMITS } from './intake/limits.ts';
export { readRawHeaders, headerValues, type RawHeaders } from './parse/raw-headers.ts';
export { parseMailboxes, readSender } from './parse/addresses.ts';
export { validateAuthName, type ValidatedDnsName } from './dns/name.ts';
export { LiveResolver, type DnsAnswer, type DnsResolver, type DnsStatus } from './dns/resolver.ts';
export { toMailauthResolver, type DnsLookup } from './dns/mailauth-adapter.ts';
export { rawDkimVerify } from './authentication/mailauth-dkim.ts';
export { keyFingerprint } from './authentication/fingerprint.ts';
