export { validateAuthName, type ValidatedDnsName } from './dns/name.ts';
export { LiveResolver, type DnsAnswer, type DnsResolver, type DnsStatus } from './dns/resolver.ts';
export { toMailauthResolver } from './dns/mailauth-adapter.ts';
export { rawDkimVerify } from './authentication/mailauth-dkim.ts';
export { keyFingerprint } from './authentication/fingerprint.ts';
