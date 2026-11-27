export const RULE_IDS = ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9'] as const;
export type RuleId = (typeof RULE_IDS)[number];

/** Versioned rule settings. Bump `version` whenever behaviour changes. */
export interface RuleConfig {
  version: string;
  enabled: Record<RuleId, boolean>;
}

export const DEFAULT_RULE_CONFIG: RuleConfig = {
  version: '1.1.0',
  enabled: {
    R1: true,
    R2: true,
    R3: true,
    R4: true,
    R5: true,
    R6: true,
    R7: true,
    // Not evaluated unless key history is switched on.
    R8: true,
    R9: true,
  },
};
