/**
 * Single source of truth for the version reported by `--version` and embedded
 * in every report. Kept in sync with package.json by a test, because a report
 * that lies about which build produced it is worse than no report.
 */
export const VERSION = '0.1.0';

export const TOOL_NAME = 'portcall';
