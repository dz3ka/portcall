import type { Probe } from './index.ts';

/**
 * The probe registry.
 *
 * Empty in M0 by design: the skeleton has to run end to end and emit a valid
 * empty report before any probe exists, so that the redaction and network
 * boundaries are already load-bearing when the first probe is written.
 *
 * M1 registers `dns` and `egress`, M2 `proxy`, M3 `tls`, M4 `truststore`.
 */
export const PROBES: readonly Probe[] = [];
