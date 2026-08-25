import type { Probe } from './index.ts';
import { dnsProbe } from '../probes/dns/index.ts';
import { egressProbe } from '../probes/egress/index.ts';

/**
 * The probe registry.
 *
 * Order is execution order, and it is the order a reader needs: `dns` first,
 * because a name that does not resolve makes every egress result downstream of
 * it meaningless, and the operator should see the resolution answer before the
 * connection answer that depends on it.
 *
 * M1 registers `dns` and `egress`, M2 `proxy`, M3 `tls`, M4 `truststore`.
 */
export const PROBES: readonly Probe[] = [dnsProbe, egressProbe];
