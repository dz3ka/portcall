import type { Probe } from './index.ts';
import { dnsProbe } from '../probes/dns/index.ts';
import { egressProbe } from '../probes/egress/index.ts';
import { proxyProbe } from '../probes/proxy/index.ts';
import { tlsProbe } from '../probes/tls/index.ts';

/**
 * The probe registry.
 *
 * Order is execution order, and it is the order a reader needs: `dns` first,
 * because a name that does not resolve makes every egress result downstream of
 * it meaningless, and the operator should see the resolution answer before the
 * connection answer that depends on it. `proxy` runs after `egress`: its
 * findings (an intermediary demanding auth, a PAC-discovered route) explain
 * `egress` blockers reported one probe earlier, so the reader sees the
 * mechanism before the explanation. `tls` comes after `proxy` for the same
 * reason: it captures a chain through whichever proxy the environment names,
 * and a reader meets the intermediary in the proxy findings before meeting the
 * certificate it presents.
 *
 * M1 registers `dns` and `egress`. M2 adds `proxy`. M3 `tls`, M4 `truststore`.
 */
export const PROBES: readonly Probe[] = [dnsProbe, egressProbe, proxyProbe, tlsProbe];
