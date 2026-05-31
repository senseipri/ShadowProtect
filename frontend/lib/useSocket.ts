'use client';

/**
 * useSocket.ts — FIXED
 *
 * Fixes vs original:
 *  1. THREAT_VERDICT: trust delta was applied to `verdict.target` which backend
 *     never sent. Now reads source from verdict.source (backend sends it after fix).
 *  2. ALERT events from protection layer (INJECTION_BLOCKED, SCOPE_VIOLATION_BLOCKED,
 *     EXFILTRATION_BLOCKED, DANGEROUS_OP_BLOCKED, RATE_LIMIT_EXCEEDED,
 *     QUARANTINE_BLOCKED) are now dispatched to the store's addAlert().
 *  3. TAINT_UPDATE: also applies trust score update derived from taint_level.
 *  4. Removed stale reference to `payload.source` / `payload.target` on
 *     THREAT_VERDICT — those fields live on verdict.source / verdict.target.
 */

import { useEffect, useRef } from 'react';
import { useAppStore } from './store';

const WS_URL = 'ws://localhost:8000/ws';
const MAX_BACKOFF_MS = 30_000;
const INITIAL_BACKOFF_MS = 2_000;

function extractThreatChain(verdict: Record<string, unknown>): string[] | null {
  const taintChain = verdict?.taint_chain;
  if (!Array.isArray(taintChain) || taintChain.length <= 1) return null;
  const ids = (taintChain as Array<Record<string, unknown>>)
    .map((node) => String(node?.agent_id || '').trim())
    .filter((id) => id.length > 0);
  return ids.length > 1 ? ids : null;
}

export function useSocket(): void {
  const wsRef              = useRef<WebSocket | null>(null);
  const reconnectTimerRef  = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef         = useRef<number>(INITIAL_BACKOFF_MS);
  const closedByHookRef    = useRef(false);

  useEffect(() => {
    closedByHookRef.current = false;

    const connect = () => {
      const socket = new WebSocket(WS_URL);
      wsRef.current = socket;

      socket.onopen = () => {
        useAppStore.getState().setConnected(true);
        backoffRef.current = INITIAL_BACKOFF_MS;
      };

      socket.onmessage = (msgEvent) => {
        let payload: Record<string, unknown>;
        try {
          payload = JSON.parse(msgEvent.data as string) as Record<string, unknown>;
        } catch {
          return;
        }

        const store     = useAppStore.getState();
        const eventType = String(payload?.type || '').toUpperCase();

        /* ── Raw agent event (message flow) ── */
        if (eventType === 'EVENT') {
          store.addEvent((payload.event ?? payload) as Parameters<typeof store.addEvent>[0]);
          return;
        }

        /* ── Full threat verdict from detection engine ── */
        if (eventType === 'THREAT_VERDICT') {
          const verdict = (payload.verdict ?? payload) as Record<string, unknown>;
          store.addThreatVerdict(verdict as Parameters<typeof store.addThreatVerdict>[0]);

          const trustDelta = Number(verdict?.trust_delta ?? 0);

          // FIX: source and target are now on verdict (backend fix applied)
          const source = String(verdict?.source || '').trim();
          const target = String(verdict?.target || '').trim();

          // Apply trust drop to both source AND target when present
          if (target && Number.isFinite(trustDelta) && trustDelta !== 0) {
            store.updateTrustScore(target, trustDelta, 'delta');
            store.setAgentUnderAttack(target, true);
          }
          if (source && Number.isFinite(trustDelta) && trustDelta !== 0) {
            store.updateTrustScore(source, trustDelta, 'delta');
            store.setAgentUnderAttack(source, true);
          } else if (source) {
            store.setAgentUnderAttack(source, true);
          }

          const chain = extractThreatChain(verdict);
          if (chain) store.setActiveAttackChain(chain);

          const severity = String(
            verdict?.severity ?? verdict?.system_threat_level ?? '',
          ).toUpperCase();

          if (severity === 'HIGH' || severity === 'CRITICAL') {
            store.addAlert({
              kind:        String(verdict?.primary_threat_type ?? 'THREAT_VERDICT'),
              severity,
              description: String(verdict?.alert_description ?? 'High-risk threat verdict received.'),
              timestamp:   String(verdict?.timestamp ?? new Date().toISOString()),
            });
          }
          return;
        }

        /* ── Taint propagation update ── */
        if (eventType === 'TAINT_UPDATE') {
          const tu      = (payload.taint_update ?? payload) as Record<string, unknown>;
          const agentId = String(tu?.agent_id ?? tu?.target ?? '').trim();
          if (!agentId) return;

          const taintLevel = Number.isFinite(Number(tu?.taint_level))
            ? Number(tu.taint_level)
            : 0;

          store.updateTaintMap(agentId, {
            taint_level:  taintLevel,
            taint_source: (tu?.source_agent ?? tu?.source ?? null) as string | null,
            infected_at:  (tu?.infected_at ?? null) as string | null,
            chain:        Array.isArray(tu?.chain) ? tu.chain as [] : [],
          });

          if (taintLevel > 0.3) {
            store.setAgentUnderAttack(agentId, true);
          }

          // FIX: Sync trust score from taint level if updated_agent is present
          const updatedAgent = tu?.updated_agent as Record<string, unknown> | undefined;
          if (updatedAgent?.id && typeof updatedAgent.trust_score === 'number') {
            store.updateTrustScore(String(updatedAgent.id), updatedAgent.trust_score, 'set');
          }
          return;
        }

        /* ── Protection-layer alerts (new in completed backend) ── */
        if (eventType === 'ALERT') {
          const alert = (payload.alert ?? payload) as Record<string, unknown>;
          store.addAlert({
            kind:        String(alert?.kind ?? 'ALERT'),
            severity:    String(alert?.severity ?? 'medium'),
            description: String(alert?.description ?? 'Security event.'),
            timestamp:   String(alert?.timestamp ?? new Date().toISOString()),
          });
          return;
        }

        /* ── Heartbeat ── */
        if (eventType === 'HEARTBEAT') {
          const agentStatuses = Array.isArray(payload?.agent_statuses)
            ? payload.agent_statuses as Record<string, unknown>[]
            : [];

          if (agentStatuses.length > 0) {
            const current = useAppStore.getState().agents;
            const byId    = new Map(current.map((a) => [a.id, a]));
            const merged  = agentStatuses.map((s) => {
              const id       = String(s?.id ?? '');
              const existing = byId.get(id);
              return {
                id,
                name:         String(s?.name ?? existing?.name ?? id),
                trust_score:  Number(s?.trust_score ?? existing?.trust_score ?? 100),
                status:       String(s?.status ?? existing?.status ?? 'active'),
                underAttack:  existing?.underAttack ?? false,
              };
            });
            store.setAgents(merged);
          }

          store.setSystemThreatSummary({
            system_composite_threat_level: String(payload?.system_threat_level ?? 'LOW'),
            heartbeat_at: new Date().toISOString(),
          });
          return;
        }
      };

      socket.onclose = () => {
        useAppStore.getState().setConnected(false);
        if (closedByHookRef.current) return;

        const waitMs            = backoffRef.current;
        reconnectTimerRef.current = setTimeout(connect, waitMs);
        backoffRef.current      = Math.min(MAX_BACKOFF_MS, backoffRef.current * 2);
      };

      socket.onerror = () => {
        socket.close();
      };
    };

    connect();

    return () => {
      closedByHookRef.current = true;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      wsRef.current?.close();
      wsRef.current = null;
      useAppStore.getState().setConnected(false);
    };
  }, []);
}