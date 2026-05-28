'use client';

import { useEffect, useRef } from 'react';
import { useAppStore } from './store';

const WS_URL = 'ws://localhost:8000/ws';
const MAX_BACKOFF_MS = 30000;
const INITIAL_BACKOFF_MS = 2000;

function extractThreatChain(verdict: any): string[] | null {
  const taintChain = verdict?.taint_chain;
  if (!Array.isArray(taintChain) || taintChain.length <= 1) {
    return null;
  }
  const ids = taintChain
    .map((node: any) => String(node?.agent_id || '').trim())
    .filter((id: string) => id.length > 0);
  return ids.length > 1 ? ids : null;
}

export function useSocket(): void {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef = useRef<number>(INITIAL_BACKOFF_MS);
  const closedByHookRef = useRef(false);

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
        let payload: any;
        try {
          payload = JSON.parse(msgEvent.data);
        } catch {
          return;
        }

        const store = useAppStore.getState();
        const eventType = String(payload?.type || '').toUpperCase();

        if (eventType === 'EVENT') {
          store.addEvent(payload.event || payload);
          return;
        }

        if (eventType === 'THREAT_VERDICT') {
          const verdict = payload.verdict || payload;
          store.addThreatVerdict(verdict);

          const trustDelta = Number(verdict?.trust_delta ?? 0);
          const source = verdict?.source || payload?.source;
          const target = verdict?.target || payload?.target;

          if (target && Number.isFinite(trustDelta) && trustDelta !== 0) {
            store.updateTrustScore(String(target), trustDelta, 'delta');
            store.setAgentUnderAttack(String(target), true);
          } else if (source) {
            store.setAgentUnderAttack(String(source), true);
          }

          const chain = extractThreatChain(verdict);
          if (chain) {
            store.setActiveAttackChain(chain);
          }

          const severity = String(verdict?.severity || verdict?.system_threat_level || '').toUpperCase();
          if (severity === 'HIGH' || severity === 'CRITICAL') {
            store.addAlert({
              kind: 'THREAT_VERDICT',
              severity,
              description: String(verdict?.alert_description || 'High-risk threat verdict received.'),
              timestamp: String(verdict?.timestamp || new Date().toISOString()),
            });
          }
          return;
        }

        if (eventType === 'TAINT_UPDATE') {
          const taintUpdate = payload.taint_update || payload;
          const agentId = String(taintUpdate?.agent_id || taintUpdate?.target || '').trim();
          if (!agentId) {
            return;
          }

          const taintLevel = Number(taintUpdate?.taint_level ?? 0);
          store.updateTaintMap(agentId, {
            taint_level: Number.isFinite(taintLevel) ? taintLevel : 0,
            taint_source: taintUpdate?.source_agent || taintUpdate?.source || null,
            infected_at: taintUpdate?.infected_at || null,
            chain: Array.isArray(taintUpdate?.chain) ? taintUpdate.chain : [],
          });

          if (taintLevel > 0.3) {
            store.setAgentUnderAttack(agentId, true);
          }
          return;
        }

        if (eventType === 'HEARTBEAT') {
          const agentStatuses = Array.isArray(payload?.agent_statuses) ? payload.agent_statuses : [];
          if (agentStatuses.length > 0) {
            const currentAgents = useAppStore.getState().agents;
            const byId = new Map(currentAgents.map((a) => [a.id, a]));
            const merged = agentStatuses.map((status: any) => {
              const id = String(status?.id || '');
              const existing = byId.get(id);
              return {
                id,
                name: String(status?.name || existing?.name || id),
                trust_score: Number(status?.trust_score ?? existing?.trust_score ?? 100),
                status: String(status?.status || existing?.status || 'active'),
                underAttack: existing?.underAttack || false,
              };
            });
            store.setAgents(merged);
          }

          store.setSystemThreatSummary({
            system_composite_threat_level: payload?.system_threat_level || 'LOW',
            heartbeat_at: new Date().toISOString(),
          });
        }
      };

      socket.onclose = () => {
        useAppStore.getState().setConnected(false);
        if (closedByHookRef.current) {
          return;
        }

        const waitMs = backoffRef.current;
        reconnectTimerRef.current = setTimeout(() => {
          connect();
        }, waitMs);

        backoffRef.current = Math.min(MAX_BACKOFF_MS, backoffRef.current * 2);
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
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      useAppStore.getState().setConnected(false);
    };
  }, []);
}
