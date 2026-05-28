import { create } from 'zustand';

export type Agent = {
  id: string;
  name: string;
  trust_score: number;
  status: string;
  underAttack?: boolean;
};

export type AgentEvent = {
  type: string;
  source?: string;
  target?: string;
  message?: string;
  timestamp?: string;
  [key: string]: unknown;
};

export type Alert = {
  id?: string | number;
  kind: string;
  severity?: string;
  description: string;
  timestamp?: string;
  [key: string]: unknown;
};

export type ThreatVerdict = {
  composite_score?: number;
  severity?: string;
  triggered_detectors?: string[];
  primary_threat_type?: string;
  taint_chain?: Array<{ agent_id?: string; taint_level?: number }>;
  alert_description?: string;
  trust_delta?: number;
  confidence?: number;
  event_type?: string;
  system_threat_level?: string;
  risk_score?: number;
  timestamp?: string;
  source?: string;
  target?: string;
  [key: string]: unknown;
};

export type TaintInfo = {
  taint_level: number;
  taint_source?: string | null;
  infected_at?: string | null;
  chain?: Array<{ agent_id?: string; taint_level?: number; [key: string]: unknown }>;
};

export type SystemThreatSummary = {
  total_alerts_last_hour?: number;
  most_suspicious_agent?: string | null;
  active_taint_chains?: unknown[];
  top_threat_vectors?: unknown[];
  system_composite_threat_level?: string;
  [key: string]: unknown;
};

type AttackTimeouts = Record<string, ReturnType<typeof setTimeout>>;

export type AppState = {
  agents: Agent[];
  events: AgentEvent[];
  alerts: Alert[];
  connected: boolean;
  taintMap: Record<string, TaintInfo>;
  threatVerdicts: ThreatVerdict[];
  systemThreatSummary: SystemThreatSummary | null;
  activeAttackChain: string[] | null;
  systemThreatLevel: 'SECURE' | 'ELEVATED' | 'CRITICAL';

  setAgents: (agents: Agent[]) => void;
  addEvent: (event: AgentEvent) => void;
  addAlert: (alert: Alert) => void;
  updateTrustScore: (agentId: string, value: number, mode?: 'delta' | 'set') => void;
  setAgentUnderAttack: (agentId: string, underAttack: boolean) => void;
  setConnected: (connected: boolean) => void;
  updateTaintMap: (agentId: string, taint: TaintInfo) => void;
  addThreatVerdict: (verdict: ThreatVerdict) => void;
  setActiveAttackChain: (chain: string[] | null) => void;
  setSystemThreatSummary: (summary: SystemThreatSummary | null) => void;
  clearAlerts: () => void;
};

const MAX_EVENTS = 200;
const MAX_ALERTS = 50;
const MAX_VERDICTS = 200;

const attackTimeouts: AttackTimeouts = {};

function deriveSystemThreatLevel(agents: Agent[]): 'SECURE' | 'ELEVATED' | 'CRITICAL' {
  if (agents.length === 0) {
    return 'SECURE';
  }
  const avgTrust = agents.reduce((acc, a) => acc + Number(a.trust_score || 0), 0) / agents.length;
  if (avgTrust < 40) {
    return 'CRITICAL';
  }
  if (avgTrust < 70) {
    return 'ELEVATED';
  }
  return 'SECURE';
}

export const useAppStore = create<AppState>((set, get) => ({
  agents: [],
  events: [],
  alerts: [],
  connected: false,
  taintMap: {},
  threatVerdicts: [],
  systemThreatSummary: null,
  activeAttackChain: null,
  systemThreatLevel: 'SECURE',

  setAgents: (agents) =>
    set({
      agents,
      systemThreatLevel: deriveSystemThreatLevel(agents),
    }),

  addEvent: (event) =>
    set((state) => ({
      events: [event, ...state.events].slice(0, MAX_EVENTS),
    })),

  addAlert: (alert) =>
    set((state) => ({
      alerts: [alert, ...state.alerts].slice(0, MAX_ALERTS),
    })),

  updateTrustScore: (agentId, value, mode = 'delta') =>
    set((state) => {
      const agents = state.agents.map((agent) => {
        if (agent.id !== agentId) {
          return agent;
        }
        const next = mode === 'set' ? value : agent.trust_score + value;
        return {
          ...agent,
          trust_score: Math.max(0, Math.min(100, Math.round(next))),
        };
      });
      return {
        agents,
        systemThreatLevel: deriveSystemThreatLevel(agents),
      };
    }),

  setAgentUnderAttack: (agentId, underAttack) => {
    if (attackTimeouts[agentId]) {
      clearTimeout(attackTimeouts[agentId]);
      delete attackTimeouts[agentId];
    }

    set((state) => ({
      agents: state.agents.map((agent) =>
        agent.id === agentId ? { ...agent, underAttack } : agent
      ),
    }));

    if (underAttack) {
      attackTimeouts[agentId] = setTimeout(() => {
        get().setAgentUnderAttack(agentId, false);
      }, 3000);
    }
  },

  setConnected: (connected) => set({ connected }),

  updateTaintMap: (agentId, taint) =>
    set((state) => ({
      taintMap: {
        ...state.taintMap,
        [agentId]: taint,
      },
    })),

  addThreatVerdict: (verdict) =>
    set((state) => ({
      threatVerdicts: [verdict, ...state.threatVerdicts].slice(0, MAX_VERDICTS),
    })),

  setActiveAttackChain: (chain) => set({ activeAttackChain: chain }),

  setSystemThreatSummary: (summary) => set({ systemThreatSummary: summary }),

  clearAlerts: () => set({ alerts: [] }),
}));
