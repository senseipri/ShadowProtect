'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useAppStore, type Agent } from '@/lib/store';

/* ── Types ───────────────────────────────────────────────── */
type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

function getAgentRisk(score: number): RiskLevel {
  if (score < 20) return 'CRITICAL';
  if (score < 40) return 'HIGH';
  if (score < 70) return 'MEDIUM';
  return 'LOW';
}

function getSystemThreatLevel(avgTrust: number): 'SECURE' | 'ELEVATED' | 'CRITICAL' {
  if (avgTrust > 70) return 'SECURE';
  if (avgTrust < 40) return 'CRITICAL';
  return 'ELEVATED';
}

/* ── Badge / colour helpers ──────────────────────────────── */
const RISK_BADGE: Record<RiskLevel, string> = {
  LOW:      'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  MEDIUM:   'bg-yellow-500/15  text-yellow-400  border-yellow-500/30',
  HIGH:     'bg-orange-500/15  text-orange-400  border-orange-500/30',
  CRITICAL: 'bg-red-500/15     text-red-400     border-red-500/30',
};

const SYSTEM_BADGE: Record<'SECURE' | 'ELEVATED' | 'CRITICAL', string> = {
  SECURE:   'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  ELEVATED: 'bg-yellow-500/15  text-yellow-400  border-yellow-500/30',
  CRITICAL: 'bg-red-500/15     text-red-400     border-red-500/30 animate-pulse',
};

const BAR_COLOR: Record<RiskLevel, string> = {
  LOW:      '#22c55e',   /* green-500  */
  MEDIUM:   '#f59e0b',   /* amber-500  */
  HIGH:     '#f97316',   /* orange-500 */
  CRITICAL: '#ef4444',   /* red-500    */
};

/* ── Sparkline ───────────────────────────────────────────── */
function buildSparklinePoints(
  values: number[],
  width  = 100,
  height = 24,
): string {
  if (values.length === 0) return '';
  const stepX = values.length > 1 ? width / (values.length - 1) : width;
  return values
    .map((v, i) => {
      const x    = i * stepX;
      const norm = Math.max(0, Math.min(100, v)) / 100;
      const y    = height - norm * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
}

/* ── Component ───────────────────────────────────────────── */
export default function TrustPanel() {
  const agents        = useAppStore((s) => s.agents);
  const alerts        = useAppStore((s) => s.alerts);
  const threatVerdicts = useAppStore((s) => s.threatVerdicts);
  const taintMap      = useAppStore((s) => s.taintMap);

  const [historyMap, setHistoryMap] = useState<Record<string, number[]>>({});
  const [flashMap,   setFlashMap]   = useState<Record<string, boolean>>({});
  const prevScoresRef               = useRef<Record<string, number>>({});

  /* Track score history + flash on drops */
  useEffect(() => {
    setHistoryMap((prev) => {
      const next = { ...prev };
      for (const agent of agents) {
        const score    = Number(agent.trust_score ?? 100);
        const oldScore = prevScoresRef.current[agent.id];

        if (typeof oldScore === 'number' && score < oldScore) {
          setFlashMap((c) => ({ ...c, [agent.id]: true }));
          window.setTimeout(
            () => setFlashMap((c) => ({ ...c, [agent.id]: false })),
            400,
          );
        }

        const existing  = next[agent.id] ?? [];
        const lastValue = existing[existing.length - 1];
        const append    = typeof lastValue !== 'number' || lastValue !== score;
        next[agent.id]  = append
          ? [...existing, score].slice(-12)
          : existing.slice(-12);

        prevScoresRef.current[agent.id] = score;
      }
      return next;
    });
  }, [agents]);

  const averageTrust = useMemo(() => {
    if (agents.length === 0) return 100;
    return agents.reduce((s, a) => s + Number(a.trust_score ?? 100), 0) / agents.length;
  }, [agents]);

  const systemThreatLevel = getSystemThreatLevel(averageTrust);

  /* Last alert description per agent */
  const lastAlertByAgent = useMemo(() => {
    const map: Record<string, string> = {};
    for (const v of threatVerdicts) {
      const desc   = String(v.alert_description || '').trim();
      const source = String(v.source || '').trim();
      const target = String(v.target || '').trim();
      if (desc) {
        if (source && !map[source]) map[source] = desc;
        if (target && !map[target]) map[target] = desc;
      }
    }
    const latest = alerts[0]?.description;
    if (latest) {
      for (const a of agents) {
        if (!map[a.id]) map[a.id] = latest;
      }
    }
    return map;
  }, [agents, alerts, threatVerdicts]);

  /* ── Render ── */
  return (
    <section className="w-full flex flex-col">

      {/* Panel header */}
      <header className="sticky top-0 z-10 flex items-center justify-between gap-2 px-4 py-3 bg-slate-900 border-b border-slate-800/80">
        <h2 className="text-sm font-bold text-slate-100 tracking-tight">Trust Panel</h2>
        <span className={`px-2 py-0.5 rounded border text-[9px] font-extrabold uppercase tracking-widest ${SYSTEM_BADGE[systemThreatLevel]}`}>
          {systemThreatLevel}
        </span>
      </header>

      {/* Agent list */}
      <div className="flex-1 divide-y divide-slate-800/60 overflow-y-auto">
        {agents.length === 0 && (
          <div className="px-4 py-8 text-center text-xs text-slate-500">
            Waiting for agent heartbeat…
          </div>
        )}

        {agents.map((agent: Agent) => {
          const score     = Math.max(0, Math.min(100, Number(agent.trust_score ?? 100)));
          const risk      = getAgentRisk(score);
          const critical  = risk === 'CRITICAL';
          const taint     = taintMap[agent.id];
          const taintPct  = taint ? Math.round(taint.taint_level * 100) : null;
          const sparkPts  = buildSparklinePoints(historyMap[agent.id] ?? [score]);

          const cardBg = flashMap[agent.id]
            ? 'bg-red-950/40'
            : 'bg-slate-800/30 hover:bg-slate-800/60';

          return (
            <div
              key={agent.id}
              className={`px-4 py-3 transition-colors duration-300 ${cardBg}`}
              style={critical ? { boxShadow: 'inset 3px 0 0 #ef4444' } : undefined}
            >
              {/* Name + badge row */}
              <div className="flex items-start justify-between gap-2 mb-2">
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-slate-100 truncate">
                    {agent.name}
                  </div>
                  <div className="text-[10px] text-slate-500 truncate">{agent.id}</div>
                </div>
                <span className={`shrink-0 px-1.5 py-0.5 rounded border text-[9px] font-bold uppercase ${RISK_BADGE[risk]}`}>
                  {risk}
                </span>
              </div>

              {/* Trust bar */}
              <div className="mb-2">
                <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                  <span>Trust</span>
                  <span className="font-mono font-bold text-slate-300">{Math.round(score)}</span>
                </div>
                <div className="h-1.5 w-full bg-slate-700/70 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${score}%`,
                      backgroundColor: BAR_COLOR[risk],
                      transition: 'width 0.6s ease, background-color 0.4s ease',
                    }}
                  />
                </div>
              </div>

              {/* Taint level (if any) */}
              {taintPct !== null && (
                <div className="flex items-center justify-between text-[10px] mb-2">
                  <span className="text-slate-500">Taint</span>
                  <span
                    className={`font-mono font-bold ${
                      taintPct >= 80 ? 'text-red-400' :
                      taintPct >= 60 ? 'text-orange-400' :
                      taintPct >= 30 ? 'text-yellow-400' : 'text-emerald-400'
                    }`}
                  >
                    {taintPct}%
                  </span>
                </div>
              )}

              {/* Last alert */}
              <p className="text-[10px] text-slate-500 mb-2 line-clamp-1">
                <span className="text-slate-400 font-medium">Last: </span>
                {lastAlertByAgent[agent.id] || 'No recent alert'}
              </p>

              {/* Sparkline */}
              <div className="flex items-center gap-2">
                <span className="text-[9px] font-semibold uppercase tracking-widest text-slate-600">Trend</span>
                <svg width="100" height="24" viewBox="0 0 100 24" className="overflow-visible">
                  <polyline
                    fill="none"
                    stroke={critical ? '#f87171' : '#38bdf8'}
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    points={sparkPts}
                  />
                </svg>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
