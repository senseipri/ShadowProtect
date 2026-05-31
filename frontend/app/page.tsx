'use client';

/**
 * page.tsx — FIXED
 *
 * Fixes vs original:
 *  1. On mount: fetches GET /alerts (was missing) and seeds the store so
 *     AlertFeed and TrustPanel show history even before new WS events arrive.
 *  2. On mount: fetches GET /events so AgentGraph can show recent edges on load.
 *  3. Error handling uses console.warn instead of silent swallowing.
 */

import { useEffect, useRef, useState } from 'react';
import { Shield, ChevronDown, Loader2 } from 'lucide-react';

import { useSocket }    from '@/lib/useSocket';
import { useAppStore }  from '@/lib/store';
import TrustPanel       from '@/components/TrustPanel';
import AlertFeed        from '@/components/AlertFeed';
import AgentGraph       from '@/components/AgentGraph';
import ReplayBar        from '@/components/ReplayBar';

const API = 'http://localhost:8000';

type Scenario = 'injection' | 'collusion' | 'exfiltration' | 'lateral_movement';

const SCENARIOS: { value: Scenario; label: string }[] = [
  { value: 'injection',        label: 'Prompt Injection'  },
  { value: 'collusion',        label: 'Agent Collusion'   },
  { value: 'exfiltration',     label: 'Data Exfiltration' },
  { value: 'lateral_movement', label: 'Lateral Movement'  },
];

const THREAT_STYLES = {
  SECURE:   'bg-emerald-500/10 text-emerald-400 border-emerald-500/25',
  ELEVATED: 'bg-yellow-500/10  text-yellow-400  border-yellow-500/25',
  CRITICAL: 'bg-red-500/10     text-red-400     border-red-500/25 animate-pulse',
} as const;

export default function HomePage() {
  useSocket();

  const connected         = useAppStore((s) => s.connected);
  const systemThreatLevel = useAppStore((s) => s.systemThreatLevel);
  const setAgents         = useAppStore((s) => s.setAgents);
  const setSummary        = useAppStore((s) => s.setSystemThreatSummary);
  const addAlert          = useAppStore((s) => s.addAlert);
  const addEvent          = useAppStore((s) => s.addEvent);

  const [injecting,    setInjecting]    = useState(false);
  const [scenario,     setScenario]     = useState<Scenario>('injection');
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  /* ── On mount: hydrate store from REST endpoints ── */
  useEffect(() => {
    // Agents
    fetch(`${API}/agents`)
      .then((r) => r.json())
      .then(setAgents)
      .catch((e) => console.warn('[ShadowMesh] /agents fetch failed:', e));

    // Threat summary
    fetch(`${API}/threat-summary`)
      .then((r) => r.json())
      .then(setSummary)
      .catch((e) => console.warn('[ShadowMesh] /threat-summary fetch failed:', e));

    // FIX: Hydrate past alerts so AlertFeed is populated on page load
    fetch(`${API}/alerts?limit=50`)
      .then((r) => r.json())
      .then((alerts: unknown[]) => {
        // Insert in oldest-first order so newest ends up at the front of the store
        [...alerts].reverse().forEach((a) => {
          const alert = a as Record<string, unknown>;
          addAlert({
            id:          alert.id as string | number | undefined,
            kind:        String(alert.kind ?? 'ALERT'),
            severity:    String(alert.severity ?? 'medium'),
            description: String(alert.description ?? ''),
            timestamp:   String(alert.timestamp ?? ''),
          });
        });
      })
      .catch((e) => console.warn('[ShadowMesh] /alerts fetch failed:', e));

    // FIX: Hydrate past events so AgentGraph shows recent message edges on load
    fetch(`${API}/events?limit=50`)
      .then((r) => r.json())
      .then((events: unknown[]) => {
        [...events].reverse().forEach((ev) => {
          addEvent(ev as Parameters<typeof addEvent>[0]);
        });
      })
      .catch((e) => console.warn('[ShadowMesh] /events fetch failed:', e));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* ── Close dropdown on outside click ── */
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  /* ── Inject handler ── */
  const handleInject = async () => {
    setDropdownOpen(false);
    setInjecting(true);
    try {
      await fetch(`${API}/inject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario }),
      });
    } catch (e) {
      console.warn('[ShadowMesh] /inject failed:', e);
    }
    setTimeout(() => setInjecting(false), 500);
  };

  const currentLabel = SCENARIOS.find((s) => s.value === scenario)?.label ?? 'Injection';
  const threatStyle  = THREAT_STYLES[systemThreatLevel];

  return (
    <div className="app-shell">

      <header className="app-header">
        <div className="flex items-center gap-3 mr-auto min-w-0">
          <span className="font-mono text-base font-bold tracking-tight text-slate-100 whitespace-nowrap">
            ShadowMesh
          </span>
          <span className="text-[11px] text-slate-500 font-medium hidden sm:block whitespace-nowrap">
            Wireshark for AI Agents
          </span>
        </div>

        <div className="flex items-center gap-1.5 text-[11px] font-semibold shrink-0">
          <span
            className={`ws-dot ${connected ? 'ws-dot--live' : 'ws-dot--dead'}`}
            aria-label={connected ? 'Connected' : 'Disconnected'}
          />
          <span className={connected ? 'text-emerald-400' : 'text-red-400'}>
            {connected ? 'Live' : 'Offline'}
          </span>
        </div>

        <div
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-extrabold uppercase tracking-widest shrink-0 ${threatStyle}`}
          aria-label={`System threat level: ${systemThreatLevel}`}
        >
          <Shield className="w-3 h-3" />
          {systemThreatLevel}
        </div>

        <div className="relative flex items-center shrink-0" ref={dropdownRef}>
          <button
            id="btn-simulate-injection"
            disabled={injecting}
            onClick={handleInject}
            className="inject-btn inject-btn--main"
            aria-busy={injecting}
          >
            {injecting
              ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
              : <span aria-hidden>🔴</span>
            }
            <span>Simulate {currentLabel}</span>
          </button>

          <button
            id="btn-scenario-dropdown"
            onClick={() => setDropdownOpen((v) => !v)}
            className="inject-btn inject-btn--caret"
            aria-haspopup="listbox"
            aria-expanded={dropdownOpen}
            aria-label="Choose scenario"
          >
            <ChevronDown
              className="w-3.5 h-3.5 transition-transform duration-200"
              style={{ transform: dropdownOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}
            />
          </button>

          {dropdownOpen && (
            <ul role="listbox" className="scenario-menu">
              {SCENARIOS.map((s) => (
                <li key={s.value} role="none">
                  <button
                    role="option"
                    aria-selected={scenario === s.value}
                    onClick={() => { setScenario(s.value); setDropdownOpen(false); }}
                    className={`scenario-option ${scenario === s.value ? 'scenario-option--active' : ''}`}
                  >
                    {s.label}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </header>

      <div className="app-grid">
        <aside className="panel panel--left" aria-label="Trust Panel">
          <div className="panel-inner">
            <TrustPanel />
          </div>
        </aside>

        <main className="panel panel--center" aria-label="Agent Graph">
          <AgentGraph />
        </main>

        <aside className="panel panel--right" aria-label="Alert Feed">
          <div className="panel-inner">
            <AlertFeed />
          </div>
        </aside>
      </div>

      <ReplayBar />
    </div>
  );
}