'use client';

import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  ReactFlow,
  ReactFlowProvider,
  Controls,
  Background,
  MarkerType,
  Position,
  Handle,
  BaseEdge,
  EdgeProps,
  getBezierPath,
} from '@xyflow/react';
import { Search, Brain, Terminal, Shield, AlertTriangle } from 'lucide-react';
import { useAppStore } from '@/lib/store';

// Import ReactFlow styles
import '@xyflow/react/dist/style.css';

// ---------------------------------------------------------
// Custom CSS Keyframe Animations for Premium Visuals
// ---------------------------------------------------------
const GRAPH_STYLES = `
  @keyframes slow-pulse {
    0%, 100% {
      box-shadow: 0 0 10px rgba(239, 68, 68, 0.4);
      border-color: rgba(239, 68, 68, 0.7);
    }
    50% {
      box-shadow: 0 0 20px rgba(239, 68, 68, 0.8);
      border-color: rgba(239, 68, 68, 1);
    }
  }

  @keyframes fast-pulse {
    0%, 100% {
      box-shadow: 0 0 12px rgba(153, 27, 27, 0.6);
      border-color: rgba(153, 27, 27, 0.8);
      transform: scale(1);
    }
    50% {
      box-shadow: 0 0 26px rgba(239, 68, 68, 1);
      border-color: rgba(239, 68, 68, 1);
      transform: scale(1.02);
    }
  }

  @keyframes attack-pulse {
    0%, 100% {
      outline: 3px solid rgba(239, 68, 68, 0.9);
      outline-offset: 2px;
      transform: scale(1);
    }
    50% {
      outline: 6px solid rgba(239, 68, 68, 0);
      outline-offset: 6px;
      transform: scale(1.06);
    }
  }

  @keyframes flash-injection {
    0%, 100% {
      stroke-dashoffset: 0;
      stroke: #ef4444;
      opacity: 1;
    }
    50% {
      stroke-dashoffset: 8;
      stroke: #f97316;
      opacity: 0.6;
    }
  }

  .animate-slow-pulse {
    animation: slow-pulse 2s infinite ease-in-out;
  }

  .animate-fast-pulse {
    animation: fast-pulse 0.75s infinite ease-in-out;
  }

  .animate-attack-pulse {
    animation: attack-pulse 1s infinite ease-in-out;
  }

  .animate-flash-injection {
    animation: flash-injection 1s infinite linear;
  }
`;

// Helper to format ISO timestamps to local time
const formatTime = (isoString?: string | null) => {
  if (!isoString) return 'unknown time';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return isoString;
  }
};

// ---------------------------------------------------------
// Custom Node Component: AgentNode
// ---------------------------------------------------------
interface NodeData {
  id: string;
  name: string;
  trustScore: number;
  status: string;
  underAttack: boolean;
  taintLevel?: number;
  infectedAt?: string | null;
  taintSource?: string | null;
}

function AgentNode({ data }: { data: NodeData }) {
  const { id, name, trustScore, underAttack, taintLevel } = data;

  // 1. Ring color by trust: green>70, yellow 40-70, red<40
  let ringClasses = 'border-slate-300';
  let ringStyles: React.CSSProperties = {};

  if (trustScore > 70) {
    ringClasses = 'border-emerald-500';
  } else if (trustScore >= 40) {
    ringClasses = 'border-yellow-500';
  } else {
    ringClasses = 'border-red-500';
  }

  // 2. Taint-based override: 
  // - 0-0.1 green
  // - 0.1-0.3 yellow glow
  // - 0.3-0.6 orange glow
  // - 0.6-0.8 red slow-pulse
  // - 0.8-1.0 deep red fast-pulse + "COMPROMISED" badge
  let isCompromised = false;
  let taintOverlayClass = '';

  if (taintLevel !== undefined) {
    if (taintLevel <= 0.1) {
      ringClasses = 'border-emerald-500';
      ringStyles = {};
    } else if (taintLevel <= 0.3) {
      ringClasses = 'border-yellow-400';
      ringStyles = { boxShadow: '0 0 12px #facc15' };
    } else if (taintLevel <= 0.6) {
      ringClasses = 'border-orange-500';
      ringStyles = { boxShadow: '0 0 15px #f97316' };
    } else if (taintLevel <= 0.8) {
      ringClasses = 'border-red-500';
      taintOverlayClass = 'animate-slow-pulse';
    } else {
      ringClasses = 'border-red-800';
      taintOverlayClass = 'animate-fast-pulse';
      isCompromised = true;
    }
  }

  // Under attack pulse animation override/addition
  const attackClass = underAttack ? 'animate-attack-pulse' : '';

  // Get nice role icons
  const idLower = id.toLowerCase();
  let IconComponent = Shield;
  if (idLower.includes('researcher')) {
    IconComponent = Search;
  } else if (idLower.includes('planner')) {
    IconComponent = Brain;
  } else if (idLower.includes('executor')) {
    IconComponent = Terminal;
  }

  // Clean short name
  const shortName = name.replace('-agent', '');

  return (
    <div
      className={`w-20 h-20 rounded-2xl flex flex-col items-center justify-center p-2 text-center relative bg-slate-900 border text-slate-100 transition-all duration-500 ease-in-out select-none ${ringClasses} ${taintOverlayClass} ${attackClass}`}
      style={ringStyles}
    >
      {/* Absolute Centered Handles to maintain symmetrical radial connections */}
      <Handle
        type="target"
        position={Position.Top}
        id="target"
        style={{ top: '50%', left: '50%', transform: 'translate(-50%, -50%)', opacity: 0, pointerEvents: 'none' }}
      />
      <Handle
        type="source"
        position={Position.Bottom}
        id="source"
        style={{ top: '50%', left: '50%', transform: 'translate(-50%, -50%)', opacity: 0, pointerEvents: 'none' }}
      />

      {/* Role Icon */}
      <div className="mb-1 text-slate-300">
        <IconComponent className="w-5 h-5" />
      </div>

      {/* Node Short Name */}
      <div className="text-[10px] font-bold tracking-tight capitalize truncate w-full text-slate-200">
        {shortName}
      </div>

      {/* Trust Score Percentage Indicator */}
      <div className="text-[9px] font-semibold text-slate-400 mt-0.5">
        {Math.round(trustScore)}%
      </div>

      {/* Taint Badge: "COMPROMISED" for taint levels > 0.8 */}
      {isCompromised && (
        <span className="absolute -bottom-2 px-1.5 py-0.5 text-[7px] font-extrabold uppercase bg-red-600 text-white rounded border border-red-800 tracking-wider shadow-md animate-pulse z-10">
          COMPROMISED
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------
// Custom Edge Component: TaintEdge (Hover Tooltip Chain)
// ---------------------------------------------------------
function TaintEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  markerEnd,
  data,
}: EdgeProps) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetPosition,
    targetX,
    targetY,
  });

  const [isHovered, setIsHovered] = useState(false);

  const sourceName = String(data?.source || '').replace('-agent', '');
  const targetName = String(data?.target || '').replace('-agent', '');
  const timeStr = formatTime(data?.infectedAt);

  return (
    <>
      {/* The visible animated taint line */}
      <BaseEdge
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          ...style,
          stroke: '#ef4444',
          strokeWidth: 2.5,
          strokeDasharray: '5,5',
        }}
      />

      {/* Invisible wider interaction path for effortless hover */}
      <path
        d={edgePath}
        fill="none"
        stroke="transparent"
        strokeWidth={15}
        className="cursor-pointer"
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
      />

      {/* Tooltip Overlay */}
      {isHovered && (
        <foreignObject
          x={labelX - 110}
          y={labelY - 35}
          width={220}
          height={70}
          className="pointer-events-none overflow-visible z-50"
        >
          <div className="bg-slate-900/95 border border-slate-700/80 text-white rounded-lg p-2 text-[10px] shadow-xl text-center font-medium transition-all duration-300">
            Tainted from {sourceName} to {targetName} at {timeStr}
          </div>
        </foreignObject>
      )}
    </>
  );
}

// Map custom component definitions
const nodeTypes = {
  agentNode: AgentNode,
};

const edgeTypes = {
  taintEdge: TaintEdge,
};

// ---------------------------------------------------------
// Main AgentGraph Component
// ---------------------------------------------------------
function AgentGraph() {
  const agents = useAppStore((s) => s.agents);
  const events = useAppStore((s) => s.events);
  const taintMap = useAppStore((s) => s.taintMap);

  const processedEventsRef = useRef<Set<string>>(new Set());
  const [eventEdges, setEventEdges] = useState<any[]>([]);

  // 1. Position Coordinates for Symmetrical Layouts
  const getAgentPosition = (id: string) => {
    const idLower = id.toLowerCase();
    
    // Triangle layout: researcher top-left, planner top-right, executor bottom-center.
    if (idLower.includes('researcher')) {
      return { x: 150, y: 80 };
    }
    if (idLower.includes('planner')) {
      return { x: 450, y: 80 };
    }
    if (idLower.includes('executor')) {
      return { x: 300, y: 280 };
    }

    // Dynamic external boundaries for client browser & external network targets
    if (idLower.includes('browser') || idLower.includes('client')) {
      return { x: 40, y: 180 };
    }
    if (idLower.includes('runtime') || idLower.includes('endpoint') || idLower.includes('external')) {
      return { x: 560, y: 180 };
    }

    return { x: 300, y: 180 };
  };

  // 2. Derive unique agent nodes based on active agents & active telemetries
  const nodes = useMemo(() => {
    const allNodeIds = new Set<string>();
    
    // Seed primary nodes
    agents.forEach((a) => allNodeIds.add(a.id));

    // Incorporate active nodes from events dynamically
    events.forEach((e) => {
      if (e.source) allNodeIds.add(e.source);
      if (e.target) allNodeIds.add(e.target);
    });

    // Incorporate active nodes from taint maps dynamically
    Object.entries(taintMap).forEach(([targetId, taintInfo]) => {
      allNodeIds.add(targetId);
      if (taintInfo.taint_source) allNodeIds.add(taintInfo.taint_source);
    });

    return Array.from(allNodeIds).map((id) => {
      const agent = agents.find((a) => a.id === id);
      const taint = taintMap[id];

      return {
        id,
        type: 'agentNode',
        position: getAgentPosition(id),
        data: {
          id,
          name: agent?.name || id,
          trustScore: agent?.trust_score ?? 100,
          status: agent?.status || 'active',
          underAttack: agent?.underAttack || false,
          taintLevel: taint?.taint_level,
          infectedAt: taint?.infected_at,
          taintSource: taint?.taint_source,
        },
      };
    });
  }, [agents, events, taintMap]);

  // 3. Listen to store events and trigger temporary communication lines
  useEffect(() => {
    const newEdgesToAdd: any[] = [];

    events.forEach((event) => {
      if (!event.source || !event.target) return;

      const eventKey = `${event.source}-${event.target}-${event.type}-${event.timestamp || ''}`;

      if (!processedEventsRef.current.has(eventKey)) {
        processedEventsRef.current.add(eventKey);

        const edgeId = `event-${event.source}-${event.target}-${Math.random()}`;
        const isInjection = String(event.type).toUpperCase() === 'INJECTION';

        const newEdge = {
          id: edgeId,
          source: event.source,
          target: event.target,
          animated: !isInjection,
          style: isInjection
            ? { stroke: '#ef4444', strokeWidth: 3, animation: 'flash-injection 1s infinite linear' }
            : { stroke: '#94a3b8', strokeWidth: 1.5 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isInjection ? '#ef4444' : '#94a3b8',
          },
        };

        newEdgesToAdd.push(newEdge);

        // Auto-remove edges after 3 seconds
        setTimeout(() => {
          setEventEdges((prev) => prev.filter((e) => e.id !== edgeId));
        }, 3000);
      }
    });

    if (newEdgesToAdd.length > 0) {
      setEventEdges((prev) => [...prev, ...newEdgesToAdd]);
    }
  }, [events]);

  // 4. Derive persistent active taint chain edges based on taint mappings
  const taintEdges = useMemo(() => {
    const edges: any[] = [];
    Object.entries(taintMap).forEach(([targetId, taintInfo]) => {
      if (taintInfo.taint_source && taintInfo.taint_level > 0) {
        edges.push({
          id: `taint-${taintInfo.taint_source}-${targetId}`,
          source: taintInfo.taint_source,
          target: targetId,
          type: 'taintEdge',
          animated: true,
          style: {
            stroke: '#ef4444',
            strokeWidth: 2.5,
            strokeDasharray: '5,5',
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: '#ef4444',
          },
          data: {
            source: taintInfo.taint_source,
            target: targetId,
            infectedAt: taintInfo.infected_at,
          },
        });
      }
    });
    return edges;
  }, [taintMap]);

  // Combine both active taints and dynamic communication events
  const edges = useMemo(() => {
    return [...taintEdges, ...eventEdges];
  }, [taintEdges, eventEdges]);

  return (
    <div className="w-full h-full relative bg-slate-950">
      {/* Premium CSS Keyframe Injection */}
      <style>{GRAPH_STYLES}</style>

      {/* Dashboard Top Header Overlay */}
      <div className="absolute top-4 left-4 z-10 pointer-events-none">
        <div className="flex items-center gap-2 bg-slate-900/90 border border-slate-700/50 rounded-lg px-3 py-1.5 shadow-md">
          <AlertTriangle className="w-4 h-4 text-orange-400 animate-pulse" />
          <span className="text-[11px] font-bold text-slate-100 uppercase tracking-wider">
            Network Topology telemetry
          </span>
        </div>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.5}
        maxZoom={1.5}
        nodesDraggable={true}
        nodesConnectable={false}
      >
        <Background variant="grid" color="#334155" gap={20} size={1} className="opacity-30" />
        <Controls className="!bg-slate-900 !border-slate-700 !text-slate-200 fill-slate-200 shadow-lg !rounded-lg overflow-hidden [&>button]:!border-slate-800" />
      </ReactFlow>
    </div>
  );
}

// ---------------------------------------------------------
// Wrapped Entry Point providing ReactFlowProvider
// ---------------------------------------------------------
export default function AgentGraphWrapper() {
  return (
    <ReactFlowProvider>
      <AgentGraph />
    </ReactFlowProvider>
  );
}
