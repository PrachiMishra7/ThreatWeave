import { useState, useMemo, useCallback, useEffect } from "react";
import {
  ReactFlow,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  MarkerType
} from "@xyflow/react";
import '@xyflow/react/dist/style.css';
import { CampaignNode, AlertNode, IOCNode } from "../components/graph/CustomNodes";
import { X, ExternalLink, Network, RefreshCw, Loader2, Play, TerminalSquare } from "lucide-react";
import { useCampaigns } from "../hooks/useCampaigns";
import { useAlerts } from "../hooks/useAlerts";
import { useTheme } from "../context/ThemeContext";

const nodeTypes = {
  campaign: CampaignNode,
  alert: AlertNode,
  ioc: IOCNode,
};

// Helper functions for Neo4j Node/Edge conversion and layout styling
function mapNeo4jLabelToReactFlowType(label: string) {
  const l = label?.toLowerCase();
  if (l === "campaign") return "campaign";
  if (l === "alert") return "alert";
  return "ioc";
}

function mapNeo4jLabelToSidebarType(label: string) {
  const l = label?.toLowerCase();
  if (l === "campaign") return "campaign";
  if (l === "alert") return "alert";
  return "ioc";
}

function layoutGraph(rawNodes: any[], rawEdges: any[], campaigns: any[], alerts: any[]) {
  const nodes = [...rawNodes];
  const edges = [...rawEdges];

  const nodeMap = new Map<string, any>();

  const campaignsList = nodes.filter(n => n.type?.toLowerCase() === "campaign");

  // Build adjacency list for layout computation
  const adj = new Map<string, string[]>();
  edges.forEach(e => {
    if (!adj.has(e.source)) adj.set(e.source, []);
    adj.get(e.source)!.push(e.target);
    if (!adj.has(e.target)) adj.set(e.target, []);
    adj.get(e.target)!.push(e.source);
  });

  nodes.forEach(n => {
    const rfType = mapNeo4jLabelToReactFlowType(n.type);
    const sidebarType = mapNeo4jLabelToSidebarType(n.type);

    let fullData = { ...n.properties };
    let label = n.label;
    let actor = "Unknown";
    let severity = "MEDIUM";

    if (rfType === "campaign") {
      const matchedCamp = campaigns.find((c: any) => c.name?.toLowerCase() === n.label?.toLowerCase());

      const connectedActors = (adj.get(n.id) || [])
        .map(id => nodes.find(node => node.id === id))
        .filter((node): node is any => !!node && node.type?.toLowerCase() === "threatactor");

      if (connectedActors.length > 0) {
        actor = connectedActors[0].label;
      } else if (matchedCamp && matchedCamp.threatActor) {
        actor = matchedCamp.threatActor;
      }

      fullData = {
        threatActor: actor,
        riskScore: matchedCamp?.riskScore || Math.min(70 + (adj.get(n.id) || []).length * 5, 95),
        confidence: matchedCamp?.confidence || 85,
        summary: matchedCamp?.summary || `Threat campaign containing alerts parsed from correlation.`,
        ...matchedCamp,
        ...n.properties
      };
    } else if (rfType === "alert") {
      const matchedAlert = alerts.find((a: any) => a.id === n.properties.id || a.title?.toLowerCase() === n.label?.toLowerCase());
      severity = n.properties.severity || matchedAlert?.severity || "MEDIUM";

      fullData = {
        sourceSystem: n.properties.sourceSystem || matchedAlert?.sourceSystem || "SIEM",
        description: n.properties.description || matchedAlert?.description || `Security alert: ${n.label}`,
        affectedAsset: n.properties.affectedAsset || matchedAlert?.affectedAsset || "Internal Network",
        mitreTTPs: matchedAlert?.mitreTTPs || [],
        ...matchedAlert,
        ...n.properties
      };
    } else if (rfType === "ioc") {
      let iocType = n.type || "IOC";
      if (n.type?.toLowerCase() === "mitretactic") {
        iocType = "tactic";
      } else if (n.type?.toLowerCase() === "threatactor") {
        iocType = "actor";
      }

      fullData = {
        value: n.properties.value || n.properties.name || n.label,
        type: iocType,
        ...n.properties
      };
    }

    nodeMap.set(n.id, {
      id: n.id,
      type: rfType,
      position: { x: 0, y: 0 },
      data: {
        label,
        actor,
        severity,
        iocType: n.type || "IOC",
        fullData,
        nodeType: sidebarType
      }
    });
  });

  const placedNodeIds = new Set<string>();

  // 1. Layout Campaigns and their subtrees
  const campaignSpacing = 600;
  const startX = 200;

  campaignsList.forEach((campNode, campIdx) => {
    const campX = startX + campIdx * campaignSpacing;
    const campY = 180;

    const campFlow = nodeMap.get(campNode.id);
    if (campFlow) {
      campFlow.position = { x: campX, y: campY };
      placedNodeIds.add(campNode.id);
    }

    // A. Threat Actors connected to this Campaign (above campaign)
    const connectedActors = (adj.get(campNode.id) || [])
      .map(id => nodeMap.get(id))
      .filter((n): n is any => !!n && n.type === "ioc" && n.data.nodeType === "ioc" && n.data.iocType?.toLowerCase() === "threatactor");

    connectedActors.forEach((actorFlow, actorIdx) => {
      if (!placedNodeIds.has(actorFlow.id)) {
        actorFlow.position = {
          x: campX + (actorIdx - (connectedActors.length - 1) / 2) * 180,
          y: 40
        };
        placedNodeIds.add(actorFlow.id);
      }
    });

    // B. MITRE Tactics connected to this Campaign (left side of campaign)
    const connectedTactics = (adj.get(campNode.id) || [])
      .map(id => nodeMap.get(id))
      .filter((n): n is any => !!n && n.type === "ioc" && n.data.nodeType === "ioc" && n.data.iocType?.toLowerCase() === "mitretactic");

    connectedTactics.forEach((tacticFlow, tacticIdx) => {
      if (!placedNodeIds.has(tacticFlow.id)) {
        tacticFlow.position = {
          x: campX - 220,
          y: campY - 50 + tacticIdx * 90
        };
        placedNodeIds.add(tacticFlow.id);
      }
    });

    // C. Alerts connected to this Campaign (below campaign)
    const campaignAlerts = (adj.get(campNode.id) || [])
      .map(id => nodeMap.get(id))
      .filter((n): n is any => !!n && n.type === "alert");

    const alertSpacing = 240;

    campaignAlerts.forEach((alertFlow, alertIdx) => {
      const alertX = campX - ((campaignAlerts.length - 1) / 2) * alertSpacing + alertIdx * alertSpacing;
      const alertY = 320;

      if (!placedNodeIds.has(alertFlow.id)) {
        alertFlow.position = { x: alertX, y: alertY };
        placedNodeIds.add(alertFlow.id);
      }

      // D. IOCs connected to this Alert (below alert)
      const alertIocs = (adj.get(alertFlow.id) || [])
        .map(id => nodeMap.get(id))
        .filter((n): n is any => !!n && n.type === "ioc" && n.data.iocType?.toLowerCase() !== "mitretactic" && n.data.iocType?.toLowerCase() !== "threatactor");

      const iocSpacing = 160;

      alertIocs.forEach((iocFlow, iocIdx) => {
        if (!placedNodeIds.has(iocFlow.id)) {
          iocFlow.position = {
            x: alertX - ((alertIocs.length - 1) / 2) * iocSpacing + iocIdx * iocSpacing,
            y: 480
          };
          placedNodeIds.add(iocFlow.id);
        }
      });
    });
  });

  // 2. Place any remaining nodes that weren't reached by the campaign tree
  const remainingNodes = Array.from(nodeMap.values()).filter(n => !placedNodeIds.has(n.id));
  const cols = 5;
  const remSpacingX = 220;
  const remSpacingY = 120;
  const remStartX = 100;
  const remStartY = 620;

  remainingNodes.forEach((flowNode, idx) => {
    const row = Math.floor(idx / cols);
    const col = idx % cols;
    flowNode.position = {
      x: remStartX + col * remSpacingX,
      y: remStartY + row * remSpacingY
    };
    placedNodeIds.add(flowNode.id);
  });

  const reactFlowNodes = Array.from(nodeMap.values());

  const reactFlowEdges = edges.map(e => {
    const edgeType = e.label || "";
    let style: any = { stroke: '#475569', strokeWidth: 1.5 };
    let animated = false;
    let markerEnd: any = undefined;

    if (edgeType === "CONTAINS") {
      style = { stroke: '#14b8a6', strokeWidth: 2 };
      animated = true;
      markerEnd = { type: MarkerType.ArrowClosed, color: '#14b8a6' };
    } else if (edgeType === "USES_TACTIC") {
      style = { stroke: '#f43f5e', strokeWidth: 1.5, strokeDasharray: '3,3' };
      markerEnd = { type: MarkerType.ArrowClosed, color: '#f43f5e' };
    } else if (edgeType === "ATTRIBUTED_TO") {
      style = { stroke: '#a855f7', strokeWidth: 2 };
      markerEnd = { type: MarkerType.ArrowClosed, color: '#a855f7' };
    } else if (edgeType === "CORRELATES_TO") {
      style = { stroke: '#f59e0b', strokeWidth: 2, strokeDasharray: '5,5' };
      animated = true;
      markerEnd = { type: MarkerType.ArrowClosed, color: '#f59e0b' };
    }

    return {
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      style,
      animated,
      markerEnd
    };
  });

  return { reactFlowNodes, reactFlowEdges };
}

export default function GraphExplorer() {
  const [selectedNodeData, setSelectedNodeData] = useState<any | null>(null);
  const { campaigns, loading: camLoading, refresh: refreshCampaigns } = useCampaigns();
  const { alerts, loading: alertLoading } = useAlerts(100);
  const { theme } = useTheme();

  const [graphData, setGraphData] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });
  const [graphLoading, setGraphLoading] = useState(true);
  const [graphError, setGraphError] = useState<string | null>(null);

  // Custom Query State
  const [queryMode, setQueryMode] = useState(false);
  const [cypherQuery, setCypherQuery] = useState("MATCH (n)-[r]->(m) RETURN n,r,m LIMIT 50");
  const [queryRunning, setQueryRunning] = useState(false);

  const fetchGraph = useCallback(async () => {
    setGraphLoading(true);
    setGraphError(null);
    try {
      const res = await fetch("/api/graph");
      if (!res.ok) {
        let errMessage = "Failed to fetch Neo4j graph data";
        try {
          const errData = await res.json();
          if (errData.error) errMessage = errData.error;
        } catch (e) {
          // Ignore JSON parse errors if response is plain text
        }
        throw new Error(errMessage);
      }
      const data = await res.json();
      setGraphData(data);
    } catch (err: any) {
      setGraphError(err.message || "Failed to load Neo4j graph");
    } finally {
      setGraphLoading(false);
    }
  }, []);

  const runCustomQuery = async () => {
    if (!cypherQuery.trim()) return;
    setQueryRunning(true);
    setGraphError(null);
    try {
      const res = await fetch("/api/graph/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: cypherQuery })
      });
      
      let data: any = {};
      const text = await res.text();
      try {
        if (text) data = JSON.parse(text);
      } catch (e) {
        throw new Error(`Server returned invalid response: ${text.substring(0, 50)}`);
      }

      if (!res.ok) throw new Error(data.error || `HTTP ${res.status} Error`);
      setGraphData(data);
    } catch (err: any) {
      setGraphError(err.message || "Custom query failed");
    } finally {
      setQueryRunning(false);
    }
  };

  const refresh = useCallback(async () => {
    refreshCampaigns();
    await fetchGraph();
  }, [refreshCampaigns, fetchGraph]);

  useEffect(() => {
    fetchGraph();
  }, [fetchGraph]);

  const loading = camLoading || alertLoading || graphLoading;

  const { initialNodes, initialEdges } = useMemo(() => {
    if (!graphData.nodes || graphData.nodes.length === 0) {
      return { initialNodes: [], initialEdges: [] };
    }

    // Deduplicate edges to prevent warnings
    const uniqueEdges = new Map<string, any>();
    graphData.edges.forEach((e: any) => {
      uniqueEdges.set(`${e.source}-${e.target}-${e.label}`, e);
    });
    const dedupedEdges = Array.from(uniqueEdges.values());

    const { reactFlowNodes, reactFlowEdges } = layoutGraph(graphData.nodes, dedupedEdges, campaigns, alerts);
    return { initialNodes: reactFlowNodes, initialEdges: reactFlowEdges };
  }, [graphData, campaigns, alerts]);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  // Sync computed nodes/edges into ReactFlow state whenever API data arrives.
  useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  const onNodeClick = useCallback((_: any, node: Node) => {
    setSelectedNodeData(node.data);
  }, []);

  return (
    <div className="flex h-[calc(100vh-8rem)] gap-4">

      {/* Graph Canvas */}
      <div className="flex-1 glass glow-teal rounded-xl overflow-hidden relative">

        <div className="absolute top-4 left-4 z-10 pointer-events-none">
          <h2 className="text-xl font-bold text-white flex items-center gap-2 drop-shadow-md">
            <Network className="h-5 w-5 text-teal-500" />
            Attack Chain Matrix
          </h2>
          <p className="text-xs font-mono text-slate-400 mt-1 drop-shadow-md">
            Interactive node relationships from the live correlation engine.
          </p>
        </div>

        {/* Top Controls */}
        <div className="absolute top-4 right-4 z-10 flex flex-col items-end gap-2">
          <div className="flex gap-2">
            <button
              onClick={() => setQueryMode(!queryMode)}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg backdrop-blur border transition-all ${
                queryMode 
                  ? "bg-teal-500/20 border-teal-500/50 text-teal-400" 
                  : "bg-slate-800/80 border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white"
              }`}
            >
              <TerminalSquare className="h-3.5 w-3.5" />
              Cypher
            </button>
            <button
              onClick={refresh}
              disabled={loading || queryRunning}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800/80 backdrop-blur border border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white transition-all disabled:opacity-40"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${(loading || queryRunning) ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
          
          {/* Cypher Query Panel */}
          {queryMode && (
            <div className="bg-slate-900/95 glass border border-slate-700 rounded-xl p-4 shadow-2xl w-[450px] animate-in slide-in-from-top-2">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-2">
                <TerminalSquare className="h-4 w-4 text-teal-500" />
                Custom Neo4j Query
              </h3>
              <textarea
                value={cypherQuery}
                onChange={(e) => setCypherQuery(e.target.value)}
                placeholder="MATCH (n)-[r]->(m) RETURN n,r,m LIMIT 50"
                className="w-full h-24 bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-teal-400 focus:outline-none focus:border-teal-500/50 focus:ring-1 focus:ring-teal-500/50 transition-all resize-none"
              />
              
              {/* Sample Queries */}
              <div className="mt-2 flex flex-wrap gap-2">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider w-full mb-1">Samples:</span>
                {[
                  { label: "Critical Alerts", query: 'MATCH (a:Alert {severity: "CRITICAL"})-[r]-(c) RETURN a,r,c LIMIT 30' },
                  { label: "Shared IPs", query: 'MATCH (a1:Alert)-[:USES]->(ip:IP)<-[:USES]-(a2:Alert) WHERE a1 <> a2 RETURN a1,a2,ip LIMIT 25' },
                  { label: "MITRE Tactics", query: 'MATCH (c:Campaign)-[r:USES_TACTIC]->(t:MitreTactic) RETURN c,r,t LIMIT 30' },
                  { label: "Show All", query: 'MATCH (n)-[r]->(m) RETURN n,r,m LIMIT 100' }
                ].map((sample, idx) => (
                  <button
                    key={idx}
                    onClick={() => setCypherQuery(sample.query)}
                    className="px-2 py-1 bg-slate-800 hover:bg-teal-500/20 text-slate-300 hover:text-teal-400 border border-slate-700 hover:border-teal-500/50 rounded text-[10px] font-mono transition-colors"
                  >
                    {sample.label}
                  </button>
                ))}
              </div>
              <div className="flex justify-between items-center mt-3">
                <span className="text-[10px] text-slate-500 font-mono">Press Run to execute against graph DB</span>
                <button
                  onClick={runCustomQuery}
                  disabled={queryRunning || !cypherQuery.trim()}
                  className="flex items-center gap-1.5 px-4 py-1.5 bg-teal-500 hover:bg-teal-400 text-slate-950 text-xs font-bold rounded-lg transition-colors disabled:opacity-50"
                >
                  {queryRunning ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5 fill-current" />}
                  Run Query
                </button>
              </div>
            </div>
          )}
        </div>

        {loading ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 text-slate-500">
            <Loader2 className="h-8 w-8 animate-spin text-teal-500" />
            <p className="text-sm font-mono">Running correlation engine...</p>
          </div>
        ) : graphError ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 text-red-500 bg-red-500/5 p-6 text-center">
            <Network className="h-10 w-10 opacity-50" />
            <p className="text-sm font-mono font-bold">Database Connection Failed</p>
            <p className="text-xs font-mono opacity-80">{graphError}</p>
          </div>
        ) : nodes.length === 0 ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 text-slate-500">
            <Network className="h-10 w-10 opacity-20" />
            <p className="text-sm font-mono">No correlation data available yet.</p>
          </div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.2}
          >
            <Background color={theme === 'dark' ? "#334155" : "#cbd5e1"} gap={24} size={2} />
            <Controls className="bg-slate-900 border-slate-700 fill-white" />
          </ReactFlow>
        )}
      </div>

      {/* Details Side Panel */}
      {selectedNodeData && (
        <div className="w-80 glass glow-indigo border-indigo-500/30 rounded-xl flex flex-col shadow-2xl overflow-hidden animate-in slide-in-from-right-4 duration-300">
          <div className="p-4 border-b border-slate-800/60 flex items-center justify-between bg-slate-900/40 backdrop-blur-md">
            <h3 className="font-semibold text-sm text-slate-200 uppercase tracking-wider">
              {selectedNodeData.nodeType} Details
            </h3>
            <button
              onClick={() => setSelectedNodeData(null)}
              className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="p-5 overflow-y-auto flex-1 flex flex-col gap-4">
            <div>
              <p className="text-xs text-slate-500 font-mono mb-1">Identifier</p>
              <p className="font-semibold text-slate-200 break-words">{selectedNodeData.label}</p>
            </div>

            {selectedNodeData.nodeType === "alert" && (
              <>
                <div>
                  <p className="text-xs text-slate-500 font-mono mb-1">Severity</p>
                  <SeverityBadge severity={selectedNodeData.severity} />
                </div>
                <div>
                  <p className="text-xs text-slate-500 font-mono mb-1">System</p>
                  <p className="text-sm font-mono text-slate-300">{selectedNodeData.fullData.sourceSystem}</p>
                </div>
                {selectedNodeData.fullData.affectedAsset && (
                  <div>
                    <p className="text-xs text-slate-500 font-mono mb-1">Affected Asset</p>
                    <p className="text-sm font-mono text-slate-300">{selectedNodeData.fullData.affectedAsset}</p>
                  </div>
                )}
                <div>
                  <p className="text-xs text-slate-500 font-mono mb-1">Description</p>
                  <p className="text-xs text-slate-400 leading-relaxed">{selectedNodeData.fullData.description}</p>
                </div>
                {selectedNodeData.fullData.mitreTTPs?.length > 0 && (
                  <div>
                    <p className="text-xs text-slate-500 font-mono mb-1">MITRE TTPs</p>
                    <div className="flex flex-wrap gap-1">
                      {selectedNodeData.fullData.mitreTTPs.map((ttp: string) => (
                        <span key={ttp} className="text-[10px] font-mono px-1.5 py-0.5 bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 rounded">
                          {ttp.split(" ")[0]}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}

            {selectedNodeData.nodeType === "campaign" && (
              <>
                <div>
                  <p className="text-xs text-slate-500 font-mono mb-1">Threat Actor</p>
                  <p className="text-sm font-semibold text-indigo-400">{selectedNodeData.fullData.threatActor}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 font-mono mb-1">Risk Score</p>
                  <p className="text-lg font-bold font-mono text-red-500">{selectedNodeData.fullData.riskScore}%</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 font-mono mb-1">Confidence</p>
                  <p className="text-sm font-bold font-mono text-teal-400">{selectedNodeData.fullData.confidence}%</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 font-mono mb-1">Summary</p>
                  <p className="text-xs text-slate-400 leading-relaxed">{selectedNodeData.fullData.summary}</p>
                </div>
              </>
            )}

            {selectedNodeData.nodeType === "ioc" && (
              <>
                <div>
                  <p className="text-xs text-slate-500 font-mono mb-1">Type</p>
                  <p className="text-sm font-mono text-sky-400 uppercase">{selectedNodeData.iocType}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 font-mono mb-1">Value</p>
                  <p className="text-xs font-mono text-slate-300 break-all">{selectedNodeData.fullData.value}</p>
                </div>
                {selectedNodeData.iocType?.toLowerCase() !== "mitretactic" && selectedNodeData.iocType?.toLowerCase() !== "threatactor" && (
                  <button className="mt-2 w-full py-2 bg-slate-800 hover:bg-slate-700 transition-colors border border-slate-700 rounded-lg text-xs font-semibold text-slate-300 flex items-center justify-center gap-2">
                    <ExternalLink className="h-3.5 w-3.5" />
                    Run External Lookup
                  </button>
                )}
              </>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
