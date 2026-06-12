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
import { X, ExternalLink, Network, RefreshCw, Loader2 } from "lucide-react";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { useCampaigns } from "../hooks/useCampaigns";
import { useAlerts } from "../hooks/useAlerts";

const nodeTypes = {
  campaign: CampaignNode,
  alert: AlertNode,
  ioc: IOCNode,
};

export default function GraphExplorer() {
  const [selectedNodeData, setSelectedNodeData] = useState<any | null>(null);
  const { campaigns, loading: camLoading, refresh } = useCampaigns();
  const { alerts, loading: alertLoading } = useAlerts(20);

  const loading = camLoading || alertLoading;

  // Derive nodes and edges from live API data
  const { initialNodes, initialEdges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];

    if (campaigns.length === 0 || alerts.length === 0) {
      return { initialNodes: nodes, initialEdges: edges };
    }

    // Use the highest-risk campaign as the center node
    const activeCamp = campaigns[0];

    // 1. Center Campaign Node
    nodes.push({
      id: `camp-${activeCamp.id}`,
      type: "campaign",
      position: { x: 400, y: 50 },
      data: {
        label: activeCamp.name,
        actor: activeCamp.threatActor,
        fullData: activeCamp,
        nodeType: "campaign"
      }
    });

    // 2. Alert Nodes — take up to 5 alerts
    const relatedAlerts = alerts.slice(0, 5);
    relatedAlerts.forEach((alert, index) => {
      const alertId = `alert-${alert.id}`;
      const xPos = 80 + (index * 220);

      nodes.push({
        id: alertId,
        type: "alert",
        position: { x: xPos, y: 260 },
        data: {
          label: alert.title,
          severity: alert.severity,
          fullData: alert,
          nodeType: "alert"
        }
      });

      edges.push({
        id: `edge-${activeCamp.id}-${alert.id}`,
        source: `camp-${activeCamp.id}`,
        target: alertId,
        animated: true,
        style: { stroke: '#14b8a6', strokeWidth: 2, strokeDasharray: '5,5' },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#14b8a6' },
      });

      // 3. IOC Nodes for each alert (max 2 per alert to avoid overflow)
      alert.iocs.slice(0, 2).forEach((ioc, iocIndex) => {
        const iocId = `ioc-${ioc.type}-${ioc.value.replace(/[^a-zA-Z0-9]/g, "").substring(0, 20)}`;

        if (!nodes.find(n => n.id === iocId)) {
          nodes.push({
            id: iocId,
            type: "ioc",
            position: { x: xPos - 40 + (iocIndex * 140), y: 460 },
            data: {
              label: ioc.value.length > 22 ? `${ioc.value.substring(0, 19)}...` : ioc.value,
              iocType: ioc.type,
              fullData: ioc,
              nodeType: "ioc"
            }
          });
        }

        edges.push({
          id: `edge-${alertId}-${iocId}-${iocIndex}`,
          source: alertId,
          target: iocId,
          style: { stroke: '#475569', strokeWidth: 1.5 },
        });
      });
    });

    // 4. If there's a second campaign, add it as a secondary node
    if (campaigns.length > 1) {
      const secondCamp = campaigns[1];
      nodes.push({
        id: `camp-${secondCamp.id}`,
        type: "campaign",
        position: { x: 850, y: 50 },
        data: {
          label: secondCamp.name,
          actor: secondCamp.threatActor,
          fullData: secondCamp,
          nodeType: "campaign"
        }
      });

      // Link a couple alerts to the second campaign too
      alerts.slice(5, 8).forEach((alert, index) => {
        const alertId = `alert2-${alert.id}`;
        nodes.push({
          id: alertId,
          type: "alert",
          position: { x: 700 + index * 200, y: 260 },
          data: {
            label: alert.title,
            severity: alert.severity,
            fullData: alert,
            nodeType: "alert"
          }
        });
        edges.push({
          id: `edge2-${secondCamp.id}-${alert.id}`,
          source: `camp-${secondCamp.id}`,
          target: alertId,
          animated: true,
          style: { stroke: '#f59e0b', strokeWidth: 2, strokeDasharray: '5,5' },
          markerEnd: { type: MarkerType.ArrowClosed, color: '#f59e0b' },
        });
      });
    }

    return { initialNodes: nodes, initialEdges: edges };
  }, [campaigns, alerts]);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  // Sync computed nodes/edges into ReactFlow state whenever API data arrives.
  // useNodesState/useEdgesState only use their constructor arg once (like useState),
  // so we must explicitly push updates when useMemo recomputes after async load.
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
      <div className="flex-1 bg-slate-950 border border-slate-800 rounded-xl overflow-hidden relative shadow-inner">

        <div className="absolute top-4 left-4 z-10 pointer-events-none">
          <h2 className="text-xl font-bold text-white flex items-center gap-2 drop-shadow-md">
            <Network className="h-5 w-5 text-teal-500" />
            Attack Chain Matrix
          </h2>
          <p className="text-xs font-mono text-slate-400 mt-1 drop-shadow-md">
            Interactive node relationships from the live correlation engine.
          </p>
        </div>

        {/* Refresh button */}
        <button
          onClick={refresh}
          disabled={loading}
          className="absolute top-4 right-4 z-10 flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800/80 backdrop-blur border border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white transition-all disabled:opacity-40"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>

        {loading ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 text-slate-500">
            <Loader2 className="h-8 w-8 animate-spin text-teal-500" />
            <p className="text-sm font-mono">Running correlation engine...</p>
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
            className="bg-slate-950"
            minZoom={0.2}
          >
            <Background color="#334155" gap={24} size={2} />
            <Controls className="bg-slate-900 border-slate-700 fill-white" />
          </ReactFlow>
        )}
      </div>

      {/* Details Side Panel */}
      {selectedNodeData && (
        <div className="w-80 bg-slate-900 border border-slate-800 rounded-xl flex flex-col shadow-xl overflow-hidden animate-in slide-in-from-right-4 duration-200">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
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
                <button className="mt-2 w-full py-2 bg-slate-800 hover:bg-slate-700 transition-colors border border-slate-700 rounded-lg text-xs font-semibold text-slate-300 flex items-center justify-center gap-2">
                  <ExternalLink className="h-3.5 w-3.5" />
                  Run External Lookup
                </button>
              </>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
