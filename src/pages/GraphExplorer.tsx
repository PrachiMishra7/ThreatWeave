import { useState, useMemo, useCallback } from "react";
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
import { mockCampaigns, mockAlerts } from "../mockData";
import { X, ExternalLink, Network } from "lucide-react";
import { SeverityBadge } from "../components/ui/SeverityBadge";

const nodeTypes = {
  campaign: CampaignNode,
  alert: AlertNode,
  ioc: IOCNode,
};

export default function GraphExplorer() {
  const [selectedNodeData, setSelectedNodeData] = useState<any | null>(null);

  // Derive nodes and edges from mock data
  const { initialNodes, initialEdges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const activeCamp = mockCampaigns[0];

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

    // 2. Alert Nodes
    const relatedAlerts = mockAlerts.slice(0, 4);
    relatedAlerts.forEach((alert, index) => {
      const alertId = `alert-${alert.id}`;
      nodes.push({
        id: alertId,
        type: "alert",
        position: { x: 100 + (index * 200), y: 250 },
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

      // 3. IOC Nodes for each alert
      alert.iocs.forEach((ioc, iocIndex) => {
        const iocId = `ioc-${ioc.type}-${ioc.value.replace(/[^a-zA-Z0-9]/g, "")}`;
        
        // Prevent duplicate IOC nodes
        if (!nodes.find(n => n.id === iocId)) {
          nodes.push({
            id: iocId,
            type: "ioc",
            position: { x: 50 + (index * 200) + (iocIndex * 150), y: 450 },
            data: {
              label: ioc.value,
              iocType: ioc.type,
              fullData: ioc,
              nodeType: "ioc"
            }
          });
        }

        edges.push({
          id: `edge-${alertId}-${iocId}`,
          source: alertId,
          target: iocId,
          style: { stroke: '#475569', strokeWidth: 1.5 },
        });
      });
    });

    return { initialNodes: nodes, initialEdges: edges };
  }, []);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

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
            Interactive node relationships based on threat intelligence correlations.
          </p>
        </div>

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
                <div>
                  <p className="text-xs text-slate-500 font-mono mb-1">Description</p>
                  <p className="text-xs text-slate-400 leading-relaxed">{selectedNodeData.fullData.description}</p>
                </div>
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
