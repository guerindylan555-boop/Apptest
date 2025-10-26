/**
 * Graph Viewer Component
 *
 * Interactive visualization component for UI graph nodes and edges.
 * Supports pan, zoom, node selection, and edge highlighting.
 * Uses SVG for rendering with basic force-directed layout.
 */

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Box, Card, CardContent, Typography, IconButton, Tooltip, Zoom } from '@mui/material';
import {
  ZoomIn as ZoomInIcon,
  ZoomOut as ZoomOutIcon,
  CenterFocusStrong as CenterIcon,
  Refresh as RefreshIcon,
  Fullscreen as FullscreenIcon,
} from '@mui/icons-material';
import { useUIGraphStore } from '../stores/uiGraphStore';
import type { ScreenNode, ActionEdge } from '../stores/uiGraphStore';

interface GraphViewerProps {
  width?: number;
  height?: number;
  showControls?: boolean;
  onNodeSelect?: (node: ScreenNode) => void;
  onEdgeSelect?: (edge: ActionEdge) => void;
  selectedNodeId?: string;
  selectedEdgeId?: string;
}

interface GraphNode extends ScreenNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

interface GraphEdge extends ActionEdge {
  source: GraphNode;
  target: GraphNode | null;
}

interface ViewBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

export const GraphViewer: React.FC<GraphViewerProps> = ({
  width = 800,
  height = 600,
  showControls = true,
  onNodeSelect,
  onEdgeSelect,
  selectedNodeId,
  selectedEdgeId,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const [viewBox, setViewBox] = useState<ViewBox>({ x: 0, y: 0, width, height });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0, viewBoxX: 0, viewBoxY: 0 });

  const {
    nodes,
    edges,
    loading,
    error,
    fetchGraph,
  } = useUIGraphStore();

  // Convert store data to graph format
  const graphData = useMemo(() => {
    const nodeMap = new Map<string, GraphNode>();

    // Create nodes with random initial positions
    const graphNodes: GraphNode[] = nodes.map((node, index) => {
      const angle = (index / nodes.length) * 2 * Math.PI;
      const radius = Math.min(width, height) * 0.3;
      const x = width / 2 + radius * Math.cos(angle);
      const y = height / 2 + radius * Math.sin(angle);

      const graphNode: GraphNode = {
        ...node,
        x,
        y,
        vx: 0,
        vy: 0,
      };

      nodeMap.set(node.id, graphNode);
      return graphNode;
    });

    // Create edges with node references
    const graphEdges: GraphEdge[] = edges
      .filter(edge => edge.fromNodeId && edge.toNodeId)
      .map(edge => ({
        ...edge,
        source: nodeMap.get(edge.fromNodeId)!,
        target: edge.toNodeId ? nodeMap.get(edge.toNodeId) || null : null,
      }))
      .filter(edge => edge.source && edge.target); // Remove edges with missing nodes

    return { nodes: graphNodes, edges: graphEdges };
  }, [nodes, edges, width, height]);

  // Simple force-directed layout
  useEffect(() => {
    if (graphData.nodes.length === 0) return;

    const iterations = 50;
    const k = Math.sqrt((width * height) / graphData.nodes.length) * 0.5;
    const damping = 0.9;

    for (let iter = 0; iter < iterations; iter++) {
      // Calculate repulsive forces between all nodes
      for (let i = 0; i < graphData.nodes.length; i++) {
        const node1 = graphData.nodes[i];
        let fx = 0, fy = 0;

        for (let j = 0; j < graphData.nodes.length; j++) {
          if (i === j) continue;

          const node2 = graphData.nodes[j];
          const dx = node1.x - node2.x;
          const dy = node1.y - node2.y;
          const distance = Math.sqrt(dx * dx + dy * dy);

          if (distance > 0 && distance < width) {
            const force = (k * k) / distance;
            fx += (dx / distance) * force;
            fy += (dy / distance) * force;
          }
        }

        node1.vx = (node1.vx + fx) * damping;
        node1.vy = (node1.vy + fy) * damping;
      }

      // Calculate attractive forces for edges
      for (const edge of graphData.edges) {
        if (!edge.target) continue;

        const dx = edge.target.x - edge.source.x;
        const dy = edge.target.y - edge.source.y;
        const distance = Math.sqrt(dx * dx + dy * dy);

        if (distance > 0) {
          const force = (distance * distance) / k;
          const fx = (dx / distance) * force;
          const fy = (dy / distance) * force;

          edge.source.vx += fx * 0.5;
          edge.source.vy += fy * 0.5;
          edge.target.vx -= fx * 0.5;
          edge.target.vy -= fy * 0.5;
        }
      }

      // Update positions
      for (const node of graphData.nodes) {
        node.x += node.vx;
        node.y += node.vy;

        // Keep nodes within bounds
        const margin = 50;
        node.x = Math.max(margin, Math.min(width - margin, node.x));
        node.y = Math.max(margin, Math.min(height - margin, node.y));
      }
    }
  }, [graphData, width, height]);

  // Auto-center the view
  const centerView = useCallback(() => {
    if (graphData.nodes.length === 0) return;

    const minX = Math.min(...graphData.nodes.map(n => n.x));
    const maxX = Math.max(...graphData.nodes.map(n => n.x));
    const minY = Math.min(...graphData.nodes.map(n => n.y));
    const maxY = Math.max(...graphData.nodes.map(n => n.y));

    const padding = 50;
    const contentWidth = maxX - minX + padding * 2;
    const contentHeight = maxY - minY + padding * 2;

    setViewBox({
      x: minX - padding,
      y: minY - padding,
      width: contentWidth,
      height: contentHeight,
    });
  }, [graphData]);

  // Auto-center when data changes
  useEffect(() => {
    centerView();
  }, [centerView]);

  // Zoom controls
  const handleZoomIn = useCallback(() => {
    setViewBox(prev => ({
      ...prev,
      width: prev.width * 0.8,
      height: prev.height * 0.8,
    }));
  }, []);

  const handleZoomOut = useCallback(() => {
    setViewBox(prev => ({
      ...prev,
      width: prev.width * 1.2,
      height: prev.height * 1.2,
    }));
  }, []);

  const handleZoomReset = useCallback(() => {
    setViewBox({ x: 0, y: 0, width, height });
  }, [width, height]);

  // Pan controls
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button === 1 || (e.button === 0 && e.shiftKey)) {
      // Middle mouse button or shift+left for panning
      setIsPanning(true);
      setPanStart({
        x: e.clientX,
        y: e.clientY,
        viewBoxX: viewBox.x,
        viewBoxY: viewBox.y,
      });
      e.preventDefault();
    }
  }, [viewBox]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (isPanning) {
      const dx = (e.clientX - panStart.x) * (viewBox.width / width);
      const dy = (e.clientY - panStart.y) * (viewBox.height / height);

      setViewBox(prev => ({
        ...prev,
        x: panStart.viewBoxX - dx,
        y: panStart.viewBoxY - dy,
      }));
    }
  }, [isPanning, panStart, viewBox.width, viewBox.height, width, height]);

  const handleMouseUp = useCallback(() => {
    setIsPanning(false);
  }, []);

  // Node selection
  const handleNodeClick = useCallback((node: GraphNode) => {
    onNodeSelect?.(node);
  }, [onNodeSelect]);

  // Edge selection
  const handleEdgeClick = useCallback((edge: GraphEdge) => {
    onEdgeSelect?.(edge);
  }, [onEdgeSelect]);

  // Get node color based on status
  const getNodeColor = (node: GraphNode) => {
    switch (node.status) {
      case 'active': return '#4CAF50';
      case 'deprecated': return '#FF9800';
      case 'duplicate': return '#9E9E9E';
      default: return '#2196F3';
    }
  };

  // Get edge color based on confidence
  const getEdgeColor = (edge: GraphEdge) => {
    if (edge.confidence >= 0.8) return '#4CAF50';
    if (edge.confidence >= 0.6) return '#FF9800';
    return '#F44336';
  };

  if (loading) {
    return (
      <Card>
        <CardContent>
          <Typography>Loading graph...</Typography>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent>
          <Typography color="error">Error: {error}</Typography>
        </CardContent>
      </Card>
    );
  }

  return (
    <Box position="relative">
      <Card>
        <CardContent sx={{ p: 0 }}>
          <svg
            ref={svgRef}
            width={width}
            height={height}
            viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.width} ${viewBox.height}`}
            style={{
              border: '1px solid #ddd',
              cursor: isPanning ? 'grabbing' : 'grab',
              userSelect: 'none',
            }}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
          >
            {/* Define arrowhead marker */}
            <defs>
              <marker
                id="arrowhead"
                markerWidth="10"
                markerHeight="7"
                refX="9"
                refY="3.5"
                orient="auto"
              >
                <polygon
                  points="0 0, 10 3.5, 0 7"
                  fill="#666"
                />
              </marker>
            </defs>

            {/* Render edges */}
            {graphData.edges.map(edge => (
              <g key={edge.id}>
                <line
                  x1={edge.source.x}
                  y1={edge.source.y}
                  x2={edge.target ? edge.target.x : edge.source.x + 100}
                  y2={edge.target ? edge.target.y : edge.source.y}
                  stroke={getEdgeColor(edge)}
                  strokeWidth={selectedEdgeId === edge.id ? 3 : 2}
                  markerEnd={edge.target ? "url(#arrowhead)" : undefined}
                  strokeDasharray={edge.target ? undefined : "5,5"}
                  opacity={0.7}
                  style={{ cursor: 'pointer' }}
                  onClick={() => handleEdgeClick(edge)}
                />
                {/* Edge label */}
                <text
                  x={(edge.source.x + (edge.target?.x || edge.source.x + 100)) / 2}
                  y={(edge.source.y + (edge.target?.y || edge.source.y)) / 2}
                  fontSize="10"
                  fill="#666"
                  textAnchor="middle"
                  style={{ pointerEvents: 'none' }}
                >
                  {edge.action.kind}
                </text>
              </g>
            ))}

            {/* Render nodes */}
            {graphData.nodes.map(node => (
              <g key={node.id}>
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={selectedNodeId === node.id ? 25 : 20}
                  fill={getNodeColor(node)}
                  stroke={selectedNodeId === node.id ? '#333' : '#666'}
                  strokeWidth={selectedNodeId === node.id ? 3 : 2}
                  style={{ cursor: 'pointer' }}
                  onClick={() => handleNodeClick(node)}
                />
                <text
                  x={node.x}
                  y={node.y + 35}
                  fontSize="12"
                  fill="#333"
                  textAnchor="middle"
                  style={{ pointerEvents: 'none' }}
                >
                  {node.name.length > 15 ? node.name.substring(0, 15) + '...' : node.name}
                </text>
                {/* Node status indicator */}
                {node.status !== 'active' && (
                  <text
                    x={node.x + 15}
                    y={node.y - 15}
                    fontSize="10"
                    fill="#666"
                    textAnchor="middle"
                    style={{ pointerEvents: 'none' }}
                  >
                    {node.status}
                  </text>
                )}
              </g>
            ))}
          </svg>
        </CardContent>
      </Card>

      {/* Controls */}
      {showControls && (
        <Box
          sx={{
            position: 'absolute',
            top: 16,
            right: 16,
            display: 'flex',
            flexDirection: 'column',
            gap: 1,
          }}
        >
          <Tooltip title="Zoom In" arrow>
            <IconButton onClick={handleZoomIn} size="small">
              <ZoomInIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Zoom Out" arrow>
            <IconButton onClick={handleZoomOut} size="small">
              <ZoomOutIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Reset Zoom" arrow>
            <IconButton onClick={handleZoomReset} size="small">
              <CenterIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Center View" arrow>
            <IconButton onClick={centerView} size="small">
              <FullscreenIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Refresh Graph" arrow>
            <IconButton onClick={() => fetchGraph()} size="small">
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>
      )}

      {/* Graph info */}
      <Box
        sx={{
          position: 'absolute',
          bottom: 16,
          left: 16,
          bgcolor: 'rgba(255, 255, 255, 0.9)',
          p: 1,
          borderRadius: 1,
          fontSize: '12px',
        }}
      >
        <Typography variant="caption" display="block">
          Nodes: {graphData.nodes.length} | Edges: {graphData.edges.length}
        </Typography>
        <Typography variant="caption" display="block">
          Shift+Drag to pan | Click to select
        </Typography>
      </Box>
    </Box>
  );
};