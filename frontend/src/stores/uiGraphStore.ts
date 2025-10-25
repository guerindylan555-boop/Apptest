/**
 * UI Graph Store - Frontend Zustand Store
 *
 * Manages UI graph state for the React frontend including:
 * - Screen nodes and actions
 * - Capture workflow state
 * - Graph visualization data
 * - Integration with backend API
 */

import { create } from 'zustand';
import { devtools } from 'zustand/middleware';

// Helper function to extract selectors from XML dump
function extractSelectorsFromXML(xmlContent: string) {
  const selectors = [];
  try {
    // Parse XML nodes
    const nodeRegex = /<node[^>]*>/g;
    const nodes = xmlContent.match(nodeRegex) || [];

    nodes.forEach((nodeString, index) => {
      const resourceIdMatch = nodeString.match(/resource-id=['"]([^'"]+)['"]/);
      const textMatch = nodeString.match(/text=['"]([^'"]*)['"]/);
      const contentDescMatch = nodeString.match(/content-desc=['"]([^'"]*)['"]/);
      const clickableMatch = nodeString.match(/clickable=['"](true|false)['"]/);
      const boundsMatch = nodeString.match(/bounds=['"]\[(\d+),(\d+)\]\[(\d+),(\d+)\]['"]/);

      const isClickable = clickableMatch?.[1] === 'true';
      const hasText = textMatch?.[1] && textMatch[1].length > 0;
      const hasResourceId = resourceIdMatch?.[1] && resourceIdMatch[1].trim().length > 0;
      const hasContentDesc = contentDescMatch?.[1] && contentDescMatch[1].trim().length > 0;

      // Only create selectors for interactive elements
      if (isClickable && (hasText || hasResourceId || hasContentDesc)) {
        const selectorId = `selector_${index}`;
        const confidence = calculateSelectorConfidence({
          hasText: !!hasText,
          hasResourceId: !!hasResourceId,
          hasContentDesc: !!hasContentDesc,
          isClickable,
          hasBounds: !!boundsMatch,
        });

        if (confidence >= 0.3) { // Filter very low-confidence selectors
          // Add resource-id selector if available
          if (hasResourceId) {
            selectors.push({
              id: `${selectorId}_resource_id`,
              type: 'resource-id',
              value: resourceIdMatch![1],
              confidence: confidence * 1.2, // Boost resource-id confidence
            });
          }

          // Add text selector if available
          if (hasText) {
            selectors.push({
              id: `${selectorId}_text`,
              type: 'text',
              value: textMatch![1],
              confidence: confidence * 0.8, // Text selectors are slightly less reliable
            });
          }

          // Add content-desc selector if available
          if (hasContentDesc) {
            selectors.push({
              id: `${selectorId}_content_desc`,
              type: 'content-desc',
              value: contentDescMatch![1],
              confidence: confidence * 0.9, // Content-desc is fairly reliable
            });
          }

          // Add coordinate fallback if bounds available
          if (boundsMatch) {
            const [x1, y1, x2, y2] = boundsMatch.slice(1).map(Number);
            const centerX = Math.floor((x1 + x2) / 2);
            const centerY = Math.floor((y1 + y2) / 2);

            selectors.push({
              id: `${selectorId}_coords`,
              type: 'coords',
              value: `${centerX},${centerY}`,
              confidence: confidence * 0.4, // Coordinate selectors are least reliable
            });
          }
        }
      }
    });

    return selectors;
  } catch (error) {
    console.error('Failed to extract selectors from XML:', error);
    return [];
  }
}

// Helper function to calculate selector confidence
function calculateSelectorConfidence(traits: {
  hasText: boolean;
  hasResourceId: boolean;
  hasContentDesc: boolean;
  isClickable: boolean;
  hasBounds: boolean;
}): number {
  let confidence = 0.0;

  // Base confidence for clickable elements
  if (traits.isClickable) confidence += 0.3;

  // Boosts for reliable attributes
  if (traits.hasResourceId) confidence += 0.5;
  if (traits.hasText) confidence += 0.3;
  if (traits.hasContentDesc) confidence += 0.2;
  if (traits.hasBounds) confidence += 0.1;

  // Cap at 1.0
  return Math.min(confidence, 1.0);
}

// Types (shared with backend)
export interface ScreenNode {
  id: string;
  name: string;
  signature: {
    activity: string;
    resourceIds: string[];
    requiredTexts: string[];
    layoutFingerprint: string;
    hash: string;
    version: number;
  };
  selectors: Array<{
    id: string;
    type: 'resource-id' | 'content-desc' | 'text' | 'accessibility' | 'xpath' | 'coords';
    value: string;
    confidence: number;
    lastValidatedAt: string;
  }>;
  hints: string[];
  samples: {
    screenshotPath: string;
    xmlPath: string;
    metadataPath?: string;
    checksum: string;
  };
  metadata: {
    activity?: string;
    class?: string;
    package?: string;
    emulatorBuild?: string;
    captureTimestamp: string;
    operatorId: string;
  };
  outgoingEdgeIds: string[];
  incomingEdgeIds: string[];
  status: 'active' | 'deprecated' | 'duplicate';
}

export interface SelectorCandidate {
  id: string;
  type: 'resource-id' | 'content-desc' | 'text' | 'accessibility' | 'xpath' | 'coords';
  value: string;
  confidence: number;
}

export interface ActionEdge {
  id: string;
  fromNodeId: string;
  toNodeId: string | null;
  action: {
    kind: 'tap' | 'type' | 'wait' | 'back' | 'intent';
    selectorId?: string;
    text?: string;
    keycode?: number;
    delayMs?: number;
  };
  guard: {
    mustMatchSignatureHash?: string;
    requiredTexts?: string[];
  };
  notes: string;
  createdAt: string;
  createdBy: string;
  confidence: number;
}

export interface CaptureWorkflowState {
  isActive: boolean;
  currentNode?: ScreenNode;
  screenshot?: string; // Base64 encoded
  xmlDump?: string;
  availableSelectors: Array<{
    id: string;
    type: string;
    value: string;
    confidence: number;
  }>;
  selectedSelectors: string[];
  nodeName: string;
  nodeHints: string[];
  selectors: SelectorCandidate[];
}

export interface UIGraphState {
  nodes: ScreenNode[];
  edges: ActionEdge[];
  selectedNodeId?: string;
  selectedEdgeId?: string;
  loading: boolean;
  error?: string;
}

export interface DetectionResult {
  timestamp: string;
  dumpSource: string;
  topCandidates: Array<{
    nodeId: string;
    score: number;
  }>;
  selectedNodeId?: string;
  status: 'matched' | 'ambiguous' | 'unknown';
  operatorAction?: 'accept' | 'map_new' | 'merge' | 'retry';
}

// Store interface
interface UIGraphStore extends UIGraphState, CaptureWorkflowState {
  // Actions
  loadGraph: () => Promise<void>;
  selectNode: (nodeId: string | undefined) => void;
  selectEdge: (edgeId: string | undefined) => void;
  addNode: (node: ScreenNode) => void;
  addEdge: (edge: ActionEdge) => void;
  updateNode: (nodeId: string, updates: Partial<ScreenNode>) => void;
  updateEdge: (edgeId: string, updates: Partial<ActionEdge>) => void;
  deleteNode: (nodeId: string) => void;
  deleteEdge: (edgeId: string) => void;
  clearError: () => void;

  // Capture workflow actions
  startCapture: () => void;
  cancelCapture: () => void;
  setCaptureScreenshot: (screenshot: string) => void;
  setCaptureXmlDump: (xml: string) => void;
  setAvailableSelectors: (selectors: SelectorCandidate[]) => void;
  toggleSelectorSelection: (selectorId: string) => void;
  setNodeName: (name: string) => void;
  setNodeHints: (hints: string[]) => void;
  saveCapturedNode: () => Promise<void>;

  // Detection actions
  runDetection: (xmlDump: string) => Promise<DetectionResult | null>;
  acceptDetection: (nodeId: string) => void;
  rejectDetection: (action: 'map_new' | 'merge' | 'retry') => void;

  // Optimistic edge creation
  createOptimisticEdge: (fromNodeId: string, action: any, notes?: string) => Promise<ActionEdge | null>;

  // Computed getters
  getNodeById: (nodeId: string) => ScreenNode | undefined;
  getEdgeById: (edgeId: string) => ActionEdge | undefined;
  getEdgesForNode: (nodeId: string) => ActionEdge[];
  getIncomingEdges: (nodeId: string) => ActionEdge[];
  getOutgoingEdges: (nodeId: string) => ActionEdge[];
}

// Create the store
export const useUIGraphStore = create<UIGraphStore>()(
  devtools(
    (set, get) => ({
      // Initial state
      nodes: [],
      edges: [],
      selectedNodeId: undefined,
      selectedEdgeId: undefined,
      loading: false,
      error: undefined,

      // Capture workflow initial state
      isActive: false,
      currentNode: undefined,
      screenshot: undefined,
      xmlDump: undefined,
      availableSelectors: [],
      selectedSelectors: [],
      nodeName: '',
      nodeHints: [],

      // Basic actions
      loadGraph: async () => {
        set({ loading: true, error: undefined });
        try {
          const response = await fetch('/api/ui-graph');
          if (!response.ok) {
            throw new Error(`Failed to load graph: ${response.statusText}`);
          }

          const result = await response.json();
          if (!result.success) {
            throw new Error(result.error || 'Failed to load graph');
          }

          set({
            nodes: result.data.nodes || [],
            edges: result.data.edges || [],
            loading: false,
          });
        } catch (error) {
          set({
            error: error instanceof Error ? error.message : 'Unknown error',
            loading: false,
          });
        }
      },

      loadNode: async (nodeId: string) => {
        set({ loading: true, error: undefined });
        try {
          const response = await fetch(`/api/ui-graph/nodes/${nodeId}`);
          if (!response.ok) {
            throw new Error(`Failed to load node: ${response.statusText}`);
          }

          const result = await response.json();
          if (!result.success) {
            throw new Error(result.error || 'Failed to load node');
          }

          const node = result.data;
          set((state) => ({
            nodes: state.nodes.some(n => n.id === node.id)
              ? state.nodes.map(n => n.id === node.id ? node : n)
              : [...state.nodes, node],
            loading: false,
          }));

          return node;
        } catch (error) {
          set({
            error: error instanceof Error ? error.message : 'Unknown error',
            loading: false,
          });
          return null;
        }
      },

      captureSignature: async (screenshot: string, xmlDump: string) => {
        set({ loading: true, error: undefined });
        try {
          // Extract selectors from XML dump (client-side extraction)
          const selectors = extractSelectorsFromXML(xmlDump);

          set({
            screenshot,
            xmlDump,
            availableSelectors: selectors,
            loading: false,
          });

          return selectors;
        } catch (error) {
          set({
            error: error instanceof Error ? error.message : 'Failed to capture signature',
            loading: false,
          });
          return [];
        }
      },

      createOptimisticEdge: async (fromNodeId: string, action: any, notes?: string) => {
        set({ loading: true, error: undefined });
        try {
          // Create optimistic edge locally first
          const tempEdge: ActionEdge = {
            id: `temp-${Date.now()}`,
            fromNodeId,
            toNodeId: null, // Will be determined after action execution
            action,
            guard: {},
            notes: notes || '',
            createdAt: new Date().toISOString(),
            createdBy: 'current-operator',
            confidence: 0.8, // Initial optimistic confidence
          };

          // Add to local state immediately (optimistic update)
          set((state) => ({
            edges: [...state.edges, tempEdge],
          }));

          // Send to backend
          const response = await fetch(`/api/ui-graph/nodes/${fromNodeId}/actions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              action,
              notes,
            }),
          });

          if (!response.ok) {
            throw new Error(`Failed to create edge: ${response.statusText}`);
          }

          const result = await response.json();
          if (!result.success) {
            throw new Error(result.error || 'Failed to create edge');
          }

          // Replace optimistic edge with real one
          set((state) => ({
            edges: state.edges.map(edge =>
              edge.id === tempEdge.id ? result.data : edge
            ),
            loading: false,
          }));

          return result.data;
        } catch (error) {
          // Remove optimistic edge on error
          set((state) => ({
            edges: state.edges.filter(edge => !edge.id.startsWith('temp-')),
            error: error instanceof Error ? error.message : 'Failed to create edge',
            loading: false,
          }));
          return null;
        }
      },

      selectNode: (nodeId) => set({ selectedNodeId: nodeId, selectedEdgeId: undefined }),

      selectEdge: (edgeId) => set({ selectedEdgeId: edgeId, selectedNodeId: undefined }),

      addNode: (node) => set((state) => ({
        nodes: [...state.nodes, node],
      })),

      addEdge: (edge) => set((state) => ({
        edges: [...state.edges, edge],
      })),

      updateNode: (nodeId, updates) => set((state) => ({
        nodes: state.nodes.map(node =>
          node.id === nodeId ? { ...node, ...updates } : node
        ),
      })),

      updateEdge: (edgeId, updates) => set((state) => ({
        edges: state.edges.map(edge =>
          edge.id === edgeId ? { ...edge, ...updates } : edge
        ),
      })),

      deleteNode: (nodeId) => set((state) => ({
        nodes: state.nodes.filter(node => node.id !== nodeId),
        edges: state.edges.filter(edge =>
          edge.fromNodeId !== nodeId && edge.toNodeId !== nodeId
        ),
        selectedNodeId: state.selectedNodeId === nodeId ? undefined : state.selectedNodeId,
      })),

      deleteEdge: (edgeId) => set((state) => ({
        edges: state.edges.filter(edge => edge.id !== edgeId),
        selectedEdgeId: state.selectedEdgeId === edgeId ? undefined : state.selectedEdgeId,
      })),

      clearError: () => set({ error: undefined }),

      // Capture workflow actions
      startCapture: () => set({
        isActive: true,
        selectedSelectors: [],
        nodeName: '',
        nodeHints: [],
        currentNode: undefined,
        screenshot: undefined,
        xmlDump: undefined,
        availableSelectors: [],
      }),

      cancelCapture: () => set({
        isActive: false,
      }),

      setCaptureScreenshot: (screenshot) => set({
        screenshot,
      }),

      setCaptureXmlDump: (xmlDump) => set({
        xmlDump,
      }),

      setAvailableSelectors: (selectors) => set({
        availableSelectors: selectors,
      }),

      toggleSelectorSelection: (selectorId) => {
        const state = get();
        const selected = state.selectedSelectors;
        const isSelected = selected.includes(selectorId);

        set({
          selectedSelectors: isSelected
            ? selected.filter(id => id !== selectorId)
            : [...selected, selectorId],
        });
      },

      setNodeName: (name) => set({
        nodeName: name,
      }),

      setNodeHints: (hints) => set({
        nodeHints: hints,
      }),

      saveCapturedNode: async () => {
        const state = get();

        if (!state.nodeName) {
          set({ error: 'Node name is required' });
          return;
        }

        try {
          const response = await fetch('/api/ui-graph/nodes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name: state.nodeName,
              hints: state.nodeHints,
              metadata: {
                // Additional metadata can be added here
              },
            }),
          });

          if (!response.ok) {
            throw new Error(`Failed to save node: ${response.statusText}`);
          }

          const result = await response.json();
          if (!result.success) {
            throw new Error(result.error || 'Failed to save node');
          }

          const newNode = result.data;
          get().addNode(newNode);

          // Reset capture workflow
          set({ isActive: false });
        } catch (error) {
          set({
            error: error instanceof Error ? error.message : 'Failed to save node',
          });
        }
      },

      // Detection actions
      runDetection: async (xmlDump) => {
        try {
          const response = await fetch('/api/state-detection', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ xmlDump }),
          });

          if (!response.ok) {
            throw new Error(`Detection failed: ${response.statusText}`);
          }

          return await response.json();
        } catch (error) {
          set({
            error: error instanceof Error ? error.message : 'Detection failed',
          });
          return null;
        }
      },

      acceptDetection: (nodeId) => {
        get().selectNode(nodeId);
      },

      rejectDetection: (action) => {
        // Handle different rejection actions
        switch (action) {
          case 'map_new':
            get().startCapture();
            break;
          case 'merge':
            // TODO: Implement merge logic
            break;
          case 'retry':
            // TODO: Implement retry logic
            break;
        }
      },

      // Computed getters
      getNodeById: (nodeId) => get().nodes.find(node => node.id === nodeId),

      getEdgeById: (edgeId) => get().edges.find(edge => edge.id === edgeId),

      getEdgesForNode: (nodeId) => get().edges.filter(
        edge => edge.fromNodeId === nodeId || edge.toNodeId === nodeId
      ),

      getIncomingEdges: (nodeId) => get().edges.filter(edge => edge.toNodeId === nodeId),

      getOutgoingEdges: (nodeId) => get().edges.filter(edge => edge.fromNodeId === nodeId),
    }),
    {
      name: 'ui-graph-store',
    }
  )
);