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
  setAvailableSelectors: (selectors: any[]) => void;
  toggleSelectorSelection: (selectorId: string) => void;
  setNodeName: (name: string) => void;
  setNodeHints: (hints: string[]) => void;
  saveCapturedNode: () => Promise<void>;

  // Detection actions
  runDetection: (xmlDump: string) => Promise<DetectionResult | null>;
  acceptDetection: (nodeId: string) => void;
  rejectDetection: (action: 'map_new' | 'merge' | 'retry') => void;

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
          const response = await fetch('/api/ui-graph/latest');
          if (!response.ok) {
            throw new Error(`Failed to load graph: ${response.statusText}`);
          }

          const graph = await response.json();
          set({
            nodes: graph.nodes || [],
            edges: graph.edges || [],
            loading: false,
          });
        } catch (error) {
          set({
            error: error instanceof Error ? error.message : 'Unknown error',
            loading: false,
          });
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

        if (!state.nodeName || !state.selectedSelectors.length) {
          set({ error: 'Node name and at least one selector are required' });
          return;
        }

        try {
          const response = await fetch('/api/ui-graph/nodes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name: state.nodeName,
              hints: state.nodeHints,
              selectedSelectorIds: state.selectedSelectors,
              screenshot: state.screenshot,
              xmlDump: state.xmlDump,
            }),
          });

          if (!response.ok) {
            throw new Error(`Failed to save node: ${response.statusText}`);
          }

          const newNode = await response.json();
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