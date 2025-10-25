import React, { useState, useEffect } from 'react';
import { useUIGraphStore } from '../../stores/uiGraphStore';

interface DiscoveryPanelProps {
  className?: string;
}

const DiscoveryPanel: React.FC<DiscoveryPanelProps> = ({ className = '' }) => {
  const {
    // Graph state
    nodes,
    edges,
    selectedNodeId,
    loading,
    error,

    // Capture workflow state
    isActive: captureActive,
    nodeName,
    nodeHints,
    selectedSelectors,
    availableSelectors,

    // Actions
    loadGraph,
    selectNode,
    startCapture,
    cancelCapture,
    setNodeName,
    setNodeHints,
    toggleSelectorSelection,
    saveCapturedNode,
  } = useUIGraphStore();

  const [newHint, setNewHint] = useState('');

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  const handleAddHint = () => {
    if (newHint.trim()) {
      setNodeHints([...nodeHints, newHint.trim()]);
      setNewHint('');
    }
  };

  const handleRemoveHint = (index: number) => {
    setNodeHints(nodeHints.filter((_, i) => i !== index));
  };

  const selectedNode = nodes.find(node => node.id === selectedNodeId);

  if (loading && nodes.length === 0) {
    return (
      <div className={`p-6 ${className}`}>
        <div className="text-center text-gray-400">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p>Loading UI graph...</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`h-full flex flex-col ${className}`}>
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <h2 className="text-lg font-semibold text-white mb-2">UI Discovery</h2>
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">
            {nodes.length} nodes, {edges.length} edges
          </span>
          <button
            onClick={loadGraph}
            className="text-xs px-2 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="p-3 bg-red-900/50 border border-red-700 rounded m-4">
          <p className="text-red-200 text-sm">{error}</p>
        </div>
      )}

      {/* Main Content */}
      <div className="flex-1 overflow-y-auto">
        {captureActive ? (
          // Capture Workflow
          <div className="p-4 space-y-4">
            <div className="bg-blue-900/50 border border-blue-700 rounded p-3">
              <h3 className="text-white font-medium mb-2">Capture New Node</h3>
              <p className="text-blue-200 text-sm mb-4">
                Configure the node details and select UI elements to capture this screen state.
              </p>
            </div>

            {/* Node Name */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Node Name *
              </label>
              <input
                type="text"
                value={nodeName}
                onChange={(e) => setNodeName(e.target.value)}
                placeholder="e.g., Login - Enter Phone"
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            {/* Node Hints */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Hints
              </label>
              <div className="space-y-2">
                {nodeHints.map((hint, index) => (
                  <div key={index} className="flex items-center gap-2">
                    <span className="flex-1 text-sm text-gray-300 bg-gray-800 px-2 py-1 rounded">
                      {hint}
                    </span>
                    <button
                      onClick={() => handleRemoveHint(index)}
                      className="text-red-400 hover:text-red-300 text-sm"
                    >
                      Remove
                    </button>
                  </div>
                ))}
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={newHint}
                    onChange={(e) => setNewHint(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleAddHint()}
                    placeholder="Add a hint..."
                    className="flex-1 px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <button
                    onClick={handleAddHint}
                    disabled={!newHint.trim()}
                    className="px-3 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Add
                  </button>
                </div>
              </div>
            </div>

            {/* Available Selectors */}
            {availableSelectors.length > 0 && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Select UI Elements *
                </label>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {availableSelectors.map((selector) => (
                    <div key={selector.id} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        id={selector.id}
                        checked={selectedSelectors.includes(selector.id)}
                        onChange={() => toggleSelectorSelection(selector.id)}
                        className="rounded border-gray-600 bg-gray-800 text-blue-600 focus:ring-blue-500 focus:ring-2"
                      />
                      <label htmlFor={selector.id} className="flex-1 text-sm">
                        <div className="text-white">{selector.value}</div>
                        <div className="text-gray-400 text-xs">
                          {selector.type} • {Math.round(selector.confidence * 100)}% confidence
                        </div>
                      </label>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="flex gap-2 pt-4 border-t border-gray-700">
              <button
                onClick={saveCapturedNode}
                disabled={!nodeName.trim() || selectedSelectors.length === 0}
                className="flex-1 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Save Node
              </button>
              <button
                onClick={cancelCapture}
                className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          // Node List
          <div className="p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-white font-medium">Captured Nodes</h3>
              <button
                onClick={startCapture}
                className="px-3 py-1 bg-blue-600 text-white text-sm rounded hover:bg-blue-700"
              >
                + Capture New
              </button>
            </div>

            {nodes.length === 0 ? (
              <div className="text-center py-8">
                <div className="text-gray-400 mb-4">
                  <div className="text-4xl mb-2">📱</div>
                  <p>No nodes captured yet</p>
                  <p className="text-sm mt-2">Start by capturing a screen state</p>
                </div>
                <button
                  onClick={startCapture}
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                >
                  Capture First Node
                </button>
              </div>
            ) : (
              <div className="space-y-2">
                {nodes.map((node) => (
                  <div
                    key={node.id}
                    onClick={() => selectNode(node.id)}
                    className={`p-3 rounded cursor-pointer transition-colors ${
                      selectedNodeId === node.id
                        ? 'bg-blue-900/50 border border-blue-600'
                        : 'bg-gray-800 border border-gray-700 hover:bg-gray-700'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <h4 className="text-white font-medium">{node.name}</h4>
                        <p className="text-gray-400 text-sm mt-1">
                          {node.selectors.length} selectors • {node.outgoingEdgeIds.length} outgoing edges
                        </p>
                        {node.hints.length > 0 && (
                          <div className="mt-2">
                            {node.hints.slice(0, 2).map((hint, index) => (
                              <span key={index} className="inline-block bg-gray-700 text-gray-300 text-xs px-2 py-1 rounded mr-1 mb-1">
                                {hint}
                              </span>
                            ))}
                            {node.hints.length > 2 && (
                              <span className="text-gray-500 text-xs">+{node.hints.length - 2} more</span>
                            )}
                          </div>
                        )}
                      </div>
                      <div className={`w-2 h-2 rounded-full mt-1 ${
                        node.status === 'active' ? 'bg-green-500' :
                        node.status === 'deprecated' ? 'bg-yellow-500' : 'bg-gray-500'
                      }`} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Selected Node Details */}
      {selectedNode && !captureActive && (
        <div className="border-t border-gray-700 p-4">
          <h3 className="text-white font-medium mb-3">Node Details</h3>
          <div className="space-y-2 text-sm">
            <div>
              <span className="text-gray-400">Activity:</span>
              <span className="text-white ml-2">{selectedNode.signature.activity}</span>
            </div>
            <div>
              <span className="text-gray-400">Signature:</span>
              <span className="text-white ml-2 font-mono text-xs">{selectedNode.signature.hash}</span>
            </div>
            <div>
              <span className="text-gray-400">Captured:</span>
              <span className="text-white ml-2">
                {new Date(selectedNode.metadata.captureTimestamp).toLocaleString()}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DiscoveryPanel;