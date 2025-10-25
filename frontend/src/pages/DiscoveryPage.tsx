/**
 * Discovery Page Component
 *
 * Lists nodes, triggers captures, and visualizes outgoing edges.
 * Integrates with UI graph functionality and emulator state.
 */

import React, { useState, useEffect } from 'react';
import { useUIGraphStore } from '../stores/uiGraphStore';
import CapturePanel from '../components/discovery/CapturePanel';

interface NodeAction {
  nodeId: string;
  kind: 'tap' | 'type' | 'wait' | 'back' | 'intent';
  selectorId?: string;
  text?: string;
  notes?: string;
}

const DiscoveryPage: React.FC = () => {
  const {
    nodes,
    edges,
    selectedNodeId,
    selectedEdgeId,
    loading,
    error,
    loadGraph,
    selectNode,
    selectEdge,
    getNodeById,
    getOutgoingEdges,
    getIncomingEdges,
    createOptimisticEdge,
    clearError,
  } = useUIGraphStore();

  const [showCapturePanel, setShowCapturePanel] = useState(false);
  const [showActionDialog, setShowActionDialog] = useState(false);
  const [selectedActionNode, setSelectedActionNode] = useState<string>('');
  const [newAction, setNewAction] = useState<NodeAction>({
    nodeId: '',
    kind: 'tap',
  });

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  const selectedNode = selectedNodeId ? getNodeById(selectedNodeId) : undefined;
  const outgoingEdges = selectedNodeId ? getOutgoingEdges(selectedNodeId) : [];
  const incomingEdges = selectedNodeId ? getIncomingEdges(selectedNodeId) : [];

  const handleAddAction = (nodeId: string) => {
    setSelectedActionNode(nodeId);
    setNewAction({ nodeId, kind: 'tap' });
    setShowActionDialog(true);
  };

  const handleCreateAction = async () => {
    if (!selectedActionNode) return;

    try {
      await createOptimisticEdge(selectedActionNode, {
        kind: newAction.kind,
        selectorId: newAction.selectorId,
        text: newAction.text,
      }, newAction.notes);

      setShowActionDialog(false);
      setSelectedActionNode('');
      setNewAction({ nodeId: '', kind: 'tap' });
    } catch (error) {
      console.error('Failed to create action:', error);
    }
  };

  const handleCaptureComplete = (nodeId: string) => {
    console.log('Node captured:', nodeId);
    loadGraph(); // Refresh graph to show new node
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-green-100 text-green-800';
      case 'deprecated': return 'bg-yellow-100 text-yellow-800';
      case 'duplicate': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getActionIcon = (kind: string) => {
    switch (kind) {
      case 'tap': return '👆';
      case 'type': return '⌨️';
      case 'wait': return '⏱️';
      case 'back': return '⬅️';
      case 'intent': return '🚀';
      default: return '❓';
    }
  };

  if (loading && nodes.length === 0) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading UI graph...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">UI Discovery</h1>
              <p className="text-gray-600 mt-1">Capture and map MaynDrive screens</p>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-sm text-gray-500">
                <span className="font-medium">{nodes.length}</span> nodes •
                <span className="font-medium">{edges.length}</span> edges
              </div>
              <button
                onClick={() => setShowCapturePanel(true)}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors flex items-center space-x-2"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
                <span>Capture Screen</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-4">
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3 flex-1">
                <p className="text-sm text-red-800">{error}</p>
                <button
                  onClick={clearError}
                  className="text-sm text-red-600 underline mt-1"
                >
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {nodes.length === 0 ? (
          // Empty State
          <div className="text-center py-12">
            <div className="text-6xl mb-4">🗺️</div>
            <h2 className="text-2xl font-bold text-gray-900 mb-2">No screens captured yet</h2>
            <p className="text-gray-600 mb-6 max-w-md mx-auto">
              Start building your UI graph by capturing screens from the MaynDrive app.
              Each captured screen becomes a node that you can connect with actions.
            </p>
            <button
              onClick={() => setShowCapturePanel(true)}
              className="px-6 py-3 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
            >
              Capture First Screen
            </button>
          </div>
        ) : (
          // Node Grid
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {nodes.map((node) => (
              <div
                key={node.id}
                className={`bg-white rounded-lg shadow-sm border-2 transition-all cursor-pointer hover:shadow-md ${
                  selectedNodeId === node.id
                    ? 'border-blue-500 shadow-md'
                    : 'border-gray-200'
                }`}
                onClick={() => selectNode(node.id)}
              >
                <div className="p-6">
                  {/* Node Header */}
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-gray-900 mb-1">
                        {node.name}
                      </h3>
                      <div className="flex items-center space-x-2">
                        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(node.status)}`}>
                          {node.status}
                        </span>
                        <span className="text-xs text-gray-500">
                          {node.selectors.length} selectors
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Node Metadata */}
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-500">Activity:</span>
                      <span className="text-gray-900 font-mono text-xs">
                        {node.signature.activity.split('.').pop()}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500">Signature:</span>
                      <span className="text-gray-900 font-mono text-xs">
                        {node.signature.hash.substring(0, 8)}...
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500">Edges:</span>
                      <span className="text-gray-900">
                        {node.outgoingEdgeIds.length} out, {node.incomingEdgeIds.length} in
                      </span>
                    </div>
                  </div>

                  {/* Hints */}
                  {node.hints.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-gray-100">
                      <div className="flex flex-wrap gap-1">
                        {node.hints.slice(0, 3).map((hint, index) => (
                          <span
                            key={index}
                            className="inline-block bg-gray-100 text-gray-700 text-xs px-2 py-1 rounded"
                          >
                            {hint}
                          </span>
                        ))}
                        {node.hints.length > 3 && (
                          <span className="text-xs text-gray-500">
                            +{node.hints.length - 3} more
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="mt-4 pt-3 border-t border-gray-100 flex justify-between items-center">
                    <div className="flex space-x-2">
                      {outgoingEdges.slice(0, 3).map((edge) => (
                        <div
                          key={edge.id}
                          className="flex items-center space-x-1 text-xs bg-blue-50 text-blue-700 px-2 py-1 rounded"
                          title={edge.notes}
                        >
                          <span>{getActionIcon(edge.action.kind)}</span>
                          <span>{edge.action.kind}</span>
                        </div>
                      ))}
                      {outgoingEdges.length > 3 && (
                        <span className="text-xs text-gray-500">
                          +{outgoingEdges.length - 3} more
                        </span>
                      )}
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleAddAction(node.id);
                      }}
                      className="text-sm text-blue-600 hover:text-blue-800 font-medium"
                    >
                      + Add Action
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Selected Node Details Sidebar */}
      {selectedNode && (
        <div className="fixed right-0 top-0 h-full w-80 bg-white shadow-lg border-l border-gray-200 overflow-y-auto z-40">
          <div className="p-6">
            <div className="flex justify-between items-start mb-6">
              <div>
                <h2 className="text-xl font-bold text-gray-900">{selectedNode.name}</h2>
                <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(selectedNode.status)}`}>
                  {selectedNode.status}
                </span>
              </div>
              <button
                onClick={() => selectNode(undefined)}
                className="text-gray-400 hover:text-gray-600"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="space-y-6">
              {/* Basic Info */}
              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-3">Basic Information</h3>
                <dl className="space-y-2">
                  <div>
                    <dt className="text-xs text-gray-500">Activity</dt>
                    <dd className="text-sm font-mono text-gray-900">{selectedNode.signature.activity}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-gray-500">Signature Hash</dt>
                    <dd className="text-sm font-mono text-gray-900">{selectedNode.signature.hash}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-gray-500">Captured</dt>
                    <dd className="text-sm text-gray-900">
                      {new Date(selectedNode.metadata.captureTimestamp).toLocaleString()}
                    </dd>
                  </div>
                </dl>
              </div>

              {/* Selectors */}
              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-3">
                  Selectors ({selectedNode.selectors.length})
                </h3>
                <div className="space-y-2">
                  {selectedNode.selectors.map((selector) => (
                    <div key={selector.id} className="text-sm p-2 bg-gray-50 rounded">
                      <div className="flex justify-between items-center">
                        <span className="font-mono text-gray-900">{selector.value}</span>
                        <div className="flex items-center space-x-2">
                          <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                            selector.type === 'resource-id' ? 'bg-green-100 text-green-800' :
                            selector.type === 'text' ? 'bg-blue-100 text-blue-800' :
                            'bg-gray-100 text-gray-800'
                          }`}>
                            {selector.type}
                          </span>
                          <span className="text-xs text-gray-500">
                            {Math.round(selector.confidence * 100)}%
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Actions */}
              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-3">
                  Actions ({outgoingEdges.length})
                </h3>
                {outgoingEdges.length === 0 ? (
                  <p className="text-sm text-gray-500">No outgoing actions yet</p>
                ) : (
                  <div className="space-y-2">
                    {outgoingEdges.map((edge) => (
                      <div
                        key={edge.id}
                        className={`text-sm p-2 rounded cursor-pointer border ${
                          selectedEdgeId === edge.id
                            ? 'bg-blue-50 border-blue-200'
                            : 'bg-gray-50 border-gray-200 hover:bg-gray-100'
                        }`}
                        onClick={() => selectEdge(edge.id)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <span>{getActionIcon(edge.action.kind)}</span>
                            <span className="font-medium">{edge.action.kind}</span>
                            {edge.action.text && (
                              <span className="text-gray-600">"{edge.action.text}"</span>
                            )}
                          </div>
                          <span className="text-xs text-gray-500">
                            {Math.round(edge.confidence * 100)}%
                          </span>
                        </div>
                        {edge.notes && (
                          <p className="text-xs text-gray-500 mt-1">{edge.notes}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Capture Panel Modal */}
      {showCapturePanel && (
        <CapturePanel
          onClose={() => setShowCapturePanel(false)}
          onCaptureComplete={handleCaptureComplete}
        />
      )}

      {/* Add Action Dialog */}
      {showActionDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Add Action</h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Action Type</label>
                <select
                  value={newAction.kind}
                  onChange={(e) => setNewAction({ ...newAction, kind: e.target.value as any })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="tap">Tap</option>
                  <option value="type">Type Text</option>
                  <option value="wait">Wait</option>
                  <option value="back">Back</option>
                  <option value="intent">Intent</option>
                </select>
              </div>

              {newAction.kind === 'type' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Text</label>
                  <input
                    type="text"
                    value={newAction.text || ''}
                    onChange={(e) => setNewAction({ ...newAction, text: e.target.value })}
                    placeholder="Text to type"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Notes (Optional)</label>
                <textarea
                  value={newAction.notes || ''}
                  onChange={(e) => setNewAction({ ...newAction, notes: e.target.value })}
                  placeholder="Describe this action..."
                  rows={3}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>

            <div className="flex justify-end space-x-3 mt-6">
              <button
                onClick={() => setShowActionDialog(false)}
                className="px-4 py-2 text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateAction}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
              >
                Add Action
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DiscoveryPage;