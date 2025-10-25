/**
 * Capture Panel Component
 *
 * UI for capturing screen nodes with name, hints, selector ranking,
 * and artifact upload progress tracking.
 */

import React, { useState, useEffect } from 'react';
import { useUIGraphStore } from '../../stores/uiGraphStore';

interface CapturePanelProps {
  onClose?: () => void;
  onCaptureComplete?: (nodeId: string) => void;
}

export const CapturePanel: React.FC<CapturePanelProps> = ({
  onClose,
  onCaptureComplete,
}) => {
  const {
    isActive,
    screenshot,
    xmlDump,
    availableSelectors,
    selectedSelectors,
    nodeName,
    nodeHints,
    loading,
    error,
    startCapture,
    cancelCapture,
    setNodeName,
    setNodeHints,
    toggleSelectorSelection,
    saveCapturedNode,
  } = useUIGraphStore();

  const [newHint, setNewHint] = useState('');

  // Start capture when component mounts
  useEffect(() => {
    if (!isActive) {
      startCapture();
    }
  }, [isActive, startCapture]);

  const handleCapture = async () => {
    if (!nodeName.trim()) {
      alert('Please enter a node name');
      return;
    }

    try {
      await saveCapturedNode();
      onCaptureComplete?.(nodeName);
      onClose?.();
    } catch (error) {
      console.error('Capture failed:', error);
    }
  };

  const handleAddHint = () => {
    if (newHint.trim() && nodeHints.length < 5) {
      setNodeHints([...nodeHints, newHint.trim()]);
      setNewHint('');
    }
  };

  const handleRemoveHint = (index: number) => {
    setNodeHints(nodeHints.filter((_, i) => i !== index));
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleAddHint();
    }
  };

  const getConfidenceColor = (confidence: number): string => {
    if (confidence >= 0.8) return 'text-green-600';
    if (confidence >= 0.6) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getConfidenceLabel = (confidence: number): string => {
    if (confidence >= 0.8) return 'High';
    if (confidence >= 0.6) return 'Medium';
    return 'Low';
  };

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
          <div className="flex items-center space-x-3">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
            <span className="text-lg font-medium">Capturing screen...</span>
          </div>
          <p className="text-gray-600 mt-2">Please wait while we analyze the current screen.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex justify-between items-start mb-6">
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Capture Screen Node</h2>
            <p className="text-gray-600 mt-1">Capture the current screen and add it to the UI graph</p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Error Display */}
        {error && (
          <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <p className="text-sm text-red-800">{error}</p>
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Column: Node Details */}
          <div className="space-y-6">
            {/* Node Name */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Node Name *
              </label>
              <input
                type="text"
                value={nodeName}
                onChange={(e) => setNodeName(e.target.value)}
                placeholder="e.g., Login/Enter Phone"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                maxLength={80}
              />
              <p className="text-xs text-gray-500 mt-1">
                3-80 characters. Descriptive name for this screen.
              </p>
            </div>

            {/* Hints */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Hints (Optional)
              </label>
              <div className="flex space-x-2 mb-2">
                <input
                  type="text"
                  value={newHint}
                  onChange={(e) => setNewHint(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="Add a hint about this screen..."
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  disabled={nodeHints.length >= 5}
                />
                <button
                  onClick={handleAddHint}
                  disabled={!newHint.trim() || nodeHints.length >= 5}
                  className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
                >
                  Add
                </button>
              </div>
              <div className="flex flex-wrap gap-2">
                {nodeHints.map((hint, index) => (
                  <span
                    key={index}
                    className="inline-flex items-center px-3 py-1 rounded-full text-sm bg-gray-100 text-gray-800"
                  >
                    {hint}
                    <button
                      onClick={() => handleRemoveHint(index)}
                      className="ml-2 text-gray-500 hover:text-gray-700"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </span>
                ))}
              </div>
              <p className="text-xs text-gray-500 mt-1">
                Up to 5 hints to help LLMs understand this screen.
              </p>
            </div>

            {/* Screenshot Preview */}
            {screenshot && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Screenshot Preview
                </label>
                <div className="border border-gray-200 rounded-lg overflow-hidden">
                  <img
                    src={screenshot}
                    alt="Screen capture"
                    className="w-full h-auto"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Right Column: Selectors */}
          <div className="space-y-6">
            <div>
              <div className="flex justify-between items-center mb-2">
                <label className="block text-sm font-medium text-gray-700">
                  Detected Selectors
                </label>
                <span className="text-xs text-gray-500">
                  {availableSelectors.length} found, {selectedSelectors.length} selected
                </span>
              </div>

              <div className="border border-gray-200 rounded-lg max-h-96 overflow-y-auto">
                {availableSelectors.length === 0 ? (
                  <div className="p-4 text-center text-gray-500">
                    No interactive elements detected on this screen
                  </div>
                ) : (
                  <div className="divide-y divide-gray-200">
                    {availableSelectors.map((selector) => {
                      const isSelected = selectedSelectors.includes(selector.id);
                      return (
                        <div
                          key={selector.id}
                          className={`p-3 hover:bg-gray-50 cursor-pointer transition-colors ${
                            isSelected ? 'bg-blue-50 border-l-4 border-blue-500' : ''
                          }`}
                          onClick={() => toggleSelectorSelection(selector.id)}
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex-1">
                              <div className="flex items-center space-x-2">
                                <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                                  selector.type === 'resource-id' ? 'bg-green-100 text-green-800' :
                                  selector.type === 'text' ? 'bg-blue-100 text-blue-800' :
                                  selector.type === 'content-desc' ? 'bg-purple-100 text-purple-800' :
                                  'bg-gray-100 text-gray-800'
                                }`}>
                                  {selector.type}
                                </span>
                                <span className="font-mono text-sm text-gray-900">
                                  {selector.value}
                                </span>
                              </div>
                            </div>
                            <div className="flex items-center space-x-2">
                              <span className={`text-sm font-medium ${getConfidenceColor(selector.confidence)}`}>
                                {getConfidenceLabel(selector.confidence)}
                              </span>
                              <div className={`w-3 h-3 rounded-full ${
                                selector.confidence >= 0.8 ? 'bg-green-400' :
                                selector.confidence >= 0.6 ? 'bg-yellow-400' :
                                'bg-red-400'
                              }`}></div>
                            </div>
                          </div>
                          <div className="mt-1">
                            <div className="w-full bg-gray-200 rounded-full h-1.5">
                              <div
                                className={`h-1.5 rounded-full ${
                                  selector.confidence >= 0.8 ? 'bg-green-500' :
                                  selector.confidence >= 0.6 ? 'bg-yellow-500' :
                                  'bg-red-500'
                                }`}
                                style={{ width: `${selector.confidence * 100}%` }}
                              ></div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <p className="text-xs text-gray-500 mt-2">
                Select the most reliable selectors. Resource IDs are preferred over text.
              </p>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex justify-between items-center mt-6 pt-6 border-t border-gray-200">
          <button
            onClick={cancelCapture}
            className="px-4 py-2 text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
          >
            Cancel
          </button>

          <div className="flex space-x-3">
            <button
              onClick={handleCapture}
              disabled={!nodeName.trim() || loading}
              className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? 'Capturing...' : 'Capture Node'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CapturePanel;