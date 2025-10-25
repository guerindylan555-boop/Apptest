/**
 * Simple Detection Panel UI Component
 *
 * Simplified version without complex UI dependencies for initial deployment.
 */

import React, { useState, useCallback } from 'react';
import { useUIGraphStore } from '../../stores/uiGraphStore';

interface DetectionResult {
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

interface DetectionPanelProps {
  onDetectionComplete?: (result: DetectionResult) => void;
  onNodeSelect?: (nodeId: string) => void;
  onNewNode?: (dumpPath: string) => void;
}

export const DetectionPanelSimple: React.FC<DetectionPanelProps> = ({
  onDetectionComplete,
  onNodeSelect,
  onNewNode,
}) => {
  const [uploading, setUploading] = useState(false);
  const [currentResult, setCurrentResult] = useState<DetectionResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { detectState, submitFeedback } = useUIGraphStore();

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    if (acceptedFiles.length === 0) return;

    const file = acceptedFiles[0];
    if (!file.name.endsWith('.xml')) {
      setError('Please upload an XML file');
      return;
    }

    setUploading(true);
    setError(null);

    try {
      const result = await detectState(file);
      setCurrentResult(result);
      onDetectionComplete?.(result);

      if (result.status === 'matched' && result.selectedNodeId) {
        setTimeout(() => {
          onNodeSelect?.(result.selectedNodeId!);
        }, 1000);
      }

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Detection failed');
    } finally {
      setUploading(false);
    }
  }, [detectState, onDetectionComplete, onNodeSelect]);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (files && files.length > 0) {
      onDrop(Array.from(files));
    }
  };

  const handleFeedback = async (action: 'accept' | 'map_new' | 'merge' | 'retry') => {
    if (!currentResult) return;

    try {
      await submitFeedback(currentResult.dumpSource, action);

      if (action === 'accept' && currentResult.selectedNodeId) {
        onNodeSelect?.(currentResult.selectedNodeId);
      } else if (action === 'map_new') {
        onNewNode?.(currentResult.dumpSource);
      }

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit feedback');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'matched': return 'text-green-600';
      case 'ambiguous': return 'text-yellow-600';
      case 'unknown': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto p-6">
      <h2 className="text-2xl font-bold mb-6">State Detection</h2>

      {/* Upload Area */}
      <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center mb-6">
        <input
          type="file"
          accept=".xml"
          onChange={handleFileSelect}
          disabled={uploading}
          className="hidden"
          id="xml-upload"
        />
        <label
          htmlFor="xml-upload"
          className="cursor-pointer"
        >
          <div className="text-6xl mb-4">📁</div>
          <h3 className="text-lg font-semibold mb-2">
            {uploading ? 'Processing...' : 'Drop XML dump here or click to browse'}
          </h3>
          <p className="text-gray-600">
            Upload UIAutomator XML dumps to detect current screen state
          </p>
        </label>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
          <div className="flex">
            <div className="flex-shrink-0">
              <span className="text-red-400">❌</span>
            </div>
            <div className="ml-3">
              <p className="text-sm text-red-800">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Detection Results */}
      {currentResult && (
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-semibold">Detection Results</h3>
            <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(currentResult.status)}`}>
              {currentResult.status.toUpperCase()}
            </span>
          </div>

          <p className="text-sm text-gray-600 mb-4">
            Processed: {new Date(currentResult.timestamp).toLocaleString()}
          </p>

          {currentResult.topCandidates.length > 0 ? (
            <div className="space-y-2">
              {currentResult.topCandidates.map((candidate, index) => (
                <div
                  key={candidate.nodeId}
                  className={`flex items-center justify-between p-3 border rounded ${
                    candidate.nodeId === currentResult.selectedNodeId
                      ? 'border-green-500 bg-green-50'
                      : 'border-gray-200'
                  }`}
                >
                  <div>
                    <div className="font-mono text-sm">
                      {candidate.nodeId.substring(0, 12)}...
                    </div>
                    <div className="text-xs text-gray-500">
                      Score: {candidate.score}
                    </div>
                  </div>
                  <div>
                    {candidate.nodeId === currentResult.selectedNodeId ? (
                      <span className="text-green-600 text-sm">✓ Selected</span>
                    ) : (
                      <button
                        onClick={() => onNodeSelect?.(candidate.nodeId)}
                        className="text-blue-600 text-sm hover:text-blue-800"
                      >
                        Select
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-4">
              <p className="text-gray-600">No matching screens found. This appears to be a new state.</p>
            </div>
          )}

          {/* Action Buttons */}
          <div className="mt-6 flex flex-wrap gap-2">
            {currentResult.status === 'matched' && currentResult.selectedNodeId && (
              <button
                onClick={() => handleFeedback('accept')}
                className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700"
              >
                Accept Match
              </button>
            )}

            {currentResult.status === 'ambiguous' && (
              <>
                <button
                  onClick={() => handleFeedback('map_new')}
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                >
                  Map as New
                </button>
                <button
                  onClick={() => handleFeedback('merge')}
                  className="px-4 py-2 bg-yellow-600 text-white rounded hover:bg-yellow-700"
                >
                  Merge with Existing
                </button>
              </>
            )}

            {currentResult.status === 'unknown' && (
              <button
                onClick={() => handleFeedback('map_new')}
                className="px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-700"
              >
                Create New Node
              </button>
            )}

            <button
              onClick={() => handleFeedback('retry')}
              className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
            >
              Try Again
            </button>
          </div>
        </div>
      )}
    </div>
  );
};