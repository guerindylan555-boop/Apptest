/**
 * Detection Panel UI Component
 *
 * Allows operators to upload XML dumps, view detection scores,
 * and make decisions on ambiguous or unknown states.
 */

import React, { useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  CardActions,
  Typography,
  Button,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  LinearProgress,
} from '@mui/material';
import {
  Upload as UploadIcon,
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
  Help as HelpIcon,
  Close as CloseIcon,
  Add as AddIcon,
  MergeType as MergeIcon,
  Replay as ReplayIcon,
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { useDropzone } from 'react-dropzone';
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

const StyledDropzone = styled(Box)(({ theme }) => ({
  border: `2px dashed ${theme.palette.divider}`,
  borderRadius: theme.shape.borderRadius,
  padding: theme.spacing(4),
  textAlign: 'center',
  cursor: 'pointer',
  transition: 'all 0.2s ease-in-out',
  '&:hover': {
    borderColor: theme.palette.primary.main,
    backgroundColor: theme.palette.action.hover,
  },
  '&.active': {
    borderColor: theme.palette.primary.main,
    backgroundColor: theme.palette.action.selected,
  },
}));

const StatusChip = styled(Chip)<{ status: string }>(({ theme, status }) => ({
  fontWeight: 'bold',
  ...(status === 'matched' && {
    backgroundColor: theme.palette.success.light,
    color: theme.palette.success.contrastText,
  }),
  ...(status === 'ambiguous' && {
    backgroundColor: theme.palette.warning.light,
    color: theme.palette.warning.contrastText,
  }),
  ...(status === 'unknown' && {
    backgroundColor: theme.palette.error.light,
    color: theme.palette.error.contrastText,
  }),
}));

interface DetectionPanelProps {
  onDetectionComplete?: (result: DetectionResult) => void;
  onNodeSelect?: (nodeId: string) => void;
  onNewNode?: (dumpPath: string) => void;
}

export const DetectionPanel: React.FC<DetectionPanelProps> = ({
  onDetectionComplete,
  onNodeSelect,
  onNewNode,
}) => {
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [currentResult, setCurrentResult] = useState<DetectionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [feedbackDialog, setFeedbackDialog] = useState<{
    open: boolean;
    action: 'map_new' | 'merge' | 'retry';
  }>({ open: false, action: 'map_new' });

  const { detectState, submitFeedback } = useUIGraphStore();

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    if (acceptedFiles.length === 0) return;

    const file = acceptedFiles[0];
    if (!file.name.endsWith('.xml')) {
      setError('Please upload an XML file');
      return;
    }

    setUploading(true);
    setUploadProgress(0);
    setError(null);

    try {
      // Create form data for upload
      const formData = new FormData();
      formData.append('xml', file);

      // Simulate progress during upload
      const progressInterval = setInterval(() => {
        setUploadProgress(prev => Math.min(prev + 10, 90));
      }, 100);

      const result = await detectState(file);

      clearInterval(progressInterval);
      setUploadProgress(100);

      setCurrentResult(result);
      onDetectionComplete?.(result);

      // Auto-accept if we have a high-confidence match
      if (result.status === 'matched' && result.selectedNodeId) {
        setTimeout(() => {
          onNodeSelect?.(result.selectedNodeId!);
        }, 1000);
      }

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Detection failed');
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  }, [detectState, onDetectionComplete, onNodeSelect]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/xml': ['.xml'],
    },
    maxFiles: 1,
    disabled: uploading,
  });

  const handleFeedback = async (action: 'accept' | 'map_new' | 'merge' | 'retry') => {
    if (!currentResult) return;

    try {
      await submitFeedback(currentResult.dumpSource, action);

      if (action === 'accept' && currentResult.selectedNodeId) {
        onNodeSelect?.(currentResult.selectedNodeId);
      } else if (action === 'map_new') {
        onNewNode?.(currentResult.dumpSource);
      }

      setFeedbackDialog({ open: false, action: 'map_new' });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit feedback');
    }
  };

  const handleRetry = () => {
    setCurrentResult(null);
    setError(null);
    setUploadProgress(0);
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'success';
    if (score >= 75) return 'warning';
    if (score >= 50) return 'error';
    return 'default';
  };

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'accept': return <CheckCircleIcon />;
      case 'map_new': return <AddIcon />;
      case 'merge': return <MergeIcon />;
      case 'retry': return <ReplayIcon />;
      default: return <HelpIcon />;
    }
  };

  return (
    <Box sx={{ width: '100%', maxWidth: 800, mx: 'auto' }}>
      <Typography variant="h5" gutterBottom>
        State Detection
      </Typography>

      {/* Upload Area */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <StyledDropzone
            {...getRootProps()}
            className={isDragActive ? 'active' : ''}
          >
            <input {...getInputProps()} />
            <UploadIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              {uploading ? 'Processing...' : 'Drop XML dump here or click to browse'}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Upload UIAutomator XML dumps to detect current screen state
            </Typography>
          </StyledDropzone>

          {uploading && (
            <Box sx={{ mt: 2 }}>
              <LinearProgress variant="determinate" value={uploadProgress} />
              <Typography variant="body2" sx={{ mt: 1 }}>
                Analyzing XML dump... {uploadProgress}%
              </Typography>
            </Box>
          )}

          {error && (
            <Alert severity="error" sx={{ mt: 2 }} action={
              <IconButton size="small" onClick={() => setError(null)}>
                <CloseIcon />
              </IconButton>
            }>
              {error}
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Detection Results */}
      {currentResult && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                Detection Results
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <StatusChip
                  status={currentResult.status}
                  label={currentResult.status.toUpperCase()}
                  size="small"
                />
                <Tooltip title="Retry with new dump">
                  <IconButton onClick={handleRetry} size="small">
                    <RefreshIcon />
                  </IconButton>
                </Tooltip>
              </Box>
            </Box>

            <Typography variant="body2" color="text.secondary" gutterBottom>
              Processed: {new Date(currentResult.timestamp).toLocaleString()}
            </Typography>

            {currentResult.topCandidates.length > 0 ? (
              <TableContainer component={Paper} variant="outlined" sx={{ mt: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Node ID</TableCell>
                      <TableCell>Score</TableCell>
                      <TableCell>Confidence</TableCell>
                      <TableCell>Action</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {currentResult.topCandidates.map((candidate, index) => (
                      <TableRow
                        key={candidate.nodeId}
                        selected={candidate.nodeId === currentResult.selectedNodeId}
                      >
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                          {candidate.nodeId.substring(0, 12)}...
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={candidate.score}
                            color={getScoreColor(candidate.score)}
                            size="small"
                            variant="outlined"
                          />
                        </TableCell>
                        <TableCell>
                          <LinearProgress
                            variant="determinate"
                            value={candidate.score}
                            sx={{ width: 100 }}
                          />
                        </TableCell>
                        <TableCell>
                          {candidate.nodeId === currentResult.selectedNodeId ? (
                            <Chip
                              icon={<CheckCircleIcon />}
                              label="Selected"
                              color="success"
                              size="small"
                            />
                          ) : (
                            <Button
                              size="small"
                              onClick={() => onNodeSelect?.(candidate.nodeId)}
                            >
                              Select
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Alert severity="info" sx={{ mt: 2 }}>
                No matching screens found. This appears to be a new state.
              </Alert>
            )}

            {/* Action Buttons */}
            <CardActions sx={{ mt: 2, pt: 2 }}>
              {currentResult.status === 'matched' && currentResult.selectedNodeId && (
                <Button
                  variant="contained"
                  color="success"
                  startIcon={<CheckCircleIcon />}
                  onClick={() => handleFeedback('accept')}
                >
                  Accept Match
                </Button>
              )}

              {currentResult.status === 'ambiguous' && (
                <>
                  <Button
                    variant="outlined"
                    startIcon={<AddIcon />}
                    onClick={() => setFeedbackDialog({ open: true, action: 'map_new' })}
                  >
                    Map as New
                  </Button>
                  <Button
                    variant="outlined"
                    startIcon={<MergeIcon />}
                    onClick={() => setFeedbackDialog({ open: true, action: 'merge' })}
                  >
                    Merge with Existing
                  </Button>
                </>
              )}

              {currentResult.status === 'unknown' && (
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={<AddIcon />}
                  onClick={() => setFeedbackDialog({ open: true, action: 'map_new' })}
                >
                  Create New Node
                </Button>
              )}

              <Button
                variant="outlined"
                startIcon={<ReplayIcon />}
                onClick={() => setFeedbackDialog({ open: true, action: 'retry' })}
              >
                Try Again
              </Button>
            </CardActions>
          </CardContent>
        </Card>
      )}

      {/* Feedback Confirmation Dialog */}
      <Dialog
        open={feedbackDialog.open}
        onClose={() => setFeedbackDialog({ open: false, action: 'map_new' })}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          Confirm Detection Feedback
        </DialogTitle>
        <DialogContent>
          <Typography>
            {feedbackDialog.action === 'map_new' && 'Create a new screen node from this dump?'}
            {feedbackDialog.action === 'merge' && 'Merge this with an existing screen node?'}
            {feedbackDialog.action === 'retry' && 'Try detection again with a different approach?'}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setFeedbackDialog({ open: false, action: 'map_new' })}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={() => handleFeedback(feedbackDialog.action)}
            startIcon={getActionIcon(feedbackDialog.action)}
          >
            {feedbackDialog.action === 'map_new' && 'Create New'}
            {feedbackDialog.action === 'merge' && 'Merge'}
            {feedbackDialog.action === 'retry' && 'Retry'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};