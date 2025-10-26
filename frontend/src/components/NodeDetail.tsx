/**
 * Node Detail Component
 *
 * Displays detailed information about a selected screen node including:
 * - Screenshots and XML dumps
 * - Selector information
 * - Metadata and provenance
 * - Incoming/outgoing edges
 * - Node status and actions
 */

import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Grid,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Tabs,
  Tab,
  Button,
  IconButton,
  Tooltip,
  Alert,
  Divider,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import {
  Visibility as ViewIcon,
  Download as DownloadIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Share as ShareIcon,
  History as HistoryIcon,
  Info as InfoIcon,
  ArrowForward as ArrowForwardIcon,
  ArrowBack as ArrowBackIcon,
} from '@mui/icons-material';
// Date formatting utility
const formatDate = (date: Date | string, formatStr: string) => {
  const d = typeof date === 'string' ? new Date(date) : date;
  switch (formatStr) {
    case 'MMM dd, yyyy HH:mm':
      return d.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    case 'MMM dd, HH:mm':
      return d.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    case 'yyyy-MM-dd HH:mm:ss':
      return d.toISOString().replace('T', ' ').substring(0, 19);
    default:
      return d.toLocaleString();
  }
};
import type { ScreenNode, ActionEdge } from '../stores/uiGraphStore';

interface NodeDetailProps {
  node: ScreenNode;
  incomingEdges?: ActionEdge[];
  outgoingEdges?: ActionEdge[];
  onEditNode?: (node: ScreenNode) => void;
  onDeleteNode?: (nodeId: string) => void;
  onExecuteEdge?: (edge: ActionEdge) => void;
  onViewScreenshot?: (path: string) => void;
  onViewXml?: (path: string) => void;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index }: TabPanelProps) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`node-detail-tabpanel-${index}`}
      aria-labelledby={`node-detail-tab-${index}`}
    >
      {value === index && <Box sx={{ py: 2 }}>{children}</Box>}
    </div>
  );
}

export const NodeDetail: React.FC<NodeDetailProps> = ({
  node,
  incomingEdges = [],
  outgoingEdges = [],
  onEditNode,
  onDeleteNode,
  onExecuteEdge,
  onViewScreenshot,
  onViewXml,
}) => {
  const [tabValue, setTabValue] = useState(0);
  const [screenshotUrl, setScreenshotUrl] = useState<string | null>(null);
  const [screenshotError, setScreenshotError] = useState<string | null>(null);

  // Load screenshot when node changes
  useEffect(() => {
    if (node.samples?.screenshotPath) {
      loadScreenshot();
    }
    return () => {
      setScreenshotUrl(null);
      setScreenshotError(null);
    };
  }, [node]);

  const loadScreenshot = async () => {
    try {
      setScreenshotError(null);
      // Convert file path to accessible URL
      // This assumes the backend serves files under /api/files/
      const url = `/api/files/${node.samples.screenshotPath.replace(/^\//, '')}`;
      setScreenshotUrl(url);
    } catch (error) {
      setScreenshotError('Failed to load screenshot');
      console.error('Failed to load screenshot:', error);
    }
  };

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success';
      case 'deprecated': return 'warning';
      case 'duplicate': return 'error';
      default: return 'default';
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'success';
    if (confidence >= 0.6) return 'warning';
    return 'error';
  };

  const formatConfidence = (confidence: number) => {
    return `${Math.round(confidence * 100)}%`;
  };

  return (
    <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <CardContent sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="h6" gutterBottom>
              {node.name}
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
              <Chip
                label={node.status}
                color={getStatusColor(node.status)}
                size="small"
              />
              <Chip
                label={`${node.selectors.length} selectors`}
                variant="outlined"
                size="small"
              />
              <Chip
                label={`${outgoingEdges.length} outgoing`}
                variant="outlined"
                size="small"
              />
              <Chip
                label={`${incomingEdges.length} incoming`}
                variant="outlined"
                size="small"
              />
            </Box>
            <Typography variant="body2" color="text.secondary">
              ID: {node.id}
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            {onEditNode && (
              <Tooltip title="Edit Node">
                <IconButton size="small" onClick={() => onEditNode(node)}>
                  <EditIcon />
                </IconButton>
              </Tooltip>
            )}
            {onDeleteNode && (
              <Tooltip title="Delete Node">
                <IconButton size="small" color="error" onClick={() => onDeleteNode(node.id)}>
                  <DeleteIcon />
                </IconButton>
              </Tooltip>
            )}
            <Tooltip title="Share Node">
              <IconButton size="small">
                <ShareIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>

        {/* Tabs */}
        <Tabs value={tabValue} onChange={handleTabChange} variant="scrollable" scrollButtons="auto">
          <Tab label="Overview" />
          <Tab label="Screenshot" />
          <Tab label="Selectors" />
          <Tab label="Metadata" />
          <Tab label="Edges" />
          <Tab label="Artifacts" />
        </Tabs>
      </CardContent>

      {/* Tab Content */}
      <Box sx={{ flex: 1, overflow: 'auto' }}>
        {/* Overview Tab */}
        <TabPanel value={tabValue} index={0}>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" gutterBottom>
                Node Information
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableBody>
                    <TableRow>
                      <TableCell component="th" sx={{ width: '40%' }}>
                        Activity
                      </TableCell>
                      <TableCell>{node.signature.activity}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">Package</TableCell>
                      <TableCell>{node.metadata.package || 'Unknown'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">Start State</TableCell>
                      <TableCell>
                        <Chip
                          label={node.startStateTag || 'none'}
                          variant="outlined"
                          size="small"
                        />
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">Capture Date</TableCell>
                      <TableCell>
                        {formatDate(node.metadata.captureTimestamp, 'MMM dd, yyyy HH:mm')}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">Operator</TableCell>
                      <TableCell>{node.metadata.operatorId}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" gutterBottom>
                Signature Details
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableBody>
                    <TableRow>
                      <TableCell component="th" sx={{ width: '40%' }}>
                        Signature Hash
                      </TableCell>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '12px' }}>
                        {node.signature.hash}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">Layout Fingerprint</TableCell>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '12px' }}>
                        {node.signature.layoutFingerprint}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">Resource IDs</TableCell>
                      <TableCell>{node.signature.resourceIds.length}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">Required Texts</TableCell>
                      <TableCell>{node.signature.requiredTexts.join(', ') || 'None'}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>

            {node.hints.length > 0 && (
              <Grid item xs={12}>
                <Typography variant="subtitle2" gutterBottom>
                  Hints
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {node.hints.map((hint, index) => (
                    <Chip key={index} label={hint} variant="outlined" size="small" />
                  ))}
                </Box>
              </Grid>
            )}
          </Grid>
        </TabPanel>

        {/* Screenshot Tab */}
        <TabPanel value={tabValue} index={1}>
          <Box sx={{ textAlign: 'center' }}>
            {screenshotUrl ? (
              <>
                <Box
                  component="img"
                  src={screenshotUrl}
                  alt={node.name}
                  sx={{
                    maxWidth: '100%',
                    maxHeight: '400px',
                    border: '1px solid #ddd',
                    borderRadius: 1,
                    mb: 2,
                  }}
                  onError={() => setScreenshotError('Failed to load screenshot')}
                />
                <Box sx={{ display: 'flex', gap: 1, justifyContent: 'center' }}>
                  {onViewScreenshot && (
                    <Button
                      startIcon={<ViewIcon />}
                      onClick={() => onViewScreenshot(node.samples.screenshotPath)}
                    >
                      View Full Size
                    </Button>
                  )}
                  <Button startIcon={<DownloadIcon />} href={screenshotUrl} download>
                    Download
                  </Button>
                </Box>
              </>
            ) : screenshotError ? (
              <Alert severity="error">{screenshotError}</Alert>
            ) : (
              <Typography color="text.secondary">No screenshot available</Typography>
            )}
          </Box>
        </TabPanel>

        {/* Selectors Tab */}
        <TabPanel value={tabValue} index={2}>
          <TableContainer component={Paper} variant="outlined">
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>Value</TableCell>
                  <TableCell>Confidence</TableCell>
                  <TableCell>Last Validated</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {node.selectors.map((selector) => (
                  <TableRow key={selector.id}>
                    <TableCell>
                      <Chip label={selector.type} variant="outlined" size="small" />
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '12px' }}>
                      {selector.value}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={formatConfidence(selector.confidence)}
                        color={getConfidenceColor(selector.confidence)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      {selector.lastValidatedAt
                        ? formatDate(selector.lastValidatedAt, 'MMM dd, HH:mm')
                        : 'Never'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>

        {/* Metadata Tab */}
        <TabPanel value={tabValue} index={3}>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" gutterBottom>
                Capture Metadata
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableBody>
                    <TableRow>
                      <TableCell component="th" sx={{ width: '40%' }}>
                        Timestamp
                      </TableCell>
                      <TableCell>
                        {formatDate(node.metadata.captureTimestamp, 'yyyy-MM-dd HH:mm:ss')}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">Operator ID</TableCell>
                      <TableCell>{node.metadata.operatorId}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">Emulator Build</TableCell>
                      <TableCell>{node.metadata.emulatorBuild || 'Unknown'}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" gutterBottom>
                Application Info
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableBody>
                    <TableRow>
                      <TableCell component="th" sx={{ width: '40%' }}>
                        Package
                      </TableCell>
                      <TableCell>{node.metadata.package || 'Unknown'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">Activity</TableCell>
                      <TableCell>{node.metadata.activity || 'Unknown'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">Class</TableCell>
                      <TableCell>{node.metadata.class || 'Unknown'}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Edges Tab */}
        <TabPanel value={tabValue} index={4}>
          <Grid container spacing={3}>
            {/* Incoming Edges */}
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" gutterBottom>
                Incoming Actions ({incomingEdges.length})
              </Typography>
              {incomingEdges.length > 0 ? (
                <List dense>
                  {incomingEdges.map((edge) => (
                    <ListItem key={edge.id} sx={{ border: 1, borderColor: 'divider', mb: 1, borderRadius: 1 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                        <ArrowBackIcon sx={{ mr: 1, color: 'text.secondary' }} />
                        <Box sx={{ flex: 1 }}>
                          <Typography variant="body2">
                            {edge.action.kind}
                            {edge.action.text && (
                              <Typography variant="caption" component="span" sx={{ ml: 1 }}>
                                "{edge.action.text}"
                              </Typography>
                            )}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            From: {edge.fromNodeId.substring(0, 8)}...
                          </Typography>
                        </Box>
                        <Chip
                          label={formatConfidence(edge.confidence)}
                          color={getConfidenceColor(edge.confidence)}
                          size="small"
                          sx={{ mr: 1 }}
                        />
                        {onExecuteEdge && (
                          <IconButton size="small" onClick={() => onExecuteEdge(edge)}>
                            <ArrowForwardIcon />
                          </IconButton>
                        )}
                      </Box>
                    </ListItem>
                  ))}
                </List>
              ) : (
                <Typography color="text.secondary">No incoming actions</Typography>
              )}
            </Grid>

            {/* Outgoing Edges */}
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" gutterBottom>
                Outgoing Actions ({outgoingEdges.length})
              </Typography>
              {outgoingEdges.length > 0 ? (
                <List dense>
                  {outgoingEdges.map((edge) => (
                    <ListItem key={edge.id} sx={{ border: 1, borderColor: 'divider', mb: 1, borderRadius: 1 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                        <ArrowForwardIcon sx={{ mr: 1, color: 'text.secondary' }} />
                        <Box sx={{ flex: 1 }}>
                          <Typography variant="body2">
                            {edge.action.kind}
                            {edge.action.text && (
                              <Typography variant="caption" component="span" sx={{ ml: 1 }}>
                                "{edge.action.text}"
                              </Typography>
                            )}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            To: {edge.toNodeId ? edge.toNodeId.substring(0, 8) + '...' : 'Unknown'}
                          </Typography>
                        </Box>
                        <Chip
                          label={formatConfidence(edge.confidence)}
                          color={getConfidenceColor(edge.confidence)}
                          size="small"
                          sx={{ mr: 1 }}
                        />
                        {onExecuteEdge && (
                          <IconButton size="small" onClick={() => onExecuteEdge(edge)}>
                            <ArrowForwardIcon />
                          </IconButton>
                        )}
                      </Box>
                    </ListItem>
                  ))}
                </List>
              ) : (
                <Typography color="text.secondary">No outgoing actions</Typography>
              )}
            </Grid>
          </Grid>
        </TabPanel>

        {/* Artifacts Tab */}
        <TabPanel value={tabValue} index={5}>
          <Typography variant="subtitle2" gutterBottom>
            Artifact Bundle
          </Typography>
          <TableContainer component={Paper} variant="outlined">
            <Table>
              <TableBody>
                <TableRow>
                  <TableCell component="th" sx={{ width: '20%' }}>
                    Screenshot
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {node.samples.screenshotPath}
                      </Typography>
                      {onViewScreenshot && (
                        <IconButton
                          size="small"
                          onClick={() => onViewScreenshot(node.samples.screenshotPath)}
                        >
                          <ViewIcon fontSize="small" />
                        </IconButton>
                      )}
                    </Box>
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell component="th">XML Dump</TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {node.samples.xmlPath}
                      </Typography>
                      {onViewXml && (
                        <IconButton size="small" onClick={() => onViewXml(node.samples.xmlPath)}>
                          <ViewIcon fontSize="small" />
                        </IconButton>
                      )}
                    </Box>
                  </TableCell>
                </TableRow>
                {node.samples.metadataPath && (
                  <TableRow>
                    <TableCell component="th">Metadata</TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {node.samples.metadataPath}
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
                <TableRow>
                  <TableCell component="th">Checksum</TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {node.samples.checksum}
                    </Typography>
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>
      </Box>
    </Card>
  );
};