# Frontend Zustand Store Structure

This directory contains the Zustand state management structure for the AutoApp UI Map & Intelligent Flow Engine feature.

## Store Overview

### 1. Discovery Store (`useDiscoveryStore`)
Manages UI state discovery and graph building functionality.

**Key Features:**
- Capture and store UI states from the Android emulator
- Build and maintain UI graphs with state transitions
- Screenshot management and analysis
- Device connection status tracking
- State selection and navigation

**Usage Example:**
```typescript
import { useDiscoveryStore } from './state';

// In a React component
const {
  currentGraph,
  capturedStates,
  isCapturing,
  captureState,
  selectState
} = useDiscoveryStore();

// Capture current UI state
await captureState();

// Select a specific state
const state = capturedStates[0];
selectState(state);
```

### 2. Flow Store (`useFlowStore`)
Manages flow definitions and execution for automated testing.

**Key Features:**
- Flow CRUD operations (Create, Read, Update, Delete)
- Flow execution management and monitoring
- Validation and error handling
- Flow templates and examples
- Import/export functionality

**Usage Example:**
```typescript
import { useFlowStore, useSelectedFlow } from './state';

// In a React component
const {
  flows,
  createFlow,
  executeFlow,
  isExecuting
} = useFlowStore();

const selectedFlow = useSelectedFlow();

// Create a new flow
const newFlow = await createFlow();

// Execute a flow
await executeFlow(newFlow.id);
```

### 3. WebRTC Store (`useWebRTCStore`)
Manages WebRTC connections and streaming for emulator display.

**Key Features:**
- Connection status and health monitoring
- Stream quality metrics
- Configuration management
- Reconnection logic with exponential backoff
- Error handling and recovery

**Usage Example:**
```typescript
import { useWebRTCStore, useConnectionQuality } from './state';

// In a React component
const {
  isConnected,
  status,
  connect,
  disconnect
} = useWebRTCStore();

const { quality, isGood, status: qualityStatus } = useConnectionQuality();

// Connect to emulator stream
await connect();

// Disconnect from stream
await disconnect();
```

### 4. Settings Store (`useSettingsStore`)
Manages user preferences and application configuration.

**Key Features:**
- UI preferences (theme, language, compact mode)
- Capture settings and timeouts
- Debug and logging options
- Performance preferences
- Persistent storage with localStorage

**Usage Example:**
```typescript
import { useSettingsStore } from './state';

// In a React component
const {
  settings,
  updateSettings,
  saveSettings
} = useSettingsStore();

// Update UI theme
updateSettings({
  ui: { theme: 'dark' }
});

// Save settings to persistent storage
await saveSettings();
```

## Selector Hooks

The following selector hooks provide convenient access to derived state:

- `useSelectedFlow()` - Get currently selected flow
- `useSelectedExecution()` - Get currently selected execution
- `useFilteredFlows(searchQuery, category)` - Get filtered flows
- `useExecutionsByStatus(status)` - Get executions by status
- `useRecentStates(limit)` - Get recent captured states
- `useConnectionQuality()` - Get connection quality indicator

## TypeScript Interfaces

### Core Types

- `UIState` - Represents a captured UI state
- `UIElement` - Individual UI element within a state
- `UIGraph` - Graph representation of UI states and transitions
- `FlowDefinition` - Complete flow definition
- `FlowStep` - Individual step within a flow
- `FlowExecution` - Flow execution instance
- `WebRTCStatus` - WebRTC connection status
- `UserSettings` - User preference configuration

### Helper Types

- `Transition` - Transition between UI states
- `ScreenshotInfo` - Screenshot metadata
- `DeviceInfo` - Device information at capture time
- `StepResult` - Result of step execution
- `ExecutionLog` - Execution log entry
- `StreamMetrics` - Stream quality metrics
- `ValidationResult` - Flow validation results

## Best Practices

1. **Use Selector Hooks**: Prefer using the provided selector hooks for accessing derived state
2. **Async Actions**: Store async actions return promises and handle errors appropriately
3. **Type Safety**: All stores are fully typed with TypeScript interfaces
4. **DevTools Integration**: Stores are integrated with Redux DevTools for debugging
5. **Persistence**: Settings store uses persistence middleware for user preferences

## Development

### Testing Store Functionality

Use the test functions in `test-stores.ts` to verify store functionality during development:

```typescript
import { testStoreFunctionality, testStoreInteractions } from './state/test-stores';

// Test store initialization
testStoreFunctionality();

// Test store interactions
testStoreInteractions();
```

### Adding New Features

1. Define new types and interfaces at the top of `index.ts`
2. Add new state properties to the appropriate store interface
3. Implement actions and async actions in the store implementation
4. Add selector hooks if needed for derived state
5. Update TypeScript types and ensure compatibility

## Integration with Components

The stores are designed to be easily integrated with React components using Zustand hooks:

```typescript
// Example component using multiple stores
function DiscoveryPanel() {
  const {
    capturedStates,
    isCapturing,
    captureState
  } = useDiscoveryStore();

  const { connectionQuality } = useConnectionQuality();

  const { settings } = useSettingsStore();

  return (
    <div>
      <button
        onClick={captureState}
        disabled={isCapturing}
      >
        {isCapturing ? 'Capturing...' : 'Capture State'}
      </button>

      <div>
        Connection Quality: {connectionQuality.quality}
      </div>

      <div>
        States Captured: {capturedStates.length}
      </div>
    </div>
  );
}
```

## Error Handling

All stores include comprehensive error handling:

- Errors are stored in the store's `error` property
- Async actions reject promises on failure
- Error states are automatically cleared on successful operations
- Loading states are managed for async operations

## Performance Considerations

- Zustand's shallow comparison prevents unnecessary re-renders
- Selector hooks can be used to optimize component updates
- Large datasets (like flow executions) should be paginated
- Settings persistence uses efficient localStorage access