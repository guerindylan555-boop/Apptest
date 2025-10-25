# Phase 0 Research: UI Map & Discovery System

**Feature**: AutoApp UI Map & Intelligent Flow Engine (Phase 1: Discovery)
**Date**: 2025-10-25
**Scope**: Discovery capability, UI state capture, graph building, basic editing

## Research Summary

This document captures the research findings for implementing the UI discovery and state capture system. Based on the existing codebase analysis and constitution requirements, we've established patterns for Android UI automation, WebRTC streaming integration, and graph data persistence.

## Technical Decisions

### 1. Android UI Automation Framework

**Decision**: UIAutomator2 + ADB Commands

**Rationale**:
- Native Android support with reliable element identification
- Container-compatible (no additional runtime dependencies)
- Proven pattern in existing codebase (Frida integration already uses ADB)
- Sub-1s performance achievable with optimized command patterns
- Standard tooling with extensive documentation

**Alternatives Considered**:
- Appium: Heavy dependency footprint, container complexity
- Custom Frida hooks: Powerful but higher maintenance overhead for basic UI capture
- Solo/Espresso: Testing-focused, not ideal for discovery automation

### 2. State Capture Architecture

**Decision**: Parallel ADB Command Execution with Direct Output Capture

**Rationale**:
- Uses `adb exec-out` for direct stdout capture (no temporary files)
- Parallel execution of activity detection, UI dump, and screenshot capture
- XML normalization with volatile attribute stripping for stable hashing
- Achieves sub-1s capture times as required by specification

**Key Commands**:
```bash
# Activity name (150-300ms)
adb -s $SERIAL shell dumpsys activity activities | grep topResumedActivity

# UI hierarchy (200-400ms)
adb -s $SERIAL exec-out uiautomator dump /dev/tty

# Screenshot (300-600ms)
adb -s $SERIAL exec-out screencap -p
```

### 3. WebRTC Streaming Integration

**Decision**: Leverage Existing WebRTC Infrastructure

**Rationale**:
- Existing Envoy gateway and emulator integration already handles WebRTC
- StreamViewer component already provides stable streaming with reconnection logic
- No new infrastructure required
- Constitution mandates WebRTC over ws-scrcpy

**Implementation Pattern**:
- Discovery panel will be added alongside existing StreamViewer
- WebRTC stream remains primary interaction surface
- No changes to streaming configuration needed

### 4. Data Persistence Strategy

**Decision**: JSON Files with Git Version Control

**Rationale**:
- LLM-friendly format for Claude Code integration
- Simple, human-readable for debugging
- Git-based versioning supports collaboration
- No additional infrastructure required
- Fits constitution requirement for artifact storage

**File Structure**:
```
/app/data/
├── graph.json           # UI graph (states, transitions, selectors)
├── sessions/           # Event logs by session
│   └── 2025-10-25T15-30.jsonl
└── screenshots/        # State screenshots
    └── abc123def.png
```

### 5. Graph Management API

**Decision**: REST API with TypeScript Types

**Rationale**:
- Consistent with existing backend architecture
- TypeScript provides type safety for frontend integration
- REST patterns match existing streamerService patterns
- Simple testing and debugging

**Performance Targets**:
- Graph validation: <2s for 50 states, 100 transitions
- State capture: <1s total including ADB operations
- API responses: <500ms p95

### 6. Frontend Integration

**Decision**: React Panel Component Replacing GPS Panel

**Rationale**:
- GPS functionality is legacy (no active use in current spec)
- Maintains existing app layout and navigation
- Leverages existing feature flag system
- Consistent with FridaPanel pattern

**Component Structure**:
```typescript
DiscoveryPanel.tsx
├── State capture controls (Snapshot, Mark Transition)
├── Current state display (activity, digest, screenshot)
├── Elements list (selectors, bounds, text)
└── Graph mini-map (table view for Phase 1)
```

## Architecture Integration

### Existing Infrastructure Alignment

**Docker Compose**: No changes required
- Backend already has ADB access via host.docker.internal
- Data volume can be added to existing compose setup
- WebRTC streaming infrastructure remains unchanged

**Backend Service Extension**:
- Add new routes: `/api/graph/*`, `/api/state/*`
- Introspection service alongside existing streamerService
- ADB connection pooling for performance

**Frontend Feature Flags**:
- `discoveryPanel: true` (enable new functionality)
- `gpsPanel: false` (disable legacy GPS panel)
- Leverages existing featureFlagsStore pattern

### Constitutional Compliance

✅ **Containers Only**: All services run in Docker containers
✅ **Immutable Configuration**: Environment-based configuration
✅ **WebRTC Streaming**: Uses existing WebRTC infrastructure
✅ **Structured Artifacts**: JSON files in mounted volume
✅ **TypeScript Strict**: Maintains code quality standards
✅ **Health Endpoints**: Add `/healthz` check for new APIs
✅ **No Public Exposure**: ADB/UI automation stays internal

## Performance Considerations

### ADB Command Optimization

1. **Connection Pooling**: Reuse ADB connections for multiple captures
2. **Parallel Execution**: Run activity, UI dump, screenshot simultaneously
3. **Direct Output**: Use `exec-out` to avoid temporary file I/O
4. **Buffer Management**: Optimal buffer sizes for different capture types

### Graph Operations

1. **In-Memory Processing**: Graph validation and merging in memory
2. **Lazy Loading**: Load graph on-demand for UI panel
3. **Incremental Updates**: Only save changes, not full graph each time
4. **Compaction**: Periodic graph file compaction to remove duplicates

## Implementation Risk Assessment

### Low Risk
- **File-based persistence**: Simple, well-understood pattern
- **REST API**: Consistent with existing backend patterns
- **React component**: Standard frontend development

### Medium Risk
- **ADB Performance**: Sub-1s capture requires optimization
- **Graph scalability**: 500 state limit needs efficient algorithms
- **State deduplication**: XML normalization complexity

### Mitigations
- Performance testing with real MaynDrive app
- Incremental rollout starting with basic state capture
- Conservative similarity thresholds for state merging

## Next Steps

1. **Phase 1 Implementation**: Create data models and API contracts
2. **Backend Services**: Implement introspection and graph management
3. **Frontend Component**: Build DiscoveryPanel with state capture UI
4. **Integration Testing**: End-to-end testing with MaynDrive app
5. **Performance Validation**: Verify sub-1s capture times

## Dependencies

**Required**: None (all dependencies already available in existing codebase)

**Optional Enhancements**:
- Advanced graph visualization (Phase 2)
- Frida-assisted selectors (Phase 2+)
- Flow definition DSL (Phase 2)

---

*Research complete. All technical unknowns resolved. Ready to proceed with Phase 1 design.*