# Graph JSON Serialization Integration Tests

Comprehensive test suite for UI Graph (UTG) JSON serialization, persistence, and validation. This test suite validates the graph persistence layer that stores all discovered UI states and transitions for the Discovery system.

## Overview

The graph serialization tests validate:
- Graph creation and initialization
- State addition and persistence
- Transition recording and storage
- JSON serialization/deserialization
- Version management and compatibility
- Performance benchmarks for large graphs
- Error handling and corruption detection
- Edge cases and boundary conditions
- Concurrent access scenarios

## Test Structure

### Main Test Files

- **`graph-serialization.test.ts`** - Complete integration test suite
- **`run-graph-tests.ts`** - Test runner with configuration options
- **`graph-tests-documentation.md`** - This documentation file

### Test Categories

#### 1. Graph Creation Tests
- Empty graph creation and validation
- Single state graph initialization
- Multiple states with unique IDs
- Graph statistics calculation

#### 2. State Management Tests
- State addition to graphs
- State deduplication and similarity detection
- State metadata validation
- State selector validation

#### 3. Transition Tests
- Transition creation between states
- Action type validation (tap, type, swipe, back, intent)
- Transition evidence tracking
- Confidence scoring

#### 4. Serialization Tests
- JSON serialization/deserialization
- Compact vs pretty printing
- File system persistence
- Binary data handling

#### 5. Version Management Tests
- Version tracking and progression
- Backward compatibility
- Migration scenarios

#### 6. Performance Tests
- Small graph processing (< 2s target)
- Large graph handling (up to 500 states)
- Serialization size benchmarks
- Memory usage monitoring

#### 7. Error Handling Tests
- Invalid JSON handling
- Missing required fields
- Invalid state IDs
- Broken transition references

#### 8. Edge Case Tests
- Empty graphs
- Single state graphs
- Graphs with no transitions
- Maximum field lengths
- Special characters handling

#### 9. Concurrency Tests
- Concurrent graph access
- Optimistic locking simulation

## Usage

### Running All Tests

```bash
# Run all tests with default settings
ts-node tests/integration/run-graph-tests.ts

# Run with verbose output
ts-node tests/integration/run-graph-tests.ts -v

# Run with performance benchmarks
ts-node tests/integration/run-graph-tests.ts -p

# Run and save results
ts-node tests/integration/run-graph-tests.ts -o test-results.json

# Production environment run with cleanup
ts-node tests/integration/run-graph-tests.ts -e production -c
```

### Command Line Options

```
Options:
  -v, --verbose        Enable verbose logging
  -p, --performance    Enable performance benchmark tests
  -c, --cleanup        Cleanup test files after completion
  -o, --output FILE    Save test results to JSON file
  -e, --environment ENV Set test environment (development, staging, production)
  -f, --filter PATTERN Filter tests by name pattern
  -h, --help          Show help message
```

### Environment Variables

```bash
# Enable performance benchmarks
export ENABLE_PERFORMANCE_TESTS=true

# Enable verbose logging
export VERBOSE_TESTS=true

# Keep test files after completion
export CLEANUP_AFTER_TEST=false

# Test configuration
export NODE_ENV=development
```

## Test Data and Examples

### Sample Graph Structure

```typescript
interface UIGraph {
  version: string;
  createdAt: string;
  updatedAt: string;
  packageName: string;
  states: StateRecord[];
  transitions: TransitionRecord[];
  stats: {
    stateCount: number;
    transitionCount: number;
    averageDegree: number;
    isolatedStates: number;
    lastCapture?: string;
  };
  metadata: {
    captureTool: string;
    androidVersion?: string;
    appVersion?: string;
    deviceInfo?: string;
    totalCaptureTime: number;
    totalSessions: number;
  };
}
```

### Test Data Files

The tests automatically generate sample data files in the `tests/integration/data/` directory:

- `small-graph.json` - 5 states, 8 transitions
- `medium-graph.json` - 50 states, 100 transitions
- `corrupted-*.json` - Invalid JSON files for error testing

## Performance Benchmarks

### Target Performance

- **Small graphs** (< 50 states): < 2 seconds processing time
- **Large graphs** (up to 500 states): Linear scaling performance
- **Serialization size**: Efficient JSON representation
- **Memory usage**: Reasonable memory footprint

### Performance Metrics

The tests track:
- Processing time per operation
- Memory usage before/after operations
- Serialized file sizes
- Operations per second for large graphs

## Error Handling

### Validation Rules

The test suite validates:

1. **Required Fields**: All mandatory fields must be present
2. **Data Types**: Fields must have correct types
3. **ID Format**: State and transition IDs must be valid SHA256 hashes
4. **Reference Integrity**: Transitions must reference existing states
5. **Timestamp Format**: ISO 8601 format required
6. **JSON Structure**: Valid JSON syntax required

### Error Scenarios

Tests cover these error scenarios:
- Corrupted JSON data
- Missing required fields
- Invalid data types
- Circular references
- Broken state references
- Invalid ID formats

## Integration with Backend Services

### GraphService Integration

The tests use the actual `GraphService` from `src/services/graphService.ts`:

```typescript
import { GraphService } from '../../src/services/graphService';

const graphService = new GraphService();
const graph = await graphService.loadGraph();
await graphService.addState(newState);
await graphService.addTransition(fromId, toId, action);
```

### JsonStorageService Integration

Tests use the `JsonStorageService` for file operations:

```typescript
import { JsonStorageService } from '../../src/services/json-storage';

const storage = new JsonStorageService();
await storage.create('graph.json', graphData);
await storage.read('graph.json');
await storage.update('graph.json', newGraphData, { expectedVersion: '1.0.0' });
```

## Continuous Integration

### GitHub Actions Integration

```yaml
name: Graph Serialization Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '18'
      - run: npm install
      - run: npm run build
      - run: ts-node tests/integration/run-graph-tests.ts -p -o results.json
      - uses: actions/upload-artifact@v2
        with:
          name: test-results
          path: results.json
```

### Test Reporting

Tests generate comprehensive reports:
- JSON format for programmatic consumption
- Markdown format for human readability
- Performance metrics and benchmarks
- Detailed error information

## Troubleshooting

### Common Issues

1. **Test Timeout**: Increase timeout for large graph tests
2. **Memory Issues**: Reduce graph size in performance tests
3. **File Permissions**: Ensure write access to test directories
4. **Dependency Issues**: Install all required dependencies

### Debug Mode

Run tests with maximum verbosity:

```bash
ts-node tests/integration/run-graph-tests.ts -v -p -e development -o debug-results.json
```

### Test Isolation

Tests use isolated temporary directories to avoid conflicts:

```typescript
const testConfig = {
  testDir: resolve(__dirname, '..'),
  testDataDir: resolve(__dirname, 'data'),
  tempDir: resolve(__dirname, 'temp'),
  cleanupAfterTest: true
};
```

## Contributing

### Adding New Tests

1. Create test method following naming convention: `testDescription`
2. Use `runTest()` wrapper for consistent error handling
3. Add appropriate test data generation
4. Include performance metrics if relevant
5. Update documentation

### Test Categories

Add tests to appropriate category in `runCompleteTestSuite()`:

```typescript
await this.runNewCategoryTests();
```

### Example Test

```typescript
await this.runTest('Descriptive test name', async () => {
  // Test implementation
  const result = await someOperation();

  // Assertions
  if (!result.isValid) {
    throw new Error('Test failed reason');
  }

  return { metric: result.value };
});
```

## Best Practices

1. **Test Isolation**: Each test should be independent
2. **Cleanup**: Clean up resources after tests
3. **Performance**: Include timing and memory metrics
4. **Validation**: Use schema validators for structure checks
5. **Error Coverage**: Test both success and failure scenarios
6. **Documentation**: Document test purpose and expected outcomes

## Resources

- [Graph Types Documentation](../../src/types/graph.ts)
- [GraphService Implementation](../../src/services/graphService.ts)
- [JSON Storage Service](../../src/services/json-storage.ts)
- [Hash Utilities](../../src/utils/hash.ts)
- [Discovery Configuration](../../src/config/discovery.ts)

## License

This test suite is part of the AutoApp UI Map & Intelligent Flow Engine project.