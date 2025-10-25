# State Deduplication Integration Tests

Comprehensive test suite for validating state deduplication logic accuracy in the AutoApp UI Map & Intelligent Flow Engine. This test suite ensures ≥95% accuracy in state deduplication, which is critical for maintaining clean UI graphs without duplicate states.

## Overview

The state deduplication system is a core component of the AutoApp UI discovery engine that:

- **Detects duplicate UI states** using digest-based hashing and similarity algorithms
- **Merges similar states** to maintain clean graph structures
- **Preserves transition integrity** during state merging operations
- **Optimizes performance** for real-time state capture scenarios

## Test Coverage

### 🔍 Digest-Based State Matching Tests
- **Identical digest generation**: Validates that identical UI hierarchies produce the same SHA256 digest
- **Digest consistency**: Ensures reproducible digest generation across multiple calls
- **Selector impact on digests**: Tests how different selectors affect digest generation
- **State ID generation**: Validates state ID creation from package, activity, and digest combinations

### 📊 State Similarity Detection Algorithm Tests
- **Jaccard similarity calculation**: Tests selector set similarity using Jaccard index
- **Text similarity algorithms**: Validates text content similarity detection
- **Comprehensive state similarity**: Tests weighted combination of selector and text similarity
- **Edge case handling**: Validates behavior with empty, minimal, or malformed state data

### 🎯 Selector-Based Deduplication Tests
- **Selector prioritization**: Tests proper handling of rid > desc > text > cls > bounds priority
- **Selector normalization**: Validates consistent selector representation regardless of order
- **Selector variations**: Tests behavior with missing, extra, or modified selector properties
- **Large selector sets**: Validates performance with 100+ selectors per state

### 📱 Activity-Aware Deduplication Tests
- **Activity boundary enforcement**: Ensures states from different activities never merge
- **Package boundary enforcement**: Validates that different packages never merge
- **Activity edge cases**: Tests empty, null, or special character activity names
- **Activity name normalization**: Validates consistent activity name handling

### 🎚️ Fuzzy Matching Threshold Tests
- **Threshold sensitivity**: Tests merge behavior across different threshold values (0.5-0.95)
- **Threshold edge cases**: Validates behavior with 0.0 (always merge) and 1.0 (identical only)
- **Invalid threshold handling**: Tests error handling for negative or >1.0 thresholds
- **Performance impact**: Validates threshold processing performance with large state sets

### 🔧 Merge Conflict Resolution Tests
- **Simple state merging**: Tests basic merge operations for identical states
- **Transition preservation**: Validates transition updates during state merges
- **Complex conflict resolution**: Tests merges with multiple inbound/outbound transitions
- **Self-loop prevention**: Ensures states cannot be merged with themselves
- **Invalid state handling**: Tests error handling for non-existent state IDs

### ⚡ Performance Validation Tests
- **Deduplication speed**: Targets <100ms per state comparison
- **Memory usage**: Validates <10MB memory usage for large state sets
- **Large state processing**: Tests performance with 1000+ selectors
- **Concurrent operations**: Validates thread-safety and performance under load
- **Scalability testing**: Ensures linear performance degradation with state count

### 🎯 Accuracy Validation Tests
- **Known state pair validation**: Tests against pre-validated state pairs
- **Edge case accuracy**: Validates accuracy with minimal and maximal state variations
- **Overall accuracy measurement**: Targets ≥95% accuracy across all test scenarios
- **False positive/negative detection**: Identifies and measures incorrect merge decisions

## Test Data

### MaynDrive Sample Hierarchies
The test suite includes realistic UI hierarchies from the MaynDrive application:

- **Home Screen**: Navigation elements, storage indicators, app branding
- **Files Screen**: File listings, upload buttons, folder navigation
- **Settings Screen**: Account sections, backup toggles, configuration options

### Test State Categories
- **Identical States**: Same digest, should always merge (100% similarity)
- **Similar States**: Minor differences, should merge at 0.9 threshold (90-95% similarity)
- **Different States**: Different activities/packages, should never merge (0% similarity)
- **Edge Cases**: Empty states, malformed data, boundary conditions

## Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| State comparison speed | <100ms | Per state similarity calculation |
| Memory usage | <10MB | For large state set processing |
| Merge operation time | <300ms | Complex merge with transitions |
| Digest generation | <50ms | For 1000+ selectors |
| Overall accuracy | ≥95% | Correct merge decisions |

## Running Tests

### Prerequisites
```bash
# Ensure dependencies are installed
npm install

# Enable debug mode for detailed output
export DEBUG=true
```

### Execute Tests
```bash
# Run all state deduplication tests
npm test -- state-dedup.test.ts

# Run with detailed output
DEBUG=true npm test -- state-dedup.test.ts

# Run specific test categories
npm test -- --grep "Digest-based"
npm test -- --grep "Performance"
npm test -- --grep "Accuracy"
```

### Test Output Format
```
🧪 Starting State Deduplication Integration Tests...

🔍 Testing Digest-Based State Matching...
📊 Testing State Similarity Detection Algorithms...
🎯 Testing Selector-Based Deduplication...
📱 Testing Activity-Aware Deduplication...
🎚️ Testing Fuzzy Matching Thresholds...
🔧 Testing Merge Conflict Resolution...
⚡ Testing Performance Validation...
🎯 Testing Accuracy Validation...

╔══════════════════════════════════════════════════════════════╗
║                STATE DEDUPLICATION TEST SUMMARY              ║
╠══════════════════════════════════════════════════════════════╣
║ Tests Passed:    45 / 45 (100.0%)                           ║
║ Benchmarks:      8 / 8 (100.0%)                             ║
║ Overall Accuracy: 97.8%   (✓)                                ║
║ Total Time:      1234ms                                      ║
╚══════════════════════════════════════════════════════════════╝
```

## Test Architecture

### Core Components
- **StateDeduplicationTestSuite**: Main test orchestrator
- **Test Fixtures**: Pre-defined state hierarchies and test data
- **Performance Monitors**: Memory and timing measurements
- **Accuracy Calculators**: Statistical analysis of test results

### Test Data Structure
```typescript
interface StateRecord {
  id: string;           // SHA256 hash of package + activity + digest
  package: string;      // Android package name
  activity: string;     // Current activity name
  digest: string;       // Normalized hash of UI hierarchy
  selectors: Selector[]; // Interactive element selectors
  visibleText: string[]; // Screen text content
  createdAt: string;    // Timestamp
  updatedAt: string;    // Last modification time
  metadata?: {          // Capture metadata
    captureMethod: 'adb' | 'frida';
    captureDuration: number;
    elementCount: number;
    hierarchyDepth: number;
  };
}
```

### Performance Monitoring
```typescript
interface PerformanceBenchmark {
  operation: string;    // Test operation name
  targetTime: number;   // Target completion time (ms)
  actualTime: number;   // Actual completion time (ms)
  passed: boolean;      // Performance target met
  memoryUsage?: number; // Memory consumed (bytes)
}
```

## Integration Points

### Backend Services
- **GraphService**: State storage and merge operations
- **HashUtils**: Digest generation and similarity calculations
- **DiscoveryConfig**: Merge thresholds and performance targets

### Test Dependencies
- **JSON Storage**: Temporary graph file for merge testing
- **Memory Profiling**: Node.js process.memoryUsage() for monitoring
- **File System**: Temporary file creation and cleanup

## Configuration

### Environment Variables
```bash
# Performance tuning
TARGET_CAPTURE_TIME=1000      # Target capture time (ms)
MERGE_THRESHOLD=0.9           # State similarity threshold
DEBUG=true                    # Enable detailed logging

# Test configuration
MAX_GRAPH_MEMORY=104857600    # Max memory for graph ops (100MB)
MAX_SELECTORS_PER_STATE=100   # Max selectors per test state
```

### Test Configuration
```typescript
const TEST_CONFIG = {
  PERFORMANCE_TARGETS: {
    DEDUPLICATION_TIME: 100,    // ms per state
    MEMORY_USAGE: 10485760,     // 10MB
    MERGE_OPERATION: 300,       // ms for complex merges
    ACCURACY_TARGET: 95         // percentage
  },
  TEST_DATA: {
    STATE_COUNT: 50,           // Test states per category
    SELECTOR_COUNT: 20,        // Average selectors per state
    TEXT_COUNT: 10,            // Average text items per state
    SIMILARITY_PAIRS: 100      // State pairs for accuracy testing
  }
};
```

## Debugging and Troubleshooting

### Common Issues

**Performance Test Failures**
- Check system memory availability
- Verify no resource-intensive processes running
- Consider adjusting performance targets for test environment

**Accuracy Test Failures**
- Review similarity threshold settings
- Check test data for edge cases
- Validate selector normalization logic

**Merge Test Failures**
- Verify graph service initialization
- Check temporary file permissions
- Ensure proper cleanup between tests

### Debug Mode
Enable debug mode for detailed test execution information:
```bash
DEBUG=true npm test -- state-dedup.test.ts
```

Debug output includes:
- Individual test results with detailed metrics
- Performance measurements with memory usage
- Similarity calculations and threshold comparisons
- Error messages and stack traces

## Continuous Integration

### CI/CD Integration
```yaml
# GitHub Actions example
- name: Run State Deduplication Tests
  run: |
    npm run test:deduplication
  env:
    NODE_ENV: test
    DEBUG: false
```

### Quality Gates
- **All tests must pass**: 100% test success rate
- **Accuracy target**: ≥95% deduplication accuracy
- **Performance targets**: All benchmarks within limits
- **No memory leaks**: Memory usage within acceptable bounds

## Contributing

### Adding New Test Cases
1. Define test state in `TEST_STATES` array
2. Create similarity test case in `SIMILARITY_TEST_CASES`
3. Add test method to appropriate test category
4. Update performance targets if needed
5. Document expected behavior in comments

### Performance Optimization
- Monitor test execution time
- Optimize large state set handling
- Consider batch processing for similarity calculations
- Profile memory usage patterns

## Future Enhancements

### Planned Test Improvements
- **Machine Learning Integration**: Test ML-based similarity detection
- **Real Device Testing**: Validate with actual Android device hierarchies
- **Concurrent Testing**: Multi-threaded deduplication validation
- **Regression Testing**: Automated accuracy monitoring over time

### Advanced Test Scenarios
- **Dynamic Content Handling**: Test states with time-based content
- **Internationalization**: Test with multi-language UI hierarchies
- **Accessibility Features**: Test with screen reader and accessibility modes
- **Custom Views**: Test with complex custom UI components

## License and Credits

This test suite is part of the AutoApp UI Map & Intelligent Flow Engine project. See the main project license for usage terms.

**Test Architecture**: Based on industry best practices for state management and deduplication testing
**Sample Data**: MaynDrive UI hierarchies used with permission for testing purposes
**Performance Targets**: Aligned with real-time UI capture requirements for mobile automation