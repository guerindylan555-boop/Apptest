# MaynDrive UI Flows Contributor Guide

This directory contains declarative flow definitions for MaynDrive UI automation. Flows are authored in YAML format and designed to be both human-readable and LLM-editable.

## Naming Rules

- Use **kebab-case** for flow filenames (e.g., `login-home.yaml`, `unlock-scooter.yaml`)
- Keep names descriptive but concise (max 50 characters)
- Prefix flows with action type when helpful: `capture-`, `unlock-`, `login-`, `logout-`
- Use semantic versioning for flow versions

## Safe Actions for LLM Editing

When contributing flows, follow these safety guidelines:

### ✅ Safe to Edit
- Flow metadata (`name`, `description`, `notes`)
- Variable definitions and prompts
- Step ordering and retry policies
- Recovery rule configurations
- Precondition/postcondition queries

### ⚠️ Edit with Caution
- Selector references (verify they still exist)
- Node IDs (must match captured nodes)
- Action parameters (test before committing)
- Guard conditions (validate logic)

### ❌ Never Edit
- Checksum fields
- System-generated timestamps
- File path references
- Core schema structure

## Flow Structure Reference

Each flow must contain:
- `name`: kebab-case identifier
- `description`: 1-2 sentence summary
- `variables[]`: Input parameters with types and prompts
- `precondition`: Starting state requirements
- `steps[]`: Ordered actions (edgeRef or inline)
- `postcondition`: Final state verification
- `recovery[]`: Failure handling rules

## Authoring Workflow

1. **Copy template**: `cp templates/flow-example.yaml your-flow.yaml`
2. **Define variables**: List all inputs needed (phone, OTP, etc.)
3. **Set precondition**: Identify starting node or state
4. **Author steps**: Reference existing edges or define inline actions
5. **Add recovery**: Cover unexpected_node, system_dialog, timeout
6. **Validate**: Run `npm run flows:lint -- your-flow.yaml`
7. **Test**: Execute flow and verify success criteria

## Node ID Guidelines

- Use the 16-character hex hash from captured nodes
- Document new node IDs in comments when first used
- Verify node IDs exist in `var/graphs/*/ui-graph.json`
- Update edge references when nodes are deprecated

## Selector Best Practices

- Prefer `resource-id` selectors (most stable)
- Use `content-desc` as secondary option
- Fall back to `text` only when necessary
- Avoid coordinates unless absolutely required
- Document brittle selectors in flow `notes`

## Recovery Strategy

Every flow must handle these scenarios:
- **unexpected_node**: Wrong screen after action
- **system_dialog**: Popups, notifications, permissions
- **timeout**: Action takes too long

Recovery actions should be ordered from least to most disruptive.

## Validation Commands

```bash
# Validate flow syntax and references
npm run flows:lint -- var/flows/your-flow.yaml

# Test flow execution
npm run flows:run -- --flow var/flows/your-flow.yaml

# List all available flows
npm run flows:list

# Check flow references against current graph
npm run flows:check-refs
```

## Contributing Tips

- **Start small**: Build flows with 2-3 steps first
- **Test incrementally**: Validate each step works
- **Document assumptions**: Note device-specific behavior
- **Keep flows idempotent**: Multiple runs should have same result
- **Monitor success rates**: Update recovery rules based on execution data

## Artifact Management

- Keep flows under 1MB (avoid embedding large data)
- Use external files for complex datasets
- Reference screenshots by relative path: `var/captures/nodeId/screenshot.png`
- Update README when adding new flow categories

## LLM Collaboration

This guide is designed to help both human operators and AI assistants contribute flows. When using AI assistance:

1. Provide current node IDs and available edges
2. Share recent detection results for context
3. Include success criteria and constraints
4. Review generated flows before execution
5. Test in safe environment before production use

For questions or issues, refer to the main project documentation or contact the automation team.