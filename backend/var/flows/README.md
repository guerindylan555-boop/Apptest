# MaynDrive Flows

This directory contains YAML flow definitions for automating MaynDrive interactions.

## Structure

Each flow is defined in a separate YAML file with the following structure:

```yaml
name: example-flow
description: "Example flow for demonstrating the format"
version: "1.0.0"

variables:
  - name: phone
    description: "User phone number"
    type: string
    required: true
    prompt: "Enter phone number"

precondition:
  nodeId: "login-screen"  # or query with activity/texts

steps:
  - kind: edgeRef
    edgeId: "login-screen-enter-phone"
  - kind: inline
    inlineAction:
      action: type
      text: "{{phone}}"

postcondition:
  nodeId: "home-screen"

recovery:
  - trigger: unexpected_node
    allowedActions: [back, reopen]
  - trigger: system_dialog
    allowedActions: [dismiss]
  - trigger: timeout
    allowedActions: [retry, back]

metadata:
  owner: "operator-name"
  lastUpdatedAt: "2025-10-25T10:00:00Z"
  validationStatus: "validated"
```

## Naming Conventions

- Flow names should use kebab-case (e.g., `login-home`)
- File names should match the flow name with .yaml extension
- Use descriptive names that indicate the start and end states

## Validation

Flows are automatically validated when loaded. Use the CLI tool to validate flows:

```bash
scripts/flows/lint-flow.ts <flow-name>
```

## Best Practices

1. Keep flows focused on a single user journey
2. Use meaningful variable names and descriptions
3. Include recovery rules for common failure scenarios
4. Test flows in a safe environment before production use
5. Update validation status when flows are ready for production
