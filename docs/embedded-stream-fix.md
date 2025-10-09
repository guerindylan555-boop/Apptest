# Embedded Stream Fix - Full Container Rendering

## Problem
The Android emulator stream was rendering in the top-right corner of the grey container instead of filling it edge-to-edge.

## Root Cause
The issue was caused by **inline styles** set by `BasePlayer.setScreenInfo()` on the `.video` element:

```typescript
// BasePlayer.ts line 389-390 (OLD)
if (this.parentElement) {
    this.parentElement.style.height = `${height}px`;  // Inline style!
    this.parentElement.style.width = `${width}px`;    // Inline style!
}
```

Inline styles have higher CSS specificity than class selectors, so even with `!important` flags, our embedded CSS couldn't override these pixel-based dimensions.

## Solution
Modified `BasePlayer.setScreenInfo()` to skip setting inline styles when in embedded mode:

```typescript
// BasePlayer.ts line 388-393 (NEW)
// Skip setting inline styles in embedded mode to allow CSS to take control
const isEmbedded = document.body.classList.contains('embedded');
if (this.parentElement && !isEmbedded) {
    this.parentElement.style.height = `${height}px`;
    this.parentElement.style.width = `${width}px`;
}
```

## Complete Embedded Mode Implementation

### 1. Hash Parameter Detection (index.ts)
```typescript
// Executes IMMEDIATELY on page load (before window.onload)
const hash = location.hash.replace(/^#!/, '');
const parsedQuery = new URLSearchParams(hash);
const isEmbedded = parsedQuery.get('embedded') === '1';
if (isEmbedded) {
    document.body.classList.add('embedded');
}
```

### 2. Device View Class Addition (StreamClientScrcpy.ts)
```typescript
const deviceView = document.createElement('div');
deviceView.className = 'device-view';
if (document.body.classList.contains('embedded')) {
    deviceView.classList.add('embedded-view');
}
```

### 3. Inline Style Prevention (BasePlayer.ts)
```typescript
// In setScreenInfo() method
const isEmbedded = document.body.classList.contains('embedded');
if (this.parentElement && !isEmbedded) {
    // Only set inline styles in non-embedded mode
    this.parentElement.style.height = `${height}px`;
    this.parentElement.style.width = `${width}px`;
}
```

### 4. CSS Overrides (app.css)
```css
/* MUST be at END of file for proper cascade */
body.embedded .device-view.embedded-view {
    float: none !important;
    position: absolute !important;
    inset: 0 !important;
    width: 100% !important;
    height: 100% !important;
    /* ... more overrides ... */
}

body.embedded .device-view.embedded-view .video {
    float: none !important;
    position: absolute !important;
    width: 100% !important;
    height: 100% !important;
    max-width: none !important;
    max-height: none !important;
    /* ... */
}

/* Target ALL player types */
body.embedded .device-view.embedded-view .screen,
body.embedded .device-view.embedded-view canvas,
body.embedded .device-view.embedded-view video,
body.embedded .device-view.embedded-view .webgl,
body.embedded .device-view.embedded-view .bitmap {
    width: 100% !important;
    height: 100% !important;
    object-fit: contain !important;
    /* ... */
}
```

## Why Each Part is Critical

1. **index.ts (top-level execution)**: Ensures `body.embedded` class is added BEFORE any components initialize
2. **StreamClientScrcpy.ts**: Adds `embedded-view` class for high-specificity CSS targeting
3. **BasePlayer.ts**: **KEY FIX** - Prevents inline styles that would override CSS
4. **app.css (at end)**: Ensures embedded rules override base rules in the cascade

## CSS Specificity Hierarchy
1. **Inline styles** (highest) - `style="width: 100px"` - NOW REMOVED in embedded mode!
2. **!important flags** - Used in our embedded CSS
3. **ID selectors** - Not used
4. **Class selectors** - `body.embedded .device-view.embedded-view` (high specificity)
5. **Element selectors** - Base `.device-view` rules

## Files Modified
- `ws-scrcpy/src/app/index.ts` - Immediate embedded detection
- `ws-scrcpy/src/app/googDevice/client/StreamClientScrcpy.ts` - Add embedded-view class
- `ws-scrcpy/src/app/player/BasePlayer.ts` - **Skip inline styles in embedded mode**
- `ws-scrcpy/src/style/app.css` - Comprehensive embedded overrides (at end of file)
- `scripts/ws-scrcpy-embedded.patch` - Updated to include all changes

## Testing
1. Frontend: http://127.0.0.1:8080
2. Verify stream renders edge-to-edge in grey container
3. Check browser console for:
   - `[ws-scrcpy] Embedded mode check: { hash: '...', isEmbedded: true }`
   - `[ws-scrcpy] Added embedded class to body`
   - `[StreamClientScrcpy] Body has embedded class: true`
   - `[StreamClientScrcpy] Added embedded-view class to device-view`
4. Inspect `.video` element - should have NO inline width/height styles
5. Computed styles should show width/height as 100%

## Build & Deploy
```bash
cd ws-scrcpy
npm run dist
cd ..
bash scripts/run-everything.sh
```
