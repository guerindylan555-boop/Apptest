#!/usr/bin/env node

/**
 * Comprehensive UI Element Discovery System for MaynDrive
 *
 * This script analyzes UI dumps and decompiled code to create a comprehensive
 * map of all UI elements, their properties, and interaction patterns.
 */

const fs = require('fs');
const path = require('path');

class UIElementDiscovery {
    constructor() {
        this.uiElements = new Map();
        this.screenStates = new Map();
        this.interactionPatterns = new Map();
        this.elementHierarchy = new Map();
    }

    /**
     * Parse UI dump XML and extract all elements
     */
    parseUIDump(xmlContent, dumpName) {
        const elements = [];

        // Extract nodes from XML hierarchy
        const nodeRegex = /<node[^>]*>(.*?)<\/node>/gs;
        let match;

        while ((match = nodeRegex.exec(xmlContent)) !== null) {
            const nodeXml = match[0];
            const element = this.parseNode(nodeXml);
            if (element) {
                elements.push(element);
                this.uiElements.set(element.id || element.signature, element);
            }
        }

        // Store screen state
        this.screenStates.set(dumpName, {
            elements: elements,
            timestamp: new Date().toISOString(),
            totalElements: elements.length
        });

        return elements;
    }

    /**
     * Parse individual UI node
     */
    parseNode(nodeXml) {
        const attributes = this.extractAttributes(nodeXml);

        if (!attributes.bounds) return null;

        const bounds = this.parseBounds(attributes.bounds);
        const element = {
            signature: this.generateSignature(attributes),
            id: attributes['resource-id'] || null,
            text: attributes.text || null,
            contentDesc: attributes['content-desc'] || null,
            class: attributes.class || null,
            package: attributes.package || null,
            clickable: attributes.clickable === 'true',
            enabled: attributes.enabled === 'true',
            focusable: attributes.focusable === 'true',
            focused: attributes.focused === 'true',
            scrollable: attributes.scrollable === 'true',
            longClickable: attributes['long-clickable'] === 'true',
            password: attributes.password === 'true',
            selected: attributes.selected === 'true',
            bounds: bounds,
            centerPoint: this.calculateCenter(bounds),
            xpath: this.generateXPath(attributes),
            confidence: this.calculateConfidence(attributes),
            interactionType: this.determineInteractionType(attributes),
            parent: null,
            children: []
        };

        return element;
    }

    /**
     * Extract all attributes from node XML
     */
    extractAttributes(nodeXml) {
        const attrRegex = /(\w+(?:-\w+)*)="([^"]*)"/g;
        const attributes = {};
        let match;

        while ((match = attrRegex.exec(nodeXml)) !== null) {
            attributes[match[1]] = match[2];
        }

        return attributes;
    }

    /**
     * Parse bounds string "[x1,y1][x2,y2]"
     */
    parseBounds(boundsStr) {
        const match = boundsStr.match(/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/);
        if (match) {
            return {
                left: parseInt(match[1]),
                top: parseInt(match[2]),
                right: parseInt(match[3]),
                bottom: parseInt(match[4]),
                width: parseInt(match[3]) - parseInt(match[1]),
                height: parseInt(match[4]) - parseInt(match[2])
            };
        }
        return null;
    }

    /**
     * Calculate center point of bounds
     */
    calculateCenter(bounds) {
        if (!bounds) return null;
        return {
            x: Math.floor((bounds.left + bounds.right) / 2),
            y: Math.floor((bounds.top + bounds.bottom) / 2)
        };
    }

    /**
     * Generate unique signature for element
     */
    generateSignature(attributes) {
        const parts = [
            attributes.class || 'unknown',
            attributes.text || '',
            attributes['content-desc'] || '',
            attributes['resource-id'] || ''
        ];
        return parts.join('|').replace(/[^\w|]/g, '_');
    }

    /**
     * Generate XPath for element
     */
    generateXPath(attributes) {
        const parts = [];

        if (attributes.class) {
            parts.push(`@class='${attributes.class}'`);
        }
        if (attributes.text) {
            parts.push(`@text='${attributes.text}'`);
        }
        if (attributes['content-desc']) {
            parts.push(`@content-desc='${attributes['content-desc']}'`);
        }
        if (attributes['resource-id']) {
            parts.push(`@resource-id='${attributes['resource-id']}'`);
        }

        return `//node[${parts.join(' and ')}]`;
    }

    /**
     * Calculate confidence score for element identification
     */
    calculateConfidence(attributes) {
        let confidence = 0;

        // Text provides high confidence
        if (attributes.text && attributes.text.length > 0) confidence += 40;

        // Resource ID provides high confidence
        if (attributes['resource-id'] && attributes['resource-id'].length > 0) confidence += 35;

        // Content description provides medium confidence
        if (attributes['content-desc'] && attributes['content-desc'].length > 0) confidence += 20;

        // Clickable elements are more important
        if (attributes.clickable === 'true') confidence += 5;

        return Math.min(confidence, 100);
    }

    /**
     * Determine interaction type for element
     */
    determineInteractionType(attributes) {
        if (attributes.clickable === 'true') {
            if (attributes.class && attributes.class.includes('EditText')) {
                return 'INPUT';
            } else if (attributes.text && (
                attributes.text.includes('Login') ||
                attributes.text.includes('Signup') ||
                attributes.text.includes('Start') ||
                attributes.text.includes('Lock') ||
                attributes.text.includes('Unlock') ||
                attributes.text.includes('Ride')
            )) {
                return 'ACTION_BUTTON';
            } else {
                return 'CLICKABLE';
            }
        } else if (attributes.scrollable === 'true') {
            return 'SCROLLABLE';
        } else if (attributes.class && attributes.class.includes('EditText')) {
            return 'INPUT';
        } else if (attributes.text && attributes.text.length > 0) {
            return 'TEXT_LABEL';
        }

        return 'STATIC';
    }

    /**
     * Analyze all UI dumps in directory
     */
    analyzeUIDumps(dumpDirectory) {
        const dumpFiles = fs.readdirSync(dumpDirectory)
            .filter(file => file.endsWith('.xml'));

        console.log(`[discovery] Found ${dumpFiles.length} UI dump files`);

        for (const dumpFile of dumpFiles) {
            const filePath = path.join(dumpDirectory, dumpFile);
            const content = fs.readFileSync(filePath, 'utf8');

            console.log(`[discovery] Processing ${dumpFile}...`);
            this.parseUIDump(content, dumpFile);
        }

        this.buildElementHierarchy();
        this.identifyInteractionPatterns();

        return this.generateReport();
    }

    /**
     * Build element hierarchy based on bounds
     */
    buildElementHierarchy() {
        for (const [screenName, screenData] of this.screenStates) {
            const elements = screenData.elements;

            for (let i = 0; i < elements.length; i++) {
                const element = elements[i];

                // Find parent (containing element)
                for (let j = 0; j < elements.length; j++) {
                    if (i !== j && this.isContainedIn(element, elements[j])) {
                        element.parent = elements[j].signature;
                        elements[j].children.push(element.signature);
                        break;
                    }
                }
            }
        }
    }

    /**
     * Check if elementA is contained within elementB
     */
    isContainedIn(elementA, elementB) {
        const a = elementA.bounds;
        const b = elementB.bounds;

        return a.left >= b.left &&
               a.top >= b.top &&
               a.right <= b.right &&
               a.bottom <= b.bottom &&
               a.width < b.width &&
               a.height < b.height;
    }

    /**
     * Identify common interaction patterns across screens
     */
    identifyInteractionPatterns() {
        // Group elements by interaction type and text patterns
        const groups = new Map();

        for (const [signature, element] of this.uiElements) {
            const key = `${element.interactionType}|${element.text || ''}`;

            if (!groups.has(key)) {
                groups.set(key, []);
            }
            groups.get(key).push(element);
        }

        // Identify patterns
        for (const [key, elements] of groups) {
            if (elements.length > 1) {
                const pattern = {
                    type: key.split('|')[0],
                    text: key.split('|')[1],
                    occurrences: elements.length,
                    variance: this.calculatePositionVariance(elements),
                    averageBounds: this.calculateAverageBounds(elements)
                };

                this.interactionPatterns.set(key, pattern);
            }
        }
    }

    /**
     * Calculate position variance for similar elements
     */
    calculatePositionVariance(elements) {
        if (elements.length < 2) return 0;

        const centers = elements.map(e => e.centerPoint);
        const avgX = centers.reduce((sum, c) => sum + c.x, 0) / centers.length;
        const avgY = centers.reduce((sum, c) => sum + c.y, 0) / centers.length;

        const variance = centers.reduce((sum, c) => {
            return sum + Math.sqrt(Math.pow(c.x - avgX, 2) + Math.pow(c.y - avgY, 2));
        }, 0) / centers.length;

        return Math.round(variance);
    }

    /**
     * Calculate average bounds for similar elements
     */
    calculateAverageBounds(elements) {
        if (elements.length === 0) return null;

        const avgBounds = {
            left: Math.round(elements.reduce((sum, e) => sum + e.bounds.left, 0) / elements.length),
            top: Math.round(elements.reduce((sum, e) => sum + e.bounds.top, 0) / elements.length),
            right: Math.round(elements.reduce((sum, e) => sum + e.bounds.right, 0) / elements.length),
            bottom: Math.round(elements.reduce((sum, e) => sum + e.bounds.bottom, 0) / elements.length)
        };

        avgBounds.width = avgBounds.right - avgBounds.left;
        avgBounds.height = avgBounds.bottom - avgBounds.top;
        avgBounds.center = this.calculateCenter(avgBounds);

        return avgBounds;
    }

    /**
     * Generate comprehensive discovery report
     */
    generateReport() {
        const report = {
            summary: {
                totalElements: this.uiElements.size,
                totalScreens: this.screenStates.size,
                interactionPatterns: this.interactionPatterns.size,
                generatedAt: new Date().toISOString()
            },
            elementsByType: this.groupElementsByType(),
            highConfidenceElements: this.getHighConfidenceElements(),
            interactionPatterns: Object.fromEntries(this.interactionPatterns),
            screenStates: Object.fromEntries(this.screenStates),
            actionableElements: this.getActionableElements(),
            recommendations: this.generateRecommendations()
        };

        return report;
    }

    /**
     * Group elements by interaction type
     */
    groupElementsByType() {
        const groups = {};

        for (const element of this.uiElements.values()) {
            if (!groups[element.interactionType]) {
                groups[element.interactionType] = [];
            }
            groups[element.interactionType].push(element);
        }

        // Add counts
        for (const type in groups) {
            groups[type] = {
                count: groups[type].length,
                elements: groups[type].map(e => ({
                    signature: e.signature,
                    text: e.text,
                    confidence: e.confidence,
                    centerPoint: e.centerPoint
                }))
            };
        }

        return groups;
    }

    /**
     * Get elements with high confidence scores
     */
    getHighConfidenceElements() {
        const highConfidence = [];

        for (const element of this.uiElements.values()) {
            if (element.confidence >= 70) {
                highConfidence.push({
                    signature: element.signature,
                    text: element.text,
                    contentDesc: element.contentDesc,
                    resourceId: element.id,
                    confidence: element.confidence,
                    interactionType: element.interactionType,
                    centerPoint: element.centerPoint,
                    xpath: element.xpath
                });
            }
        }

        return highConfidence.sort((a, b) => b.confidence - a.confidence);
    }

    /**
     * Get actionable elements (buttons, inputs, etc.)
     */
    getActionableElements() {
        const actionable = [];

        for (const element of this.uiElements.values()) {
            if (element.clickable || element.interactionType === 'INPUT') {
                actionable.push({
                    signature: element.signature,
                    text: element.text,
                    contentDesc: element.contentDesc,
                    resourceId: element.id,
                    interactionType: element.interactionType,
                    confidence: element.confidence,
                    centerPoint: element.centerPoint,
                    xpath: element.xpath,
                    bounds: element.bounds
                });
            }
        }

        return actionable.sort((a, b) => b.confidence - a.confidence);
    }

    /**
     * Generate automation recommendations
     */
    generateRecommendations() {
        const recommendations = [];

        // Analyze high-confidence elements
        const highConfElements = this.getHighConfidenceElements();
        if (highConfElements.length > 0) {
            recommendations.push({
                priority: 'HIGH',
                type: 'ELEMENT_TARGETING',
                description: `Found ${highConfElements.length} high-confidence elements suitable for reliable targeting`,
                elements: highConfElements.slice(0, 10).map(e => e.text || e.signature)
            });
        }

        // Analyze interaction patterns
        const stablePatterns = Array.from(this.interactionPatterns.values())
            .filter(p => p.variance < 50);

        if (stablePatterns.length > 0) {
            recommendations.push({
                priority: 'HIGH',
                type: 'STABLE_PATTERNS',
                description: `Found ${stablePatterns.length} stable interaction patterns with low position variance`,
                patterns: stablePatterns.slice(0, 5)
            });
        }

        // Check for text-based targeting opportunities
        const textElements = Array.from(this.uiElements.values())
            .filter(e => e.text && e.text.length > 0 && e.clickable);

        if (textElements.length > 0) {
            recommendations.push({
                priority: 'MEDIUM',
                type: 'TEXT_BASED_TARGETING',
                description: `${textElements.length} clickable elements have text that can be used for reliable targeting`,
                examples: textElements.slice(0, 8).map(e => e.text)
            });
        }

        // Check for resource ID opportunities
        const resourceIdElements = Array.from(this.uiElements.values())
            .filter(e => e.id && e.id.length > 0);

        if (resourceIdElements.length > 0) {
            recommendations.push({
                priority: 'MEDIUM',
                type: 'RESOURCE_ID_TARGETING',
                description: `${resourceIdElements.length} elements have resource IDs for precise targeting`,
                examples: resourceIdElements.slice(0, 8).map(e => e.id)
            });
        }

        return recommendations;
    }

    /**
     * Export discovery data to JSON file
     */
    exportToFile(filePath) {
        const report = this.generateReport();
        fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
        console.log(`[discovery] Report exported to ${filePath}`);
        return report;
    }
}

// CLI interface
if (require.main === module) {
    const args = process.argv.slice(2);

    if (args.length < 1) {
        console.log('Usage: node ui_element_discovery.js <ui_dump_directory> [output_file.json]');
        process.exit(1);
    }

    const dumpDir = args[0];
    const outputFile = args[1] || 'ui_discovery_report.json';

    if (!fs.existsSync(dumpDir)) {
        console.error(`Error: Directory ${dumpDir} does not exist`);
        process.exit(1);
    }

    console.log('[discovery] Starting UI element discovery...');

    const discovery = new UIElementDiscovery();
    const report = discovery.analyzeUIDumps(dumpDir);
    discovery.exportToFile(outputFile);

    console.log('\n=== DISCOVERY SUMMARY ===');
    console.log(`Total Elements: ${report.summary.totalElements}`);
    console.log(`Total Screens: ${report.summary.totalScreens}`);
    console.log(`High Confidence Elements: ${report.highConfidenceElements.length}`);
    console.log(`Actionable Elements: ${report.actionableElements.length}`);
    console.log(`Interaction Patterns: ${report.interactionPatterns.length}`);

    console.log('\n=== TOP RECOMMENDATIONS ===');
    report.recommendations.slice(0, 3).forEach((rec, i) => {
        console.log(`${i + 1}. [${rec.priority}] ${rec.type}: ${rec.description}`);
    });

    console.log(`\n[discovery] Complete! Full report saved to ${outputFile}`);
}

module.exports = UIElementDiscovery;