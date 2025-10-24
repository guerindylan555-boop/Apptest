#!/usr/bin/env python3
"""
State signature and deduplication for endless UI discovery.
Generates canonical signatures from UI hierarchy to detect duplicate states.
"""

import hashlib
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple, Optional, Set
import imagehash
from PIL import Image
import logging

logger = logging.getLogger(__name__)


class StateSignature:
    """Generates and compares canonical signatures for UI states"""

    def __init__(self, similarity_threshold: float = 0.85):
        """
        Args:
            similarity_threshold: 0-1, how similar states must be to be considered duplicates
        """
        self.similarity_threshold = similarity_threshold

    def compute_signature(self, xml_path: str, screenshot_path: Optional[str] = None,
                         package: str = "", activity: str = "") -> Dict:
        """
        Compute canonical signature from UI dump

        Returns:
            dict with: hash, structural_features, visual_hash, texts, controls
        """
        try:
            # Parse XML
            tree = ET.parse(xml_path)
            root = tree.getroot()

            # Extract structural features
            texts = self._extract_texts(root)
            controls = self._extract_controls(root)
            layout = self._extract_layout(root)

            # Build structural signature
            structural_data = {
                "package": package,
                "activity": activity,
                "texts_norm": self._normalize_texts(texts),
                "controls": controls,
                "layout_signature": layout
            }

            # Hash the structural data
            struct_hash = self._hash_dict(structural_data)

            # Compute visual hash if screenshot provided
            visual_hash = None
            if screenshot_path:
                try:
                    visual_hash = self._compute_visual_hash(screenshot_path)
                except Exception as e:
                    logger.warning(f"Failed to compute visual hash: {e}")

            return {
                "hash": struct_hash,
                "structural_features": structural_data,
                "visual_hash": visual_hash,
                "texts": texts[:50],  # Keep first 50 for summary
                "controls": controls[:30],  # Keep first 30 controls
                "layout_signature": layout
            }

        except Exception as e:
            logger.error(f"Failed to compute signature: {e}")
            return {
                "hash": "error",
                "structural_features": {},
                "visual_hash": None,
                "texts": [],
                "controls": [],
                "layout_signature": ""
            }

    def _extract_texts(self, node: ET.Element) -> List[str]:
        """Extract all visible text from UI hierarchy"""
        texts = []

        def traverse(elem):
            # Get text attribute
            text = elem.get("text", "")
            content_desc = elem.get("content-desc", "")

            # Add non-empty texts
            if text and text.strip():
                texts.append(text.strip())
            if content_desc and content_desc.strip():
                texts.append(content_desc.strip())

            # Recurse
            for child in elem:
                traverse(child)

        traverse(node)
        return texts

    def _extract_controls(self, node: ET.Element) -> List[Dict]:
        """Extract clickable/interactive elements with their properties"""
        controls = []

        def traverse(elem):
            clickable = elem.get("clickable", "false") == "true"
            focusable = elem.get("focusable", "false") == "true"

            if clickable or focusable:
                control = {
                    "class": elem.get("class", ""),
                    "resource-id": elem.get("resource-id", ""),
                    "text": elem.get("text", ""),
                    "content-desc": elem.get("content-desc", ""),
                    "clickable": clickable,
                    "bounds": elem.get("bounds", "")
                }
                controls.append(control)

            # Recurse
            for child in elem:
                traverse(child)

        traverse(node)
        return controls

    def _extract_layout(self, node: ET.Element) -> str:
        """Extract coarse layout structure (quantized bounds + classes)"""
        layout_parts = []

        def traverse(elem, depth=0):
            if depth > 6:  # Limit depth
                return

            cls = elem.get("class", "").split(".")[-1]  # Short class name
            bounds = elem.get("bounds", "")

            if bounds:
                # Quantize bounds to reduce noise
                quantized = self._quantize_bounds(bounds)
                layout_parts.append(f"{cls}@{quantized}")

            for child in elem:
                traverse(child, depth + 1)

        traverse(node)
        return "|".join(layout_parts[:100])  # Limit length

    def _normalize_texts(self, texts: List[str]) -> List[str]:
        """Normalize texts for comparison (lowercase, mask numbers)"""
        normalized = []
        for text in texts:
            # Lowercase
            norm = text.lower()
            # Mask numbers
            norm = re.sub(r'\d+', '#', norm)
            # Remove extra whitespace
            norm = ' '.join(norm.split())
            if norm:
                normalized.append(norm)
        return sorted(set(normalized))  # Unique, sorted

    def _quantize_bounds(self, bounds_str: str, grid_size: int = 100) -> str:
        """Quantize bounds to grid for layout comparison"""
        try:
            # Parse bounds like "[0,0][1080,1920]"
            match = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
            if not match:
                return "0,0,0,0"

            x1, y1, x2, y2 = map(int, match.groups())

            # Quantize to grid
            qx1 = (x1 // grid_size) * grid_size
            qy1 = (y1 // grid_size) * grid_size
            qx2 = (x2 // grid_size) * grid_size
            qy2 = (y2 // grid_size) * grid_size

            return f"{qx1},{qy1},{qx2},{qy2}"
        except Exception:
            return "0,0,0,0"

    def _hash_dict(self, data: Dict) -> str:
        """Create stable hash from dictionary"""
        # Convert to sorted JSON-like string
        import json
        json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(json_str.encode()).hexdigest()[:16]

    def _compute_visual_hash(self, screenshot_path: str) -> str:
        """Compute perceptual hash of screenshot"""
        try:
            img = Image.open(screenshot_path)
            # Use perceptual hash (robust to minor changes)
            phash = imagehash.phash(img, hash_size=8)
            return str(phash)
        except Exception as e:
            logger.warning(f"Visual hash failed: {e}")
            return None

    def are_similar(self, sig1: Dict, sig2: Dict) -> Tuple[bool, float]:
        """
        Check if two signatures represent similar states

        Returns:
            (is_similar, similarity_score)
        """
        # Exact match on structural hash
        if sig1["hash"] == sig2["hash"]:
            return True, 1.0

        # Compare structural features
        struct_sim = self._structural_similarity(
            sig1["structural_features"],
            sig2["structural_features"]
        )

        # Compare visual hashes if available
        visual_sim = 0.5  # Neutral default
        if sig1.get("visual_hash") and sig2.get("visual_hash"):
            visual_sim = self._visual_similarity(
                sig1["visual_hash"],
                sig2["visual_hash"]
            )

        # Weighted combination
        combined = struct_sim * 0.7 + visual_sim * 0.3
        is_similar = combined >= self.similarity_threshold

        return is_similar, combined

    def _structural_similarity(self, feat1: Dict, feat2: Dict) -> float:
        """Compare structural features"""
        # Package/activity must match
        if feat1.get("package") != feat2.get("package"):
            return 0.0

        if feat1.get("activity") and feat2.get("activity"):
            if feat1["activity"] != feat2["activity"]:
                return 0.3  # Different activity, but same package

        # Compare normalized texts (Jaccard similarity)
        texts1 = set(feat1.get("texts_norm", []))
        texts2 = set(feat2.get("texts_norm", []))

        if not texts1 and not texts2:
            text_sim = 1.0
        elif not texts1 or not texts2:
            text_sim = 0.0
        else:
            intersection = len(texts1 & texts2)
            union = len(texts1 | texts2)
            text_sim = intersection / union if union > 0 else 0.0

        # Compare controls (resource IDs)
        controls1 = [c.get("resource-id", "") for c in feat1.get("controls", [])]
        controls2 = [c.get("resource-id", "") for c in feat2.get("controls", [])]

        controls1_set = set(filter(None, controls1))
        controls2_set = set(filter(None, controls2))

        if not controls1_set and not controls2_set:
            control_sim = 1.0
        elif not controls1_set or not controls2_set:
            control_sim = 0.0
        else:
            intersection = len(controls1_set & controls2_set)
            union = len(controls1_set | controls2_set)
            control_sim = intersection / union if union > 0 else 0.0

        # Weighted combination
        return text_sim * 0.6 + control_sim * 0.4

    def _visual_similarity(self, hash1: str, hash2: str) -> float:
        """Compare perceptual hashes"""
        try:
            h1 = imagehash.hex_to_hash(hash1)
            h2 = imagehash.hex_to_hash(hash2)

            # Hamming distance (lower = more similar)
            distance = h1 - h2
            max_distance = len(hash1) * 4  # Max possible Hamming distance for hex

            # Convert to similarity (0-1)
            similarity = 1.0 - (distance / max_distance)
            return max(0.0, min(1.0, similarity))
        except Exception as e:
            logger.warning(f"Visual similarity comparison failed: {e}")
            return 0.5  # Neutral


def get_current_activity(device_serial: str = None) -> Tuple[str, str]:
    """
    Get current top activity and package using dumpsys

    Returns:
        (package, activity)
    """
    import subprocess

    try:
        cmd = ["adb"]
        if device_serial:
            cmd.extend(["-s", device_serial])
        cmd.extend(["shell", "dumpsys", "activity", "activities"])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        output = result.stdout

        # Parse for mResumedActivity or mFocusedActivity
        for line in output.split('\n'):
            if 'mResumedActivity' in line or 'mFocusedActivity' in line:
                # Example: mResumedActivity: ActivityRecord{... u0 fr.mayndrive.app/.MainActivity}
                match = re.search(r'(\S+)/(\S+)', line)
                if match:
                    package = match.group(1)
                    activity = match.group(2).lstrip('.')
                    return package, activity

        return "", ""
    except Exception as e:
        logger.warning(f"Failed to get current activity: {e}")
        return "", ""
