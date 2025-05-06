#!/usr/bin/env python3
"""
BIN Attack Detection System

A prototype for detecting coordinated enumeration attacks targeting bank BINs.
This system uses probabilistic data structures for memory-efficient detection:
- Bloom filters to check if IPs have been seen before
- Count-Min Sketch to estimate BIN access frequency
- MinHash sketches to compare IP sets across different BINs

Author: Claude 3.7 Sonnet
Date: May 5, 2025
"""

import random
import time
import hashlib
import ipaddress
import argparse
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional
import json
import sys
from datetime import datetime

# ---------------------
# Probabilistic Data Structures
# ---------------------

class BloomFilter:
    """
    A Bloom filter for memory-efficient set membership testing.
    
    Used to check if an IP has been seen before with a small false positive rate,
    but no false negatives.
    """
    def __init__(self, capacity: int, error_rate: float = 0.01):
        """
        Initialize a Bloom filter with desired capacity and error rate.
        
        Args:
            capacity: Expected number of items to be added
            error_rate: Acceptable false positive rate
        """
        self.capacity = capacity
        self.error_rate = error_rate
        
        # Calculate optimal bit array size and number of hash functions
        self.size = self._get_size(capacity, error_rate)
        self.hash_count = self._get_hash_count(self.size, capacity)
        
        # Initialize bit array
        self.bit_array = [0] * self.size
    
    def _get_size(self, n: int, p: float) -> int:
        """Calculate optimal bit array size."""
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)
    
    def _get_hash_count(self, m: int, n: int) -> int:
        """Calculate optimal number of hash functions."""
        k = (m / n) * math.log(2)
        return int(k)
    
    def _get_hash_values(self, item: str) -> List[int]:
        """Generate multiple hash values for the item."""
        hash_values = []
        for i in range(self.hash_count):
            # Use a combination of item and salt to create different hash functions
            hash_input = f"{item}:{i}".encode()
            hash_value = int(hashlib.md5(hash_input).hexdigest(), 16)
            hash_values.append(hash_value % self.size)
        return hash_values
    
    def add(self, item: str) -> None:
        """Add an item to the Bloom filter."""
        for index in self._get_hash_values(item):
            self.bit_array[index] = 1
    
    def check(self, item: str) -> bool:
        """
        Check if an item might be in the set.
        False positives are possible, but not false negatives.
        """
        for index in self._get_hash_values(item):
            if self.bit_array[index] == 0:
                return False
        return True
    
    def get_stats(self) -> dict:
        """Return statistics about the Bloom filter."""
        bit_count = sum(self.bit_array)
        fill_ratio = bit_count / self.size
        return {
            "size": self.size,
            "hash_count": self.hash_count,
            "filled_bits": bit_count,
            "fill_ratio": fill_ratio,
            "estimated_items": self.estimate_items(fill_ratio)
        }
    
    def estimate_items(self, fill_ratio: float) -> int:
        """Estimate the number of items in the filter based on the fill ratio."""
        if fill_ratio == 1.0:
            return self.capacity  # Completely filled
        if fill_ratio == 0.0:
            return 0  # Empty
        # Estimate using formula: n = -m/k * ln(1 - fill_ratio)
        return int(-self.size / self.hash_count * math.log(1 - fill_ratio))

import math

class CountMinSketch:
    """
    Count-Min Sketch for approximate frequency counting.
    
    Used to estimate how frequently each BIN is accessed without 
    maintaining exact counters for every possible item.
    """
    def __init__(self, width: int = 1000, depth: int = 5):
        """
        Initialize a Count-Min Sketch with specified dimensions.
        
        Args:
            width: Width of the sketch (number of columns)
            depth: Number of hash functions (number of rows)
        """
        self.width = width
        self.depth = depth
        # Initialize 2D array filled with zeros
        self.sketch = [[0 for _ in range(width)] for _ in range(depth)]
        # Track total updates for normalization
        self.total_updates = 0
    
    def update(self, item: str, count: int = 1) -> None:
        """
        Update the sketch by incrementing counters for an item.
        
        Args:
            item: The item to update
            count: Amount to increment (default: 1)
        """
        self.total_updates += count
        for i in range(self.depth):
            # Use different hash functions for each row
            hash_input = f"{item}:{i}".encode()
            index = int(hashlib.md5(hash_input).hexdigest(), 16) % self.width
            self.sketch[i][index] += count
    
    def estimate(self, item: str) -> int:
        """
        Estimate the frequency of an item.
        
        Args:
            item: The item to estimate frequency for
            
        Returns:
            Estimated count (will never underestimate but may overestimate)
        """
        min_count = float('inf')
        for i in range(self.depth):
            hash_input = f"{item}:{i}".encode()
            index = int(hashlib.md5(hash_input).hexdigest(), 16) % self.width
            min_count = min(min_count, self.sketch[i][index])
        return min_count
    
    def relative_frequency(self, item: str) -> float:
        """
        Calculate the relative frequency of an item (0.0 to 1.0).
        
        Args:
            item: The item to check
            
        Returns:
            Relative frequency as a proportion of total updates
        """
        if self.total_updates == 0:
            return 0.0
        return self.estimate(item) / self.total_updates


class MinHash:
    """
    MinHash for efficient Jaccard similarity estimation between sets.
    
    Used to compare the similarity between sets of IPs 
    accessing different BINs.
    """
    def __init__(self, num_hashes: int = 100):
        """
        Initialize a MinHash with a specific number of hash functions.
        
        Args:
            num_hashes: Number of hash functions to use
        """
        self.num_hashes = num_hashes
        self.max_hash = 2**32 - 1
        # Generate random hash functions (a*x + b) mod p
        self.hash_params = [
            (random.randint(1, self.max_hash), random.randint(0, self.max_hash))
            for _ in range(num_hashes)
        ]
        # Initialize signature with "infinity" values
        self.signature = [float('inf')] * num_hashes
    
    def update(self, item: str) -> None:
        """
        Update the MinHash signature with a new item.
        
        Args:
            item: Item to add to the set
        """
        # Convert item to an integer hash
        item_hash = int(hashlib.md5(item.encode()).hexdigest(), 16)
        
        # Apply each hash function and keep the minimum values
        for i, (a, b) in enumerate(self.hash_params):
            # Universal hash function: (a*x + b) mod p
            hash_value = (a * item_hash + b) % self.max_hash
            # Update signature with minimum value
            self.signature[i] = min(self.signature[i], hash_value)
    
    def jaccard_similarity(self, other: 'MinHash') -> float:
        """
        Estimate Jaccard similarity between this MinHash and another.
        
        Args:
            other: Another MinHash instance to compare with
            
        Returns:
            Jaccard similarity (0.0 to 1.0)
        """
        if not isinstance(other, MinHash) or self.num_hashes != other.num_hashes:
            raise ValueError("Can only compare MinHash objects with the same number of hash functions")
        
        # Count the number of identical minimum hash values
        identical = sum(1 for i in range(self.num_hashes) 
                       if self.signature[i] == other.signature[i])
        
        # Similarity is the fraction of identical minimum hash values
        return identical / self.num_hashes
    
    def copy(self) -> 'MinHash':
        """Create a deep copy of this MinHash instance."""
        new_minhash = MinHash(self.num_hashes)
        new_minhash.hash_params = self.hash_params.copy()
        new_minhash.signature = self.signature.copy()
        return new_minhash


# ---------------------
# Core Data Models
# ---------------------

@dataclass
class BINState:
    """Data structure to track the state of a single BIN."""
    bin_id: str
    # Probabilistic data structures for this BIN
    ip_bloom_filter: BloomFilter = field(default_factory=lambda: BloomFilter(10000))
    access_count_sketch: CountMinSketch = field(default_factory=lambda: CountMinSketch())
    ip_minhash: MinHash = field(default_factory=lambda: MinHash())
    # Statistics
    total_access_count: int = 0
    unique_ip_estimate: int = 0
    is_hot: bool = False
    last_update: float = field(default_factory=time.time)
    
    def update(self, ip: str) -> None:
        """
        Update BIN state with a new IP access.
        
        Args:
            ip: The IP address accessing this BIN
        """
        # Update total access count
        self.total_access_count += 1
        
        # Update probabilistic data structures
        self.access_count_sketch.update(ip)
        self.ip_minhash.update(ip)
        
        # Check if this is a new IP (might have false positives)
        if not self.ip_bloom_filter.check(ip):
            self.ip_bloom_filter.add(ip)
            self.unique_ip_estimate += 1
        
        self.last_update = time.time()


@dataclass
class Alert:
    """Model for alerts generated by the system."""
    timestamp: float
    alert_type: str
    severity: str  # 'low', 'medium', 'high'
    bin_ids: List[str]
    details: dict
    
    def to_dict(self) -> dict:
        """Convert alert to dictionary for serialization."""
        return {
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "alert_type": self.alert_type,
            "severity": self.severity,
            "bin_ids": self.bin_ids,
            "details": self.details
        }


# ---------------------
# BIN Similarity Graph
# ---------------------

class BINGraph:
    """
    Lightweight graph to track BIN similarity relationships.
    Nodes represent BINs, and edges represent Jaccard similarity scores.
    """
    def __init__(self, decay_rate: float = 0.01, similarity_threshold: float = 0.5):
        """
        Initialize the BIN graph.

        Args:
            decay_rate: Rate at which edge weights decay over time.
            similarity_threshold: Minimum similarity score to maintain an edge.
        """
        self.graph: Dict[str, Dict[str, float]] = {}
        self.decay_rate = decay_rate
        self.similarity_threshold = similarity_threshold

    def add_or_update_edge(self, bin1: str, bin2: str, similarity: float) -> None:
        """
        Add or update an edge between two BINs.

        Args:
            bin1: First BIN ID.
            bin2: Second BIN ID.
            similarity: Jaccard similarity score.
        """
        if bin1 == bin2:
            return  # No self-loops

        if bin1 not in self.graph:
            self.graph[bin1] = {}
        if bin2 not in self.graph:
            self.graph[bin2] = {}

        self.graph[bin1][bin2] = similarity
        self.graph[bin2][bin1] = similarity

    def decay_edges(self) -> None:
        """
        Decay edge weights over time and prune edges below the threshold.
        """
        to_remove = []

        for bin1, neighbors in self.graph.items():
            for bin2, weight in neighbors.items():
                # Decay the weight
                new_weight = weight * (1 - self.decay_rate)
                if new_weight < self.similarity_threshold:
                    to_remove.append((bin1, bin2))
                else:
                    self.graph[bin1][bin2] = new_weight

        # Remove edges below the threshold
        for bin1, bin2 in to_remove:
            del self.graph[bin1][bin2]
            if not self.graph[bin1]:
                del self.graph[bin1]

            del self.graph[bin2][bin1]
            if not self.graph[bin2]:
                del self.graph[bin2]

    def get_clusters(self) -> List[Set[str]]:
        """
        Identify clusters of connected BINs.

        Returns:
            List of sets, where each set contains BIN IDs in a cluster.
        """
        visited = set()
        clusters = []

        def dfs(bin_id, cluster):
            visited.add(bin_id)
            cluster.add(bin_id)
            for neighbor in self.graph.get(bin_id, {}):
                if neighbor not in visited:
                    dfs(neighbor, cluster)

        for bin_id in self.graph:
            if bin_id not in visited:
                cluster = set()
                dfs(bin_id, cluster)
                clusters.append(cluster)

        return clusters

# ---------------------
# Detection System
# ---------------------

class BINAttackDetector:
    """
    Main class for detecting coordinated enumeration attacks on BINs.
    
    This class manages the state of multiple BINs, processes incoming
    traffic, and applies detection rules to identify suspicious patterns.
    """
    def __init__(
        self, 
        hot_bin_threshold: float = 0.1,
        similarity_threshold: float = 0.5,
        check_interval: int = 100,
        graph_decay_rate: float = 0.01
    ):
        """
        Initialize the BIN attack detector.
        
        Args:
            hot_bin_threshold: Threshold for marking a BIN as "hot" (proportion of traffic)
            similarity_threshold: Threshold for considering two BINs as having similar IP sets
            check_interval: Number of events to process before running detection rules
            graph_decay_rate: Rate at which edge weights decay over time
        """
        # Configuration
        self.hot_bin_threshold = hot_bin_threshold
        self.similarity_threshold = similarity_threshold
        self.check_interval = check_interval
        
        # State
        self.bin_states: Dict[str, BINState] = {}  # BIN ID -> BINState
        self.events_since_last_check = 0
        self.global_ip_set = set()  # For statistics only
        self.alerts: List[Alert] = []
        
        # Global bloom filter for all IPs seen
        self.global_ip_bloom = BloomFilter(100000)
        
        # Statistics
        self.total_events = 0
        self.start_time = time.time()

        # BIN similarity graph
        self.bin_graph = BINGraph(
            decay_rate=graph_decay_rate, 
            similarity_threshold=similarity_threshold
        )
    
    def process_event(self, bin_id: str, ip: str) -> None:
        """
        Process a single event (an IP accessing a BIN).
        
        Args:
            bin_id: The BIN being accessed
            ip: The IP address accessing the BIN
        """
        # Create BIN state if not exists
        if bin_id not in self.bin_states:
            self.bin_states[bin_id] = BINState(bin_id=bin_id)
        
        # Update BIN state
        self.bin_states[bin_id].update(ip)
        
        # Update global tracking
        self.global_ip_bloom.add(ip)
        self.global_ip_set.add(ip)  # For statistics only
        
        # Increment counters
        self.events_since_last_check += 1
        self.total_events += 1
        
        # Run detection rules if interval reached
        if self.events_since_last_check >= self.check_interval:
            self._run_detection_rules()
            self.events_since_last_check = 0
    
    def _run_detection_rules(self) -> None:
        """Run detection rules to identify potential attacks."""
        # 1. Check for hot BINs
        hot_bins = self._identify_hot_bins()
        
        # 2. Check for similar IP sets across BINs
        similar_bin_pairs = self._identify_similar_bin_pairs()
        
        # 3. Update the BIN similarity graph
        for bin_id1, bin_id2, similarity in similar_bin_pairs:
            self.bin_graph.add_or_update_edge(bin_id1, bin_id2, similarity)

        # Decay edges in the graph
        self.bin_graph.decay_edges()

        # 4. Generate alerts based on findings
        self._generate_alerts(hot_bins, similar_bin_pairs)

        # 5. Apply graph-based rules
        self._apply_graph_rules()
    
    def _identify_hot_bins(self) -> List[str]:
        """
        Identify BINs with unusually high activity.
        
        Returns:
            List of hot BIN IDs
        """
        hot_bins = []
        
        # Skip if we have no or only one BIN
        if len(self.bin_states) <= 1:
            return hot_bins
        
        # Calculate total accesses across all BINs
        total_accesses = sum(state.total_access_count for state in self.bin_states.values())
        
        # Exit early if no accesses
        if total_accesses == 0:
            return hot_bins
        
        for bin_id, state in self.bin_states.items():
            # Calculate what percentage of all traffic this BIN receives
            bin_percentage = state.total_access_count / total_accesses
            
            # Check if above threshold
            if bin_percentage > self.hot_bin_threshold:
                state.is_hot = True
                hot_bins.append(bin_id)
            else:
                state.is_hot = False
        
        return hot_bins
    
    def _identify_similar_bin_pairs(self) -> List[Tuple[str, str, float]]:
        """
        Identify pairs of BINs with similar IP access patterns.
        
        Returns:
            List of tuples (bin_id1, bin_id2, similarity)
        """
        similar_pairs = []
        
        # Get list of BIN IDs
        bin_ids = list(self.bin_states.keys())
        
        # Compare each pair of BINs
        for i in range(len(bin_ids)):
            for j in range(i + 1, len(bin_ids)):
                bin_id1 = bin_ids[i]
                bin_id2 = bin_ids[j]
                
                # Get MinHash signatures
                minhash1 = self.bin_states[bin_id1].ip_minhash
                minhash2 = self.bin_states[bin_id2].ip_minhash
                
                # Calculate Jaccard similarity
                similarity = minhash1.jaccard_similarity(minhash2)
                
                # Check if above threshold
                if similarity >= self.similarity_threshold:
                    similar_pairs.append((bin_id1, bin_id2, similarity))
        
        return similar_pairs
    
    def _generate_alerts(
        self, 
        hot_bins: List[str], 
        similar_bin_pairs: List[Tuple[str, str, float]]
    ) -> None:
        """
        Generate alerts based on detected patterns.
        
        Args:
            hot_bins: List of hot BIN IDs
            similar_bin_pairs: List of similar BIN pairs
        """
        # Alert for hot BINs
        for bin_id in hot_bins:
            state = self.bin_states[bin_id]
            
            self.alerts.append(Alert(
                timestamp=time.time(),
                alert_type="HOT_BIN",
                severity="medium",
                bin_ids=[bin_id],
                details={
                    "access_count": state.total_access_count,
                    "unique_ip_estimate": state.unique_ip_estimate,
                    "percentage_of_traffic": state.total_access_count / self.total_events,
                }
            ))
        
        # Alert for similar BIN pairs
        for bin_id1, bin_id2, similarity in similar_bin_pairs:
            state1 = self.bin_states[bin_id1]
            state2 = self.bin_states[bin_id2]
            
            # Determine severity based on whether either BIN is hot
            severity = "high" if (bin_id1 in hot_bins or bin_id2 in hot_bins) else "medium"
            
            self.alerts.append(Alert(
                timestamp=time.time(),
                alert_type="SIMILAR_BIN_PAIR",
                severity=severity,
                bin_ids=[bin_id1, bin_id2],
                details={
                    "similarity": similarity,
                    "bin1_access_count": state1.total_access_count,
                    "bin2_access_count": state2.total_access_count,
                    "bin1_unique_ips": state1.unique_ip_estimate,
                    "bin2_unique_ips": state2.unique_ip_estimate,
                }
            ))
            
            # Generate coordinated attack alert if both conditions are met
            if bin_id1 in hot_bins and bin_id2 in hot_bins and similarity > self.similarity_threshold + 0.2:
                self.alerts.append(Alert(
                    timestamp=time.time(),
                    alert_type="COORDINATED_ATTACK",
                    severity="high",
                    bin_ids=[bin_id1, bin_id2],
                    details={
                        "similarity": similarity,
                        "bin1_access_count": state1.total_access_count,
                        "bin2_access_count": state2.total_access_count,
                        "attack_confidence": min(0.99, similarity * 1.5),  # Simple heuristic
                    }
                ))

    def _apply_graph_rules(self) -> None:
        """
        Apply rules to the BIN similarity graph to detect coordinated patterns.
        """
        clusters = self.bin_graph.get_clusters()

        for cluster in clusters:
            # Look for clusters with 3+ BINs and at least one hot BIN
            hot_bins_in_cluster = [bin_id for bin_id in cluster if bin_id in self.bin_states and self.bin_states[bin_id].is_hot]

            if len(cluster) >= 3 and hot_bins_in_cluster:
                # Check if the cluster has high average similarity
                total_similarity = 0
                edge_count = 0

                for bin1 in cluster:
                    for bin2, weight in self.bin_graph.graph.get(bin1, {}).items():
                        if bin2 in cluster:
                            total_similarity += weight
                            edge_count += 1

                average_similarity = total_similarity / edge_count if edge_count > 0 else 0

                if average_similarity > self.similarity_threshold:
                    self.alerts.append(Alert(
                        timestamp=time.time(),
                        alert_type="COORDINATED_CLUSTER_ATTACK",
                        severity="high",
                        bin_ids=list(cluster),
                        details={
                            "hot_bins": hot_bins_in_cluster,
                            "cluster_size": len(cluster),
                            "graph_density": self._calculate_cluster_density(cluster),
                            "average_similarity": average_similarity
                        }
                    ))

    def _calculate_cluster_density(self, cluster: Set[str]) -> float:
        """
        Calculate the density of a cluster in the BIN graph.

        Args:
            cluster: Set of BIN IDs in the cluster.

        Returns:
            Density of the cluster (0.0 to 1.0).
        """
        edges = 0
        possible_edges = len(cluster) * (len(cluster) - 1) / 2

        for bin1 in cluster:
            for bin2 in self.bin_graph.graph.get(bin1, {}):
                if bin2 in cluster:
                    edges += 1

        return edges / possible_edges if possible_edges > 0 else 0.0
    
    def get_stats(self) -> dict:
        """Get statistics about the current state of the detector."""
        now = time.time()
        runtime = now - self.start_time
        
        return {
            "total_events": self.total_events,
            "total_bins": len(self.bin_states),
            "total_ips": len(self.global_ip_set),
            "runtime_seconds": runtime,
            "events_per_second": self.total_events / runtime if runtime > 0 else 0,
            "alerts_generated": len(self.alerts),
            "hot_bins": [bin_id for bin_id, state in self.bin_states.items() if state.is_hot],
            "most_active_bin": max(
                self.bin_states.items(), 
                key=lambda x: x[1].total_access_count,
                default=(None, None)
            )[0] if self.bin_states else None
        }
    
    def print_alerts(self, limit: int = 10) -> None:
        """
        Print the most recent alerts.
        
        Args:
            limit: Maximum number of alerts to print
        """
        print(f"\n===== RECENT ALERTS ({min(limit, len(self.alerts))}) =====")
        
        # Sort alerts by timestamp (newest first) and limit
        recent_alerts = sorted(self.alerts, key=lambda a: a.timestamp, reverse=True)[:limit]
        
        for alert in recent_alerts:
            alert_time = datetime.fromtimestamp(alert.timestamp).strftime('%H:%M:%S')
            severity_color = {
                "low": "\033[94m",    # Blue
                "medium": "\033[93m",  # Yellow
                "high": "\033[91m"     # Red
            }.get(alert.severity, "")
            reset_color = "\033[0m"
            
            print(f"{alert_time} - {severity_color}{alert.severity.upper()}{reset_color} - {alert.alert_type}")
            print(f"    BINs: {', '.join(alert.bin_ids)}")
            
            # Print specific details based on alert type
            if alert.alert_type == "HOT_BIN":
                print(f"    Access count: {alert.details['access_count']}")
                print(f"    Traffic %: {alert.details['percentage_of_traffic']:.2%}")
            elif alert.alert_type == "SIMILAR_BIN_PAIR":
                print(f"    Similarity: {alert.details['similarity']:.2f}")
                print(f"    Access counts: {alert.details['bin1_access_count']} / {alert.details['bin2_access_count']}")
            elif alert.alert_type == "COORDINATED_ATTACK":
                print(f"    Similarity: {alert.details['similarity']:.2f}")
                print(f"    Attack confidence: {alert.details['attack_confidence']:.2%}")
            elif alert.alert_type == "COORDINATED_CLUSTER_ATTACK":
                print(f"    Hot BINs: {', '.join(alert.details['hot_bins'])}")
                print(f"    Cluster size: {alert.details['cluster_size']}")
                print(f"    Graph density: {alert.details['graph_density']:.2f}")
            
            print()  # Empty line between alerts


# ---------------------
# Simulation Functions
# ---------------------

def generate_random_ip() -> str:
    """Generate a random IP address string."""
    return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

def simulate_traffic(
    detector: BINAttackDetector, 
    num_events: int, 
    num_bins: int = 10,
    num_ips: int = 1000,
    normal_behavior_ratio: float = 0.7,
    attack_similarity: float = 0.6,
    print_progress: bool = True
) -> None:
    """
    Simulate traffic for testing the detector.
    
    Args:
        detector: The BINAttackDetector instance
        num_events: Total number of events to simulate
        num_bins: Number of BINs to use
        num_ips: Number of unique IPs to generate
        normal_behavior_ratio: Ratio of normal to attack traffic
        attack_similarity: How similar attack IP sets should be (0.0-1.0)
        print_progress: Whether to print progress updates
    """
    # Generate BIN IDs
    bin_ids = [f"BIN{i:06d}" for i in range(num_bins)]
    
    # Generate IPs
    all_ips = [generate_random_ip() for _ in range(num_ips)]
    
    # Create sets of IPs for normal behavior
    normal_traffic_ips = {}
    for bin_id in bin_ids:
        # Each BIN gets a random subset of IPs
        ip_count = random.randint(50, 200)
        normal_traffic_ips[bin_id] = set(random.sample(all_ips, ip_count))
    
    # Create attack IPs - some shared across a few BINs
    attack_target_bins = random.sample(bin_ids, min(3, num_bins))
    attack_base_ips = set(random.sample(all_ips, int(num_ips * 0.1)))  # 10% of IPs are attackers
    
    attack_ips = {}
    for bin_id in attack_target_bins:
        # Share some IPs across attack targets
        shared_ips = set(random.sample(list(attack_base_ips), 
                                     int(len(attack_base_ips) * attack_similarity)))
        # Add some unique IPs
        unique_ips = set(random.sample(all_ips, int(num_ips * 0.05)))
        attack_ips[bin_id] = shared_ips.union(unique_ips)
    
    # Make one BIN particularly hot
    hot_bin = random.choice(bin_ids)
    
    # Process events
    progress_step = max(1, num_events // 20)
    
    for i in range(num_events):
        # Determine if this is an attack event
        is_attack = random.random() > normal_behavior_ratio
        
        if is_attack and attack_ips:
            # Choose a BIN that's under attack
            bin_id = random.choice(list(attack_ips.keys()))
            # Choose an IP from the attack set for this BIN
            ip = random.choice(list(attack_ips[bin_id]))
        else:
            # Normal traffic - random BIN with bias toward hot BIN
            if random.random() < 0.3:  # 30% chance to hit the hot BIN
                bin_id = hot_bin
            else:
                bin_id = random.choice(bin_ids)
            
            # Use an IP from the normal set for this BIN, or a random one
            if bin_id in normal_traffic_ips and normal_traffic_ips[bin_id] and random.random() < 0.9:
                ip = random.choice(list(normal_traffic_ips[bin_id]))
            else:
                ip = random.choice(all_ips)
        
        # Process the event
        detector.process_event(bin_id, ip)
        
        # Print progress
        if print_progress and i % progress_step == 0:
            percent = (i / num_events) * 100
            print(f"\rSimulating traffic: {percent:.1f}% complete", end="")
    
    if print_progress:
        print("\rSimulating traffic: 100.0% complete")


# ---------------------
# Main Function & CLI
# ---------------------

def main():
    """Main function for running the BIN attack detection simulation."""
    parser = argparse.ArgumentParser(description="BIN Attack Detection System")
    
    # Simulation parameters
    parser.add_argument("--events", type=int, default=10000,
                        help="Number of events to simulate")
    parser.add_argument("--bins", type=int, default=10,
                        help="Number of BINs to simulate")
    parser.add_argument("--ips", type=int, default=1000,
                        help="Number of unique IPs to generate")
    
    # Detection parameters
    parser.add_argument("--hot-threshold", type=float, default=0.15,
                        help="Threshold for marking a BIN as hot (proportion of traffic)")
    parser.add_argument("--similarity-threshold", type=float, default=0.5,
                        help="Threshold for considering two BINs as having similar IP sets")
    parser.add_argument("--check-interval", type=int, default=500,
                        help="Number of events to process before running detection rules")
    
    # Attack simulation parameters
    parser.add_argument("--normal-ratio", type=float, default=0.7,
                        help="Ratio of normal to attack traffic")
    parser.add_argument("--attack-similarity", type=float, default=0.6,
                        help="How similar attack IP sets should be (0.0-1.0)")
    
    # Output parameters
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress progress output")
    parser.add_argument("--output", type=str,
                        help="Output file for alerts (JSON format)")
    
    args = parser.parse_args()
    
    # Create detector with specified parameters
    detector = BINAttackDetector(
        hot_bin_threshold=args.hot_threshold,
        similarity_threshold=args.similarity_threshold,
        check_interval=args.check_interval
    )
    
    # Run simulation
    print(f"Starting simulation with {args.events} events across {args.bins} BINs...")
    simulate_traffic(
        detector=detector,
        num_events=args.events,
        num_bins=args.bins,
        num_ips=args.ips,
        normal_behavior_ratio=args.normal_ratio,
        attack_similarity=args.attack_similarity,
        print_progress=not args.quiet
    )
    
    # Print results
    print("\n===== SIMULATION COMPLETE =====")
    stats = detector.get_stats()
    print(f"Total events processed: {stats['total_events']}")
    print(f"Total BINs monitored: {stats['total_bins']}")
    print(f"Total unique IPs seen: {stats['total_ips']}")
    print(f"Simulation runtime: {stats['runtime_seconds']:.2f} seconds")
    print(f"Processing speed: {stats['events_per_second']:.2f} events/second")
    print(f"Total alerts generated: {stats['alerts_generated']}")
    
    # Print alerts
    detector.print_alerts(limit=10)
    
    # Save alerts if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump([alert.to_dict() for alert in detector.alerts], f, indent=2)
        print(f"\nAlerts saved to {args.output}")


if __name__ == "__main__":
    main()