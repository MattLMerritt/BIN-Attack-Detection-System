import matplotlib.pyplot as plt
import networkx as nx

# System Architecture Diagram
def create_system_architecture_diagram():
    G = nx.DiGraph()
    G.add_edges_from([
        ("Event Processor", "Detection Engine"),
        ("Detection Engine", "Policy Engine"),
        ("Detection Engine", "Graph Database"),
        ("Policy Engine", "Alert System"),
    ])

    pos = nx.spring_layout(G)
    plt.figure(figsize=(10, 6))
    nx.draw(G, pos, with_labels=True, node_size=3000, node_color="lightblue", font_size=10, font_weight="bold")
    plt.title("System Architecture")
    plt.savefig("diagrams/system_architecture.png")
    plt.close()

# Workflow Diagram
def create_workflow_diagram():
    G = nx.DiGraph()
    G.add_edges_from([
        ("Event Ingestion", "Update Probabilistic Structures"),
        ("Update Probabilistic Structures", "Detection Rules"),
        ("Detection Rules", "BIN Similarity Graph"),
        ("BIN Similarity Graph", "Clustering"),
        ("Clustering", "Alert Generation"),
    ])

    pos = nx.spring_layout(G)
    plt.figure(figsize=(10, 6))
    nx.draw(G, pos, with_labels=True, node_size=3000, node_color="lightgreen", font_size=10, font_weight="bold")
    plt.title("Workflow")
    plt.savefig("diagrams/workflow.png")
    plt.close()

# OPA and Neo4j Integration Diagram
def create_opa_neo4j_integration_diagram():
    G = nx.DiGraph()
    G.add_edges_from([
        ("Detection Engine", "OPA"),
        ("OPA", "Policy Evaluation"),
        ("Detection Engine", "Neo4j"),
        ("Neo4j", "Graph Queries"),
    ])

    pos = nx.spring_layout(G)
    plt.figure(figsize=(10, 6))
    nx.draw(G, pos, with_labels=True, node_size=3000, node_color="lightcoral", font_size=10, font_weight="bold")
    plt.title("OPA and Neo4j Integration")
    plt.savefig("diagrams/opa_neo4j_integration.png")
    plt.close()

if __name__ == "__main__":
    create_system_architecture_diagram()
    create_workflow_diagram()
    create_opa_neo4j_integration_diagram()