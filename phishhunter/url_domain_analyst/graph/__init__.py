"""Typed knowledge-graph contracts for URL & Domain Analyst."""
from .builder import build as build_graph
from ..contracts.enums import EdgeKind, NodeKind

def relationship_contract() -> dict:
    return {
        'node_types':[x.value for x in NodeKind],
        'edge_types':[x.value for x in EdgeKind],
        'interaction':{
            'drag':True,'pan':True,'zoom':True,'fit':True,
            'one_hop':True,'two_hop':True,'shortest_path':True,'click_to_isolate':True,
            'filter_by_node_type':True,'filter_by_edge_type':True,'search':True,
            'layout_modes':['force','hierarchical','radial','timeline','geographic'],
        },
    }
