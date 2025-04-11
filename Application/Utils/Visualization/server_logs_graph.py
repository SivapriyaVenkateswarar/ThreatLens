import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import Normalize
import numpy as np
import io

def make_network_graph(df):
    G = nx.DiGraph()

    for _, row in df.iterrows():
        src = row['Src IP Addr']
        dst = row['Dst IP Addr']
        edge_data = {
            'proto': row['Proto'],
            'bytes': row['Bytes'],
            'packets': row['Packets'],
            'flags': row['Flags'],
            'duration': row['Duration'],
        }
        G.add_edge(src, dst, **edge_data)

    top_nodes = sorted(G.out_degree(), key=lambda x: x[1], reverse=True)[:50]
    top_node_ids = [n for n, _ in top_nodes]
    H = G.subgraph(top_node_ids)

    pos = nx.spring_layout(H, k=0.5, seed=42)
    edge_weights = [H[u][v].get('bytes', 1) for u, v in H.edges()]
    norm = Normalize(vmin=min(edge_weights), vmax=max(edge_weights))
    edge_colors = [plt.cm.plasma(norm(w)) for w in edge_weights]

    fig, ax = plt.subplots(figsize=(15, 12), facecolor='black')
    fig.suptitle("Directed Network Graph with Arrows", fontsize=16, color='white')

    nx.draw_networkx_nodes(H, pos, node_color="skyblue", edgecolors='white', linewidths=1.5, node_size=2500, ax=ax)
    nx.draw_networkx_labels(H, pos, font_color='white', font_size=10, ax=ax)

    for (u, v), color in zip(H.edges(), edge_colors):
        rad = 0.15
        arrow = mpatches.FancyArrowPatch(
            posA=pos[u],
            posB=pos[v],
            connectionstyle=f"arc3,rad={rad}",
            arrowstyle='-|>',
            color=color,
            mutation_scale=18,
            lw=2.5
        )
        ax.add_patch(arrow)

    sm = plt.cm.ScalarMappable(cmap=plt.cm.plasma, norm=norm)
    sm.set_array([])
    cbar = fig.colorbar(sm, ax=ax, shrink=0.75, pad=0.02)
    cbar.set_label('Bytes Transferred (per edge)', rotation=270, labelpad=20, color='white')
    cbar.ax.yaxis.set_tick_params(color='white')
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color='white')

    ax.set_facecolor('black')
    ax.axis('off')
    plt.tight_layout()

    # Save to BytesIO buffer for Streamlit
    buf = io.BytesIO()
    plt.savefig(buf, format='png', facecolor=fig.get_facecolor(), bbox_inches='tight')
    buf.seek(0)
    plt.close(fig)
    return buf

import io

def make_protocol_graphs(df, N=100):
    import networkx as nx
    import matplotlib.pyplot as plt
    import io

    graph_buffers = []
    protocols = df['Proto'].unique()

    for proto in protocols:
        df_proto = df[df['Proto'] == proto].copy()
        df_proto = df_proto.sort_values(by='Bytes', ascending=False).head(N)

        G_proto = nx.DiGraph()
        for _, row in df_proto.iterrows():
            src = row['Src IP Addr']
            dst = row['Dst IP Addr']
            edge_data = {
                'bytes': row['Bytes'],
                'packets': row['Packets'],
                'duration': row['Duration']
            }
            G_proto.add_edge(src, dst, **edge_data)

        fig, ax = plt.subplots(figsize=(6, 5))  # Smaller size
        pos = nx.spring_layout(G_proto, k=0.8, iterations=20)
        nx.draw(G_proto, pos, with_labels=True, node_size=250, edge_color='gray', alpha=0.6, ax=ax)

        edge_labels = {
            (u, v): round(d['bytes'], 2)
            for u, v, d in G_proto.edges(data=True)
        }
        nx.draw_networkx_edge_labels(G_proto, pos, edge_labels=edge_labels, font_size=6, font_color='red', ax=ax)

        ax.set_title(f"Protocol {proto} - Top {N} Connections", fontsize=10)

        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png', bbox_inches='tight')
        buf.seek(0)
        plt.close(fig)

        graph_buffers.append((proto, buf))

    return graph_buffers


