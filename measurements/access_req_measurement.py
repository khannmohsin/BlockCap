import os
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import numpy as np
import matplotlib.lines as mlines

# SET THIS TO YOUR ACTUAL PATH
NODE_ROOT = "/Users/khannmohsin/VSCode_Projects/MyDisIoT_Project/Node_measurements/trial_1"

function_metrics = ["memory_kb", "total_cpu_time_seconds"]
aggregated_data = {
    "Node": [],
    "mean_memory_kb": [],
    "std_memory_kb": [],
    "mean_cpu_time": [],
    "std_cpu_time": []
}

def parse_timestamp(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except:
        return pd.NaT

# Parse blocks separated by empty lines
def parse_csv_blocks(filepath):
    blocks = []
    with open(filepath, "r") as f:
        lines = f.readlines()

    header = lines[0].strip().split(",")
    current_block = []

    for line in lines[1:]:
        if line.strip() == "":
            if current_block:
                blocks.append(pd.DataFrame(current_block, columns=header))
                current_block = []
        else:
            current_block.append(line.strip().split(","))

    if current_block:
        blocks.append(pd.DataFrame(current_block, columns=header))
    
    return blocks

# Process each node folder
for node in os.listdir(NODE_ROOT):
    node_path = os.path.join(NODE_ROOT, node, "measurements")
    if not os.path.isdir(node_path):
        continue

    init_file = None
    for fname in ["acc_request.csv"]:
        candidate = os.path.join(node_path, fname)
        if os.path.exists(candidate):
            init_file = candidate
            break
    if not init_file:
        continue

    blocks = parse_csv_blocks(init_file)

    mem_means = []
    cpu_means = []

    for block in blocks:
        for col in ["memory_kb", "total_cpu_time_seconds"]:
            block[col] = pd.to_numeric(block[col], errors="coerce")

        mem_means.append(block["memory_kb"].sum())
        cpu_means.append(block["total_cpu_time_seconds"].sum())
    


    aggregated_data["Node"].append(node)
    aggregated_data["mean_memory_kb"].append(np.mean(mem_means))
    aggregated_data["std_memory_kb"].append(np.std(mem_means))
    aggregated_data["mean_cpu_time"].append(np.mean(cpu_means))
    aggregated_data["std_cpu_time"].append(np.std(cpu_means))
    # print(f"Processed {node}: Memory mean = {np.mean(mem_means):.2f} KB, CPU mean = {np.mean(cpu_means):.2f} seconds")

# Convert to DataFrame
df = pd.DataFrame(aggregated_data)

# Visualization
custom_colors = {
    "Cloud": "#f2495c",
    "Edge1_Jetson@10W": "#ff9830",
    "Edge2_RapsberryPi4B": "#fade2a",
    "Fog1_Jetson@20W": "#73bf69",
    "Fog2_Jetson@20W": "#5794f2",
    "Endpoint": "#b877d9",
}
markers = ['o', 's', '^', 'D', 'P', 'X', '*', 'v', '<', '>']
node_markers = {node: markers[i % len(markers)] for i, node in enumerate(df["Node"])}

plt.figure(figsize=(10, 8))
for i, row in df.iterrows():
    node = row["Node"]
    x = row["mean_cpu_time"]
    y = row["mean_memory_kb"]
    xerr = row["std_cpu_time"]
    yerr = row["std_memory_kb"]
    color = custom_colors.get(node, "#7f7f7f")
    marker = node_markers.get(node, 'o')

    # Plot marker
    plt.scatter(
        x, y,
        s=100,
        color=color,
        edgecolors=color,
        marker=marker,
        linewidths=1.5,
        zorder=3
    )

    # # Error bars from marker edge
    # plt.errorbar(
    #     x, y,
    #     xerr=xerr,
    #     yerr=yerr,
    #     fmt='none',
    #     ecolor="black",
    #     capsize=5,
    #     elinewidth=1.2,
    #     zorder=2,
    #     label="_nolegend_"
    # )

# Construct legend with matching marker shapes and colors
legend_handles = []
for node in custom_colors.keys():
    if node in df["Node"].values:
        handle = mlines.Line2D(
            [], [], color=custom_colors[node], marker=node_markers[node],
            linestyle='None', markersize=10, markerfacecolor=custom_colors[node],
            markeredgewidth=1.5, label=node
        )
        legend_handles.append(handle)

plt.xlabel("CPU Time (seconds)")
plt.ylabel("Memory Usage (KB)")
plt.title("CPU Time vs Memory Usage per Node (Initialization Phase)")
plt.grid(True)
plt.tight_layout()
plt.legend(handles=legend_handles, title="Nodes", loc="upper left", frameon=True)
plt.show()