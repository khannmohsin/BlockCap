import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# Load the two CSV files
cpu_df = pd.read_csv("/Users/khannmohsin/VSCode_Projects/MyDisIoT_Project/Node_measurements/process_cpu_seconds_total.csv")
mem_df = pd.read_csv("/Users/khannmohsin/VSCode_Projects/MyDisIoT_Project/Node_measurements/Resident Memory Usage (RAM in Use by Besu Process)-data-as-joinbyfield-2025-07-19 17_46_19.csv")

# Convert memory from bytes to MB for easier readability
mem_df_mb = mem_df.copy()
for col in mem_df.columns[1:]:
    mem_df_mb[col] = mem_df[col] / (1024 * 1024)

# Merge on the timestamp (assuming the first column is the timestamp)
cpu_df.rename(columns={cpu_df.columns[0]: "timestamp"}, inplace=True)
mem_df_mb.rename(columns={mem_df_mb.columns[0]: "timestamp"}, inplace=True)

merged_df = pd.merge(cpu_df, mem_df_mb, on="timestamp", suffixes=('_cpu', '_mem'))

# Custom colors
custom_colors = {
    "Cloud": "#f2495c",
    "Edge1_Jetson@10W": "#ff9830",
    "Edge2_RapsberryPi4B": "#fade2a",
    "Fog1_Jetson@20W": "#73bf69",
    "Fog2_Jetson@20W": "#5794f2",
    "Endpoint": "#b877d9",
}

# Create the plot
plt.figure(figsize=(9, 6))
for node in custom_colors:
    cpu_col = f"{node}_cpu"
    mem_col = f"{node}_mem"
    if cpu_col in merged_df.columns and mem_col in merged_df.columns:
        plt.plot(
            merged_df[cpu_col],
            merged_df[mem_col],
            # marker='o',
            label=node,
            color=custom_colors[node],
            linestyle='-', 
            linewidth=2,
        )

# Formatting x-axis
# plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
# plt.gcf().autofmt_xdate()

plt.legend(
    loc='upper center',
    bbox_to_anchor=(0.5, -0.25),   # Moves legend further down for more space
    ncol=3,                         # Use 3 columns instead of 6 for readability
    frameon=False,
    handlelength=1,              # Makes legend lines longer
    fontsize=14                    # Balanced for figsize=(10, 6)
)

plt.xlabel("CPU Time (seconds)", labelpad=10, fontsize=14, rotation=0, ha='center', fontweight='bold')
plt.ylabel("Resident Memory Usage (MB)", fontsize=14, fontweight='bold')
# plt.title("CPU Time vs Memory Usage per Node (Grafana Exported Data)")
ax = plt.gca()
# Hide top and right spines
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
# Ensure bottom and left are visible
ax.spines['bottom'].set_visible(True)
ax.spines['left'].set_visible(True)

plt.grid(True, color='gray', linestyle='--', linewidth=1, alpha=0.3)
plt.tight_layout()
plt.savefig("/Users/khannmohsin/VSCode_Projects/MyDisIoT_Project/Node_measurements/cpu_vs_resident_memory_usage.pdf", format="pdf", bbox_inches="tight")
# plt.show()