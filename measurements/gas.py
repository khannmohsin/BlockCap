import matplotlib.pyplot as plt
import pandas as pd
import matplotlib.dates as mdates
import numpy as np
from scipy.interpolate import make_interp_spline

# Load the CSV
csv_path = "/Users/khannmohsin/VSCode_Projects/MyDisIoT_Project/Node_measurements/jvm_buffer_pool_used_bytes-data-as-joinbyfield-2025-07-19 23_45_05.csv"
df = pd.read_csv(csv_path)

# Parse the time column
df['Time'] = pd.to_datetime(df['Time'])

# Define custom color order and labels
custom_colors = {
    "Cloud": "#f2495c",
    "Fog1_Jetson@20W": "#ff9830",
    "Fog2_Jetson@20W": "#fade2a",
    "Edge1_Jetson@10W": "#73bf69",
    "Edge2_RapsberryPi4B": "#5794f2",
    "Endpoint": "#b877d9"
}

# Filter for available columns
available_nodes = [node for node in custom_colors if node in df.columns]

# Plot
plt.figure(figsize=(9, 6))
# for node in available_nodes:
#     plt.plot(df['Time'], df[node], label=node, color=custom_colors[node], linewidth=2)
#     plt.fill_between(df['Time'], df[node], color=custom_colors[node], alpha=0.3)

# Plot each node
for node in custom_colors:
    if node in df.columns:
        x = df['Time']
        y = df[node]

        # Drop NaNs for smoothing
        valid = ~y.isna()
        x_valid = mdates.date2num(x[valid])  # Convert time to numerical format
        y_valid = y[valid].values

        if len(x_valid) > 3:
            # Generate smoothed x and y
            x_smooth = np.linspace(x_valid.min(), x_valid.max(), 300)
            spline = make_interp_spline(x_valid, y_valid, k=1)
            y_smooth = spline(x_smooth)

            # Convert smoothed x back to datetime
            x_smooth_datetime = mdates.num2date(x_smooth)

            plt.plot(x_smooth_datetime, y_smooth, label=node, color=custom_colors[node], linewidth=2.5, solid_capstyle='round')
            # plt.fill_between(x_smooth_datetime, y_smooth, color=custom_colors[node], alpha=0.8)
        else:
            # Fallback to original data if not enough points
            plt.plot(x, y, label=node, color=custom_colors[node], linewidth=2.5, solid_capstyle='round')
            # plt.fill_between(x, y, color=custom_colors[node], alpha=0.8)

# Formatting x-axis
plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
# plt.gcf().autofmt_xdate()

plt.legend(
    loc='upper center',
    bbox_to_anchor=(0.5, -0.25),   # Moves legend further down for more space
    ncol=3,                         # Use 3 columns instead of 6 for readability
    frameon=False,
    handlelength=1,              # Makes legend lines longer
    fontsize=14                    # Balanced for figsize=(10, 6)
)

# Labels and legend
plt.xlabel("Time", labelpad=10, fontsize=14, rotation=0, ha='center', fontweight='bold')
plt.ylabel("Direct Buffer Memory Usage (MB)", fontsize=14, fontweight='bold')
# plt.title("Average Gas Utilization Across Validator Nodes")
# Legend with longer line display

ax = plt.gca()
# Hide top and right spines
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
# Ensure bottom and left are visible
ax.spines['bottom'].set_visible(True)
ax.spines['left'].set_visible(True)

plt.grid(True, color='gray', linestyle='--', linewidth=1, alpha=0.3)
plt.tight_layout()
# plt.show()
plt.savefig("/Users/khannmohsin/VSCode_Projects/MyDisIoT_Project/Node_measurements/buffer_memory.pdf", format="pdf", bbox_inches="tight")
# plt.savefig()



# import pandas as pd
# import matplotlib.pyplot as plt
# import matplotlib.dates as mdates
# from scipy.interpolate import make_interp_spline
# import numpy as np
# from datetime import datetime

# # Load CSV
# df = pd.read_csv("/Users/khannmohsin/VSCode_Projects/MyDisIoT_Project/Node_measurements/Average Gas Utilization Across Validator Nodes-data-as-joinbyfield-2025-07-19 20_06_00.csv")
# df['Time'] = pd.to_datetime(df['Time'])

# # Custom colors
# custom_colors = {
#     "Cloud": "#f2495c",
#     "Fog1_Jetson@20W": "#ff9830",
#     "Fog2_Jetson@20W": "#fade2a",
#     "Edge1_Jetson@10W": "#73bf69",
#     "Edge2_RapsberryPi4B": "#5794f2",
#     "Endpoint": "#b877d9",
# }

# plt.figure(figsize=(12, 6))

# # Plot each node with smoothing and fill
# for node, color in custom_colors.items():
#     if node in df.columns:
#         x = mdates.date2num(df['Time'])
#         y = df[node].fillna(0).values
#         if len(x) > 3:
#             x_smooth = np.linspace(x.min(), x.max(), 300)
#             spline = make_interp_spline(x, y, k=3)
#             y_smooth = spline(x_smooth)
#             plt.fill_between(mdates.num2date(x_smooth), y_smooth, color=color, alpha=0.5)
#             plt.plot(mdates.num2date(x_smooth), y_smooth, label=node, color=color)
#         else:
#             plt.fill_between(df['Time'], y, color=color, alpha=0.5)
#             plt.plot(df['Time'], y, label=node, color=color)

# # Format x-axis
# plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
# plt.xlabel("Time (HH:MM)")
# plt.ylabel("Gas Used")
# plt.title("Average Gas Utilization Across Validator Nodes")
# plt.legend(title="Nodes", loc="upper right")
# plt.grid(True, color='gray', linestyle='--', linewidth=0.5, alpha=0.3)
# plt.tight_layout()
# plt.xticks(rotation=45)
# plt.show()