import statistics
import math

def compute_stats(durations):
    if len(durations) < 2:
        print("At least two data points are needed.")
        return

    mean_val = statistics.mean(durations)
    std_dev = statistics.stdev(durations)
    std_err = std_dev / math.sqrt(len(durations))

    print(f"Mean: {mean_val:.4f} seconds")
    print(f"Standard Deviation: {std_dev:.4f} seconds")
    print(f"Standard Error: ±{std_err:.4f} seconds")

# Example usage:
durations_in_seconds = [50.2010, 49.1234, 76.9830]
compute_stats(durations_in_seconds)