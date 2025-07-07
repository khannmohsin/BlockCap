import os
import time
import tracemalloc
import resource
import functools
import socket
import shutil
from flask import Flask, Response
from prometheus_client import Summary, Gauge, multiprocess, REGISTRY, generate_latest, CONTENT_TYPE_LATEST, write_to_textfile
import csv

# --- Setup Prometheus Multiprocessing ---
PROMETHEUS_DIR = "/tmp/prometheus_multiproc"
os.environ["PROMETHEUS_MULTIPROC_DIR"] = PROMETHEUS_DIR
if os.path.exists(PROMETHEUS_DIR):
    shutil.rmtree(PROMETHEUS_DIR)
os.makedirs(PROMETHEUS_DIR)

# Register the multiprocess collector
multiprocess.MultiProcessCollector(REGISTRY)

# --- Define Metrics ---
FUNCTION_DURATION = Summary('function_duration_seconds', 'Time spent in function', ['function'])
FUNCTION_MEMORY = Gauge('function_memory_kb', 'Memory used in function (KB)', ['function'])
FUNCTION_CPU = Gauge('function_cpu_time_seconds', 'CPU time used in function', ['function'])

# Request-level metrics
REQUEST_DURATION = Summary('request_duration_seconds', 'Time for outgoing request', ['function'])
REQUEST_PAYLOAD_SIZE = Gauge('request_payload_size_bytes', 'Payload size in bytes', ['function'])
REQUEST_RESPONSE_SIZE = Gauge('request_response_size_bytes', 'Response size in bytes', ['function'])



# --- Flask Server for /metrics ---
app = Flask(__name__)

@app.route("/metrics")
def metrics():
    """Expose Prometheus metrics."""
    data = generate_latest(REGISTRY)
    # print("[Flask] Metrics endpoint accessed")
    # print(data.decode('utf-8'))  # Log the metrics data
    return Response(data, mimetype=CONTENT_TYPE_LATEST)

# --- Utility to Track Function Performance ---
def track_performance(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        fname = func.__name__
        # print(f"[Monitor] Tracking performance for: {fname}")
        
        # Start tracking
        tracemalloc.start()
        cpu_start = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        start = time.time()
        
        # Run function
        result = func(*args, **kwargs)
        
        # End tracking
        end = time.time()
        cpu_end = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        current, _ = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Record metrics
        FUNCTION_DURATION.labels(fname).observe(end - start)
        FUNCTION_MEMORY.labels(fname).set(current / 1024)
        FUNCTION_CPU.labels(fname).set(cpu_end - cpu_start)

        print(f"[Monitor] {time.strftime('%Y-%m-%d %H:%M:%S')} - {fname} - Duration: {end - start:.4f}s, Memory: {current / 1024:.2f}KB, CPU Time: {cpu_end - cpu_start:.4f}s")
        # Append metrics to CSV
        csv_file = "measurements/function_metrics.csv"
        file_exists = os.path.isfile(csv_file)
        with open(csv_file, mode='a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["timestamp", "function", "duration_seconds", "memory_kb", "cpu_time_seconds"])
            writer.writerow([time.strftime('%Y-%m-%d %H:%M:%S'), fname, f"{end - start:.4f}", f"{current / 1024:.2f}", f"{cpu_end - cpu_start:.4f}"])

        return result
    return wrapper

def observe_request_metrics(func_name, payload_size, response_size, duration):
    REQUEST_DURATION.labels(func_name).observe(duration)
    REQUEST_PAYLOAD_SIZE.labels(func_name).set(payload_size)
    REQUEST_RESPONSE_SIZE.labels(func_name).set(response_size)
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    print(f"[Monitor] {timestamp} - Request Metrics - Function: {func_name}, Duration: {duration:.4f}s, Payload Size: {payload_size} bytes, Response Size: {response_size} bytes")
    csv_file = "measurements/request_metrics.csv"
    file_exists = os.path.isfile(csv_file)
    with open(csv_file, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "function", "duration_seconds", "payload_size_bytes", "response_size_bytes"])
        writer.writerow([func_name, f"{duration:.4f}", payload_size, response_size])

@track_performance
def dummy_work():
    print("Running dummy work...")
    time.sleep(2)

# --- Main Entry ---
if __name__ == "__main__":
    # dummy_work()  # Collect some metrics
    print("[Flask] Starting Flask server on port 9101...")
    app.run(host="0.0.0.0", port=9101)