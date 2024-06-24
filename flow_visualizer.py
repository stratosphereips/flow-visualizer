from flask import Flask, render_template_string
import pandas as pd
import argparse
import sys
import json
from datetime import datetime
import random

app = Flask(__name__)

# Read Zeek conn log file or stdin
def read_zeek_conn_log(file_path=None, use_stdin=False):
    columns = ["ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p", 
               "proto", "service", "duration", "orig_bytes", "resp_bytes", 
               "conn_state", "local_orig", "local_resp", "missed_bytes", 
               "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", 
               "tunnel_parents"]
    
    data = []
    if use_stdin:
        source = sys.stdin
    else:
        source = open(file_path, 'r')

    with source as file:
        for line in file:
            if not line.startswith("#"):
                parts = line.split()
                if len(parts) == len(columns):
                    data.append(parts)
                else:
                    while len(parts) < len(columns):
                        parts.append("-")
                    data.append(parts[:len(columns)])
    
    df = pd.DataFrame(data, columns=columns)
    df['ts'] = df['ts'].astype(float)
    df['duration'] = df['duration'].astype(float)
    df['human_ts'] = df['ts'].apply(lambda x: datetime.utcfromtimestamp(x).strftime('%Y-%m-%d %H:%M:%S'))
    return df

# Generate a random color
def generate_random_color():
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))

@app.route('/')
def index():
    if args.stdin:
        df = read_zeek_conn_log(use_stdin=True)
    else:
        df = read_zeek_conn_log(args.filename)
    
    # Filter by minimum duration
    df = df[df['duration'] >= args.min_duration]
    
    min_ts = df['ts'].min()
    df['relative_start'] = df['ts'] - min_ts
    max_duration = df['duration'].max()
    max_relative_start = df['relative_start'].max()
    
    # Assign colors to source IPs
    unique_ips = df['id_orig_h'].unique()
    ip_colors = {ip: generate_random_color() for ip in unique_ips}
    
    flows = df.to_dict(orient='records')
    return render_template_string(TEMPLATE, flows=flows, max_duration=max_duration, max_relative_start=max_relative_start, ip_colors=ip_colors)

TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Zeek Conn Flows</title>
    <style>
        .timeline {
            display: flex;
            flex-direction: column;
        }
        .flow-container {
            display: flex;
            align-items: center;
            position: relative;
            margin-bottom: 10px;
        }
        .flow {
            height: 10px;
            position: absolute;
        }
        .flow-text {
            margin-left: 5px;
            font-size: 12px;
            white-space: nowrap;
            position: relative;
            left: 5px;
        }
        .tooltip {
            position: absolute;
            background-color: #333;
            color: #fff;
            padding: 10px;
            border-radius: 5px;
            display: none;
            font-size: 12px;
            z-index: 1000;
            max-width: 300px;
            word-wrap: break-word;
        }
    </style>
    <script>
        function showTooltip(event, flow) {
            var tooltip = document.getElementById('tooltip');
            tooltip.innerHTML = 'Timestamp: ' + flow.human_ts + '<br>' +
                                'Source IP: ' + flow.id_orig_h + '<br>' +
                                'Source Port: ' + flow.id_orig_p + '<br>' +
                                'Destination IP: ' + flow.id_resp_h + '<br>' +
                                'Destination Port: ' + flow.id_resp_p + '<br>' +
                                'Duration: ' + flow.duration + ' seconds';
            tooltip.style.display = 'block';
            tooltip.style.left = event.pageX + 10 + 'px';
            tooltip.style.top = event.pageY + 10 + 'px';
        }

        function hideTooltip() {
            var tooltip = document.getElementById('tooltip');
            tooltip.style.display = 'none';
        }

        function filterFlows() {
            var textFilter = document.getElementById('text-filter').value.toLowerCase();
            var durationFilter = parseFloat(document.getElementById('duration-filter').value);
            var flows = document.getElementsByClassName('flow-container');
            for (var i = 0; i < flows.length; i++) {
                var flowText = flows[i].getElementsByClassName('flow-text')[0].innerText.toLowerCase();
                var flowDuration = parseFloat(flows[i].getElementsByClassName('flow')[0].dataset.duration);
                if (flowText.includes(textFilter) && (isNaN(durationFilter) || flowDuration >= durationFilter)) {
                    flows[i].style.display = 'flex';
                } else {
                    flows[i].style.display = 'none';
                }
            }
        }
    </script>
</head>
<body>
    <h1>Zeek Conn Flows</h1>
    <input type="text" id="text-filter" onkeyup="filterFlows()" placeholder="Filter by text...">
    <input type="number" id="duration-filter" onkeyup="filterFlows()" placeholder="Minimum duration (seconds)">
    <div class="timeline">
        {% for flow in flows %}
        <div class="flow-container" style="margin-left: {{ (flow.relative_start / max_relative_start) * 100 }}%;">
            <div class="flow" data-duration="{{ flow.duration }}" style="background-color: {{ ip_colors[flow.id_orig_h] }}; width: {{ (flow.duration / max_duration) * 100 }}%;" onmouseover='showTooltip(event, {{ flow | tojson }});' onmouseout="hideTooltip();"></div>
            <div class="flow-text">{{ flow.human_ts }} - {{ flow.id_orig_h }}:{{ flow.id_orig_p }} -> {{ flow.id_resp_h }}:{{ flow.id_resp_p }}</div>
        </div>
        {% endfor %}
    </div>
    <div id="tooltip" class="tooltip"></div>
</body>
</html>
'''

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run Flask app to display Zeek conn flows.')
    parser.add_argument('--stdin', action='store_true', help='Read Zeek conn log from stdin')
    parser.add_argument('--min-duration', type=float, default=0.0, help='Minimum duration of flows to display')
    parser.add_argument('filename', type=str, nargs='?', help='The Zeek conn log file to read')
    args = parser.parse_args()
    
    if not args.stdin and not args.filename:
        parser.error('Must provide a filename or use --stdin to read from stdin')

    app.run(debug=True)

