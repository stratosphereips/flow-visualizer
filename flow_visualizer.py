from flask import Flask, render_template_string
import pandas as pd
import numpy as np
import argparse
import sys
import json
from datetime import datetime
import random
import colorsys

app = Flask(__name__)

# Normalize column names to match expected format
def normalize_column_names(df):
    column_mapping = {
        "id.orig_h": "id_orig_h",
        "id.orig_p": "id_orig_p",
        "id.resp_h": "id_resp_h",
        "id.resp_p": "id_resp_p",
        "orig_bytes": "orig_bytes",
        "resp_bytes": "resp_bytes",
        "conn_state": "conn_state",
        "local_orig": "local_orig",
        "local_resp": "local_resp",
        "missed_bytes": "missed_bytes",
        "history": "history",
        "orig_pkts": "orig_pkts",
        "orig_ip_bytes": "orig_ip_bytes",
        "resp_pkts": "resp_pkts",
        "resp_ip_bytes": "resp_ip_bytes",
        "tunnel_parents": "tunnel_parents",
        "ts": "ts",
        "uid": "uid",
        "proto": "proto",
        "service": "service",
        "duration": "duration"
    }
    df.rename(columns=column_mapping, inplace=True)
    return df

# Read Zeek conn log file or stdin
def read_zeek_conn_log(file_path=None, use_stdin=False):
    if use_stdin:
        lines = sys.stdin.readlines()
    else:
        with open(file_path, 'r') as file:
            lines = file.readlines()
    
    # Determine the file type by checking the first line
    if lines[0].startswith('{'):
        # JSON format
        data = [json.loads(line) for line in lines]
        df = pd.DataFrame(data)
    else:
        # Tab-separated format
        columns = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", 
                   "proto", "service", "duration", "orig_bytes", "resp_bytes", 
                   "conn_state", "local_orig", "local_resp", "missed_bytes", 
                   "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", 
                   "tunnel_parents"]
        
        data = []
        for line in lines:
            if not line.startswith("#"):
                parts = line.split()
                if len(parts) == len(columns):
                    data.append(parts)
                else:
                    while len(parts) < len(columns):
                        parts.append("-")
                    data.append(parts[:len(columns)])
        
        df = pd.DataFrame(data, columns=columns)
        
        # Replace '-' with NaN
        df.replace('-', np.nan, inplace=True)
        
        # Convert columns to appropriate types
        df['ts'] = df['ts'].astype(float)
        df['duration'] = df['duration'].astype(float)
        df['orig_bytes'] = df['orig_bytes'].astype(float)
        df['resp_bytes'] = df['resp_bytes'].astype(float)
        df['missed_bytes'] = df['missed_bytes'].astype(float)
        df['orig_pkts'] = df['orig_pkts'].astype(float)
        df['orig_ip_bytes'] = df['orig_ip_bytes'].astype(float)
        df['resp_pkts'] = df['resp_pkts'].astype(float)
        df['resp_ip_bytes'] = df['resp_ip_bytes'].astype(float)
    
    # Normalize column names
    df = normalize_column_names(df)

    # Add human-readable timestamp
    df['human_ts'] = df['ts'].apply(lambda x: datetime.utcfromtimestamp(x).strftime('%Y-%m-%d %H:%M:%S'))
    
    return df

# Generate a random color
def generate_random_color():
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))

# Generate a shade of a given color
def generate_shade(color, shade_factor):
    color = color.lstrip('#')
    rgb = tuple(int(color[i:i+2], 16) for i in (0, 2, 4))
    hls = colorsys.rgb_to_hls(rgb[0]/255, rgb[1]/255, rgb[2]/255)
    shaded_rgb = colorsys.hls_to_rgb(hls[0], max(0, min(1, hls[1] * shade_factor)), hls[2])
    return "#{:02x}{:02x}{:02x}".format(int(shaded_rgb[0] * 255), int(shaded_rgb[1] * 255), int(shaded_rgb[2] * 255))

# Determine if a color is dark
def is_dark(color):
    color = color.lstrip('#')
    rgb = tuple(int(color[i:i+2], 16) for i in (0, 2, 4))
    hls = colorsys.rgb_to_hls(rgb[0]/255, rgb[1]/255, rgb[2]/255)
    return hls[1] < 0.5

# Custom filter to enforce minimum width
@app.template_filter('min_width')
def min_width(value, min_width):
    return max(value, min_width)

# Custom filter to check if a color is dark
@app.template_filter('is_dark')
def jinja_is_dark(color):
    return is_dark(color)

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
    
    # Assign colors to source-destination IP pairs
    unique_ip_pairs = df[['id_orig_h', 'id_resp_h']].drop_duplicates()
    ip_pair_colors = {tuple(row): generate_random_color() for row in unique_ip_pairs.values}
    
    # Assign shades to destination ports
    port_shades = {}
    for (src_ip, dst_ip), base_color in ip_pair_colors.items():
        ports = df[(df['id_orig_h'] == src_ip) & (df['id_resp_h'] == dst_ip)]['id_resp_p'].unique()
        shades = {port: generate_shade(base_color, 1 - 0.2 * i) for i, port in enumerate(ports)}
        port_shades.update({(src_ip, dst_ip, port): shade for port, shade in shades.items()})
    
    df['color'] = df.apply(lambda row: port_shades[(row['id_orig_h'], row['id_resp_h'], row['id_resp_p'])], axis=1)
    
    flows = df.to_dict(orient='records')
    return render_template_string(TEMPLATE, flows=flows, max_duration=max_duration, max_relative_start=max_relative_start)

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

        function evaluateExpression(flowText, expr) {
            try {
                return Function('"use strict"; var flowText = "' + flowText + '"; return (' + expr + ')')();
            } catch (e) {
                return false;
            }
        }

        function filterFlows() {
            var textFilter = document.getElementById('text-filter').value.toLowerCase();
            var durationFilter = parseFloat(document.getElementById('duration-filter').value);
            var flows = document.getElementsByClassName('flow-container');
            var filterExpr = textFilter
                .replace(/and/gi, '&&')
                .replace(/or/gi, '||')
                .replace(/not/gi, '!')
                .replace(/([a-zA-Z0-9]+)/g, 'flowText.includes("$1")');

            for (var i = 0; i < flows.length; i++) {
                var flowText = flows[i].getElementsByClassName('flow-text')[0].innerText.toLowerCase();
                var flowDuration = parseFloat(flows[i].getElementsByClassName('flow')[0].dataset.duration);
                var textMatch = textFilter === "" || evaluateExpression(flowText, filterExpr);
                var durationMatch = isNaN(durationFilter) || flowDuration >= durationFilter;
                if (textMatch && durationMatch) {
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
    <input type="text" id="text-filter" onkeyup="filterFlows()" placeholder="Filter by text... (use 'not', 'and', 'or', parentheses)">
    <input type="number" id="duration-filter" onkeyup="filterFlows()" placeholder="Minimum duration (seconds)">
    <div class="timeline">
        {% for flow in flows %}
        <div class="flow-container" style="margin-left: {{ (flow.relative_start / max_relative_start) * 100 }}%;">
            <div class="flow" data-duration="{{ flow.duration }}" style="background-color: {{ flow.color }}; width: {{ ((flow.duration / max_duration) * 100) | min_width(0.5) }}%;" onmouseover='showTooltip(event, {{ flow | tojson }});' onmouseout="hideTooltip();"></div>
            <div class="flow-text" style="color: {{ 'black' if ((flow.duration / max_duration) * 100) < 5 else ('white' if flow.color|is_dark else 'black') }};">{{ flow.human_ts }} - {{ flow.id_orig_h }}:{{ flow.id_orig_p }} -> {{ flow.id_resp_h }}:{{ flow.id_resp_p }}</div>
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

