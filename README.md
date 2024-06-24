# Flow timeline visualizer

## Run from stdin

`head -n 100000 conn.log|sort -n | python flow_visualizer.py --stdin --min-duration 60`

## Run from parameter

`python flow_visualizer.py --min-duration 60 conn.log`
