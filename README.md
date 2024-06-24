# Flow timeline visualizer

## Run from stdin

`head -n 100000 conn.log|sort -n | python flow_visualizer.py --stdin --min-duration 60`

## Run from parameter

`python flow_visualizer.py --min-duration 60 conn.log`

## How it looks like

![image](https://github.com/stratosphereips/flow-visualizer/assets/2458867/fd3d29bc-0a02-47a3-8a46-923687e653b4)
