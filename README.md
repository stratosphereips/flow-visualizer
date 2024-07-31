# Flow timeline visualizer

## Run from stdin

`head -n 100000 conn.log|sort -n | python flow_visualizer.py --stdin --min-duration 60`

## Run from parameter

`python flow_visualizer.py --min-duration 60 conn.log`

## Features
- Reads conn.log files separated by TAB.
- Reads conn.log files in JSON format.
- Uses font colors that do not mix with background colors.
- All the connections to the same src IP and dst IP share the same shade of color, but slightly different for different dst ports.
- You can filter by any text.
- You can filter by the min duration of the flows.

## How it looks like

![image](https://github.com/stratosphereips/flow-visualizer/assets/2458867/fd3d29bc-0a02-47a3-8a46-923687e653b4)

![image](https://github.com/user-attachments/assets/cc5e20ff-c23e-42a7-9c86-312ba24a51c4)

![image](https://github.com/user-attachments/assets/5d9db676-9f22-4b29-905e-ef55775e370c)
