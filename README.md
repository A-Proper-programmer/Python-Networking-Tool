# Python Networking Tool

> A small project, to practice networking, and to understand TCP and UDP connections.
> It is heavily inspired by the tool **nmap**.

## Overview

- It can find devices on your local network, and check for open ports
- It was built mainly for personal coding development, and network understanding
- It might be useful as a simple program, with easy-to-understand logic.

## Features

- Find Local IP — It finds your IP address in your local network.
- Find Devices — It can also find the IP addresses of devices connected to your network.
- Port Scanning — It can check if ports on the devices are open.
- User Friendly Logs — It can be used easily by first-time users.

## Tech Stack

- **Language:** Python
- **Libraries:** socket, threading, time, itertools, and scapy

## Getting Started

### Prerequisites

- Python 3.11.3
- Requires the ```scapy``` module

### Installation

```bash
git clone https://github.com/A-Proper-programmer/Python-Networking-Tool.git
cd Python-Networking-Tool

pip install scapy
```

### Usage

Explain how to run the project.

```bash
python Networker.py
```

## Project Structure

```text
Python-Networking-Tool/
├── Networker.py
├── README.md
└── LICENSE
```

## What I Learned

- I learnt how to use threading effectively, and scan ports.
- The ```port_scan()``` was threaded, resulting in a cascade of errors, when one occurred.
- I solved it easily by reducing the number of threads down to 3 (from 256).

## Future Improvements

- [ ] Try to find what service runs on each open port.
- [ ] Make a GUI version.
- [ ] Implement argument parsing through a shell.

## Disclaimer

This project is intended for educational purposes. Use it only on systems and data you own or have explicit permission to test.

## License

MIT LICENSE