# packet-sniffer

Packet sniffer is a program where packets of data flowing across the network are detected and observed. In this project, a sniffer is implemented in Python that reads packets from the raw socket and categorizes them based on protocols, namely IP, TCP, UDP, DNS, ICMP, HTTP, HTTPS and QUIC. The sniffer counts packets of each of the aforementioned protocols. The program runs for 30 seconds and then exits  gracefully. The program was written on Ubuntu 16.04 LTS operating system.

## Command to compile and execute the Packet-Sniffer

Open a new terminal and execute the below command to run the Sniffer.

```
sudo python3 packet-sniffer.py
```

## Packages and Dependencies

Below are the packages used to build the Sniffer.
 - "socket"
 - "sys"
 - "time"
 - "csv"
 - "struct"

## Experiments

The following experiments were performed to understand how raw socket interface and packet header parsing works.

- Exp 1: In this experiment, you first play any YouTube video at highest resolution possible in a browser. Once video starts playing, run your tool. Once your tool exits itself after 30 seconds, you will get an output .csv file.
- Exp 2: In this experiment, first run your tool. Then open a browser, go to YouTube website and quickly click on any video. Let this video play until the tool exits. Once your tool exits itself after 30 seconds, you will get an output .csv file.
- Exp 3: In this experiment, run your tool. Then open a browser and randomly search stuff on google and open different websites until the tool exits. Once your tool exits itself after 30 seconds, you will get an output .csv file.
 