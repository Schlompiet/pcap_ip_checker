This Python script takes any `.pcap` (including `.pcapng`) file, analyses it with **tshark** to find IP conversations, performs a reverse lookup of all the IP addresses in the Shodan database and writes the main findings to a `.csv` file.

```
usage: Pcap_IP_checker.py [-h] -i INPUT_FILE -o OUTPUT_FILE

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_FILE, --input-file INPUT_FILE
                        Input file name (must be in PCAP/PCAPNG format)
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output file name (must be in CSV format
```

A progress bar will be shown and the output should look as follows when the action is complete:

```
Performing reverse lookup of IPs identified in packet capture:
100%|███████████████████████████████████████████| 42/42 [00:18<00:00,  2.28it/s]
```
