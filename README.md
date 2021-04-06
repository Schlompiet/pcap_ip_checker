This is a simple Python script that takes any `.pcap` (or `.pcapng`) file, analyses it with **tshark** to find IP conversations, performs a reverse lookup of all the IP addresses in the Shodan database and writes the main findings to a `.csv` file.

To use it, run the following command in your terminal/command prompt, where the **input_file** is the name of the pcap file and the **output_file** is the name you want to assign to your output file. Include the file extensions for best results.

```
python pcap_ip_checker.py [input_file].pcap [output_file].csv
```

or 

```
python3 pcap_ip_checker.py [input_file].pcap [output_file].csv
```

Dependencies: 
* Python
* The Python package installer [pip](https://pypi.org/project/pip/)
* Python regex module (listed in `requirements.txt` and installed with pip)
* A valid Shodan API key
