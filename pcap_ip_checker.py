import argparse
import subprocess
import regex
import pandas as pd
import requests
from requests.exceptions import ConnectionError
import sys

from tqdm import tqdm

parser = argparse.ArgumentParser()

input_file = parser.add_argument("-i", "--input-file", help="Input file name (must be in PCAP/PCAPNG format)", required=True)
output_file = parser.add_argument("-o", "--output-file", help="Output file name (must be in CSV format", required=True)

args = parser.parse_args()

input_file = open(args.input_file, "r")
output_file = open(args.output_file, "w")


# headers are needed for https (sites with SSL)
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
}


def get_url_response(url):
    try:
        response = requests.get(url, headers=REQUEST_HEADERS).json()
        return response
    except ConnectionError as e:
        print("Connection Error: " + url)
        print(e)
        return []


def append_data_to_dict(attribute, input_data, output_dict):
    if attribute in input_data:
        output_dict[attribute] = input_data[attribute]
    else:
        output_dict[attribute] = ""


def main():
    process_capture_output = subprocess.check_output(
        ["tshark", "-r", input_file, "-q", "-z", "conv,ip"]
    )

    # Find the field content via regex
    ip_addresses = sorted(
        list(
            set(
                regex.findall(
                    "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", str(process_capture_output)
                )
            )
        )
    )

    response_data = []

    print("Performing reverse lookup of IPs identified in packet capture:")
    
    for ip_address in tqdm(ip_addresses):
        single_response = {'given_ip': ip_address}
        api_url = "https://api.shodan.io/shodan/host/{}?key=[insert-Shodan-API-key-here]&minify=true".format(
            ip_address
        )
        response = get_url_response(api_url)

        list_of_attributes = ["org", "ip_str", "country_name"]

        for attribute in list_of_attributes:
            append_data_to_dict(attribute, response, single_response)

        response_data.append(single_response)

    data = pd.DataFrame(response_data)

    data.to_csv(output_file)


if __name__ == "__main__":
    input_file = args.input_file
    output_file = args.output_file
    main()
