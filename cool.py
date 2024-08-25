import argparse
import os
import subprocess
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


# Setup logging
logging.basicConfig(filename='script_output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Configurable settings
MAX_WORKERS = 12
TIMEOUT = 10


def run_paramspider(domain, output_dir):
    output_file = os.path.join(output_dir, f"{domain}-params.txt")
    command = ["paramspider", "--domain", domain, "-o", output_file, "-s", "100"]
    try:
        logging.info(f"Running ParamSpider for {domain}")
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info(f"ParamSpider completed for {domain}")
        return output_file
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running ParamSpider for {domain}: {e}")
        return None


def test_lfi(domain, param_file, output_dir):
    output_file = os.path.join(output_dir, f"{domain}_lfi.csv")
    with open(param_file) as f:
        params = f.read().splitlines()
    for param in params:
        url = f"{domain}?{param}=FUZZ"
        command = [
            "ffuf",
            "-u",
            url,
            "-w",
            "lfi.txt",
            "-c",
            "-mr",
            "root:",
            "-v",
            "-o",
            output_file,
            "-of",
            "csv",
            "-t",
            "50",
            "-p",
            "10"
        ]
        try:
            logging.info(f"Running ffuf for {url}")
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logging.info(f"ffuf completed for {url}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error running ffuf for {url}: {e}")


def filter_results(results_dir, output_file):
    try:
        with open(output_file, 'w') as outfile:
            for filename in os.listdir(results_dir):
                if filename.endswith("_lfi.csv"):
                    filepath = os.path.join(results_dir, filename)
                    with open(filepath) as f:
                        for line in f:
                            if "root:" in line:
                                outfile.write(line.split(',')[0] + '\n')
        logging.info(f"Filtered results saved to {output_file}")
    except Exception as e:
        logging.error(f"Error filtering results: {e}")


def confirm_vulnerability(url):
    try:
        response = requests.get(url, timeout=TIMEOUT)
        if response.status_code == 200:
            return True
        else:
            return False
    except Exception as e:
        logging.error(f"Error confirming vulnerability: {e}")
        return False


def main(domains_file, output_file):
    param_dir = "param_files"
    lfi_dir = "lfi_results"
    os.makedirs(param_dir, exist_ok=True)
    os.makedirs(lfi_dir, exist_ok=True)


    with open(domains_file) as f:
        domains = f.read().splitlines()


    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        param_files = list(executor.map(lambda d: run_paramspider(d, param_dir), domains))


    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_lfi, d, pf, lfi_dir) for d, pf in zip(domains, param_files)]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error during LFI testing: {e}")


    filter_results(lfi_dir, output_file)


    with open(output_file) as f:
        vulnerabilities = f.read().splitlines()
    confirmed_vulnerabilities = []
    for vulnerability in vulnerabilities:
        if confirm_vulnerability(vulnerability):
            confirmed_vulnerabilities.append(vulnerability)


    with open(output_file, 'w') as f:
        for vulnerability in confirmed_vulnerabilities:
            f.write(vulnerability + '\n')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate LFI testing.")
    parser.add_argument("domains_file", help="File containing list of domains")
    parser.add_argument("output_file", help="File to save valid LFI findings")
    args = parser.parse_args()


    main(args.domains_file, args.output_file)
