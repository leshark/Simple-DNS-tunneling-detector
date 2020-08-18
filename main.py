import configparser
import csv
import json
import logging
import logging.handlers
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager, cpu_count

import dpkt

from checkers import shannon_entropy, check_hex, check_bad_symbols
from file_processors import get_pcaps, concat_cvs, mark_pcap_as_read
from whitelist import WhiteList

config = configparser.ConfigParser()
config.read('config.ini')

PCAP_DIR = config["files settings"]["pcap_dir"]
OUTPUT_DIR = config["files settings"]["output_dir"]
WHITELIST_PATH = config["files settings"]["whitelist"]

WHITELIST_ENABLED = config["files settings"].getboolean("enable_whitelist")

LOGGING_LEVEL = config["logging settings"]["logging_level"]
LOGGING_MODE = config["logging settings"]["logging_mode"]

OUT_LOG = os.path.join(OUTPUT_DIR, "out.log")
OUT_STATS = os.path.join(OUTPUT_DIR, "stats.json")
OUT_CSV = os.path.join(OUTPUT_DIR, "out.csv")

LOG_FORMAT = '%(asctime)s:%(levelname)s:%(lineno)d:%(message)s'

if LOGGING_MODE == "file":
    logging.basicConfig(filename=OUT_LOG, level=LOGGING_LEVEL, format=LOG_FORMAT)
elif LOGGING_MODE == "stdout":
    logging.basicConfig(stream=sys.stdout, level=LOGGING_LEVEL, format=LOG_FORMAT)

SESION_STATS = {}


def compute_stats(results):
    total_packets = 0
    total_malicious_packets = 0
    for vals in results:
        filename = vals[0].rsplit(os.sep, maxsplit=1)[1]
        SESION_STATS[filename] = {"packets_count": vals[1], "malicious_packets_count": vals[2]}
        total_packets += vals[1]
        total_malicious_packets += vals[2]
    SESION_STATS["total_packets"] = total_packets
    SESION_STATS["total_malicious_packets"] = total_malicious_packets


def process_pcap(pcap_file, q):
    total_packets = 0
    malicious_packets = 0
    pcap_filename = pcap_file.rsplit(os.sep, maxsplit=1)[1]

    if WHITELIST_ENABLED:
        whitelist = WhiteList(WHITELIST_PATH)

    # enable logging from different processes
    qh = logging.handlers.QueueHandler(q)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(qh)

    temp_csv = os.path.join(OUTPUT_DIR, "temp_" + pcap_filename + ".csv")
    with open(pcap_file, "rb") as dump, open(temp_csv, 'a') as csvfile:

        csv_writer = csv.writer(csvfile, delimiter='|', quotechar='^', quoting=csv.QUOTE_MINIMAL)
        dump = dpkt.pcap.Reader(dump)
        for ts, buf in dump:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            udp = ip.data

            try:
                dns = dpkt.dns.DNS(udp.data)

                # dns packet has multiple qnames in rare cases
                for qname in dns.qd:

                    # whitelist check
                    if WHITELIST_ENABLED and whitelist.check_domain_in_whitelist(qname.name):
                        # skipping domain {qname.name} as it is presented in whitelist
                        continue

                    # label length check
                    if any(len(name) > 40 for name in qname.name.split(".")):
                        malicious_packets += 1
                        csv_writer.writerow(
                            [pcap_filename, total_packets + 1, "high", "packet label length too high"]
                        )
                        break

                    # bad symbols check
                    if check_bad_symbols(qname.name):
                        malicious_packets += 1
                        csv_writer.writerow(
                            [pcap_filename, total_packets + 1, "high", "rare symbols detected"]
                        )
                        break

                    # entropy check
                    en = shannon_entropy(qname.name)
                    if en > 4.5:
                        malicious_packets += 1
                        csv_writer.writerow(
                            [pcap_filename, total_packets + 1, "high", "high entropy detected"]
                        )
                        break

                    # hex check
                    if check_hex(qname.name, 20):
                        malicious_packets += 1
                        csv_writer.writerow(
                            [pcap_filename, total_packets + 1, "medium", "hex encoding detected"]
                        )
                        break

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                # packet is probably malformed so ignore it
                continue
            except UnicodeDecodeError:
                # save as pcap_name, packet_number, probability(100%, high, medium, low)
                csv_writer.writerow(
                    [pcap_filename, total_packets + 1, "100%", "not utf-8 symbols detected"]
                )
                malicious_packets += 1
            finally:
                total_packets += 1
    logging.info("{} analysis finished. Total malicious  packets found: {}".format(pcap_filename, malicious_packets))
    mark_pcap_as_read(pcap_file)
    return pcap_file, total_packets, malicious_packets


def main():
    g_start = time.time()

    logging.debug("Started pcap parsing")

    pcaps = get_pcaps(PCAP_DIR)

    # start with N workers for N task unless this exceeds current machine cpu count
    with ProcessPoolExecutor(max_workers=len(pcaps) if cpu_count() >= len(pcaps) else cpu_count()) as executor:
        futures = []
        queue = Manager().Queue(-1)
        for pcap in pcaps:
            futures.append(executor.submit(process_pcap, pcap, queue))

    logging.debug("all pcap files parsed, computing statistics...")

    SESION_STATS["total_time"] = round(time.time() - g_start, 3)

    # wait fo all tasks to complete and then compute statistics
    compute_stats((future.result() for future in as_completed(futures)))

    SESION_STATS["packets_per_second"] = SESION_STATS["total_packets"] // SESION_STATS["total_time"]

    with open(OUT_STATS, "w") as stats:
        json.dump(SESION_STATS, stats, indent=4, sort_keys=True)

    logging.debug("statistics done, merging csv files...")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Job manually stopped, cleaning temp data...")
    except Exception as e:
        print("Exception occurred, see output log for details")
        logging.exception(e)
    finally:
        concat_cvs(OUT_CSV, OUTPUT_DIR)
        logging.info("Merging done, temp data cleaned successfully, job finished")
