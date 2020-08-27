import configparser
import csv
import json
import logging.handlers
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from logging.config import fileConfig
from multiprocessing import cpu_count

import dpkt

from dns_tunneling_detector.checkers import shannon_entropy, check_hex, check_bad_symbols
from dns_tunneling_detector.file_processors import get_pcaps, concat_csv, delete_temp_csv, mark_pcap_as_read
from dns_tunneling_detector.whitelist import WhiteList

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'config.ini'))

# read logger configuration from file
fileConfig(os.path.join(os.path.dirname(__file__), 'logging_config.ini'))
logger = logging.getLogger()

PCAP_DIR = config["files settings"]["pcap_dir"]
OUTPUT_DIR = config["files settings"]["output_dir"]
WHITELIST_PATH = config["whitelist settings"]["whitelist"]

IGNORE_PARSED_PCAPS = config["files settings"].getboolean("ignore_parsed_pcaps")
WHITELIST_ENABLED = config["whitelist settings"].getboolean("enable_whitelist")

OUT_LOG = os.path.join(OUTPUT_DIR, "out.log")
OUT_STATS = os.path.join(OUTPUT_DIR, "stats.json")
OUT_CSV = os.path.join(OUTPUT_DIR, "out.csv")

SESSION_STATS = {}


def compute_stats(results):
    total_packets = 0
    total_malicious_packets = 0
    for pcap_path, total_pcap_packets, mal_packets in results:
        filename = os.path.split(pcap_path)[1]
        SESSION_STATS[filename] = {"packets_count": total_pcap_packets, "malicious_packets_count": mal_packets}
        total_packets += total_pcap_packets
        total_malicious_packets += mal_packets
    SESSION_STATS["total_packets"] = total_packets
    SESSION_STATS["total_malicious_packets"] = total_malicious_packets


def process_pcap(pcap_file):
    total_packets = 0
    malicious_packets = 0
    pcap_filename = os.path.split(pcap_file)[1]

    whitelist = WhiteList(WHITELIST_PATH) if WHITELIST_ENABLED else None

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
                    if whitelist and whitelist.check_domain_in_whitelist(qname.name):
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
                csv_writer.writerow(
                    [pcap_filename, total_packets + 1, "100%", "not utf-8 symbols detected"]
                )
                malicious_packets += 1
            finally:
                total_packets += 1
    logger.info("{} analysis finished. Total malicious  packets found: {}".format(pcap_filename, malicious_packets))
    mark_pcap_as_read(pcap_file)
    return pcap_file, total_packets, malicious_packets


def main():
    g_start = time.monotonic()

    logger.debug("Started pcap parsing")

    pcaps = get_pcaps(PCAP_DIR, ignore_parsed=IGNORE_PARSED_PCAPS)
    if not pcaps:
        raise UserWarning("no traffic files found, set ignore_parsed_pcaps in config to false if you want to analyze "
                          "already parsed files")

    # start with N workers for N task unless this exceeds current machine cpu count
    with ProcessPoolExecutor(max_workers=len(pcaps) if cpu_count() >= len(pcaps) else cpu_count()) as executor:
        futures = []
        for pcap in pcaps:
            futures.append(executor.submit(process_pcap, pcap))

    logger.debug("all pcap files parsed, computing statistics...")

    SESSION_STATS["total_time"] = round(time.monotonic() - g_start, 3)

    # wait fo all tasks to complete and then compute statistics
    compute_stats((future.result() for future in as_completed(futures)))

    SESSION_STATS["packets_per_second"] = SESSION_STATS["total_packets"] // SESSION_STATS["total_time"]

    with open(OUT_STATS, "w") as stats:
        json.dump(SESSION_STATS, stats, indent=4, sort_keys=True)

    logger.debug("statistics done, merging csv files...")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Job manually stopped, cleaning temp data...")
    except Exception as e:
        print("Exception occurred, see output log for details")
        logger.exception(e)
    finally:
        concat_csv(OUT_CSV, OUTPUT_DIR)
        logger.info("Merging done")
        delete_temp_csv(OUTPUT_DIR)
        logger.info("Temp data cleaned successfully, job finished")
