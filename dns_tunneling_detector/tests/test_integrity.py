import csv
import json
import logging
import os
import unittest

import jsonschema

from dns_tunneling_detector.file_processors import get_pcaps, concat_csv, delete_temp_csv

JSON_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "clean.pcap": {
            "type": "object",
            "properties": {
                "malicious_packets_count": {
                    "type": "integer"
                },
                "packets_count": {
                    "type": "integer"
                }
            },
            "required": [
                "malicious_packets_count",
                "packets_count"
            ]
        },
        "dnsex_dump.pcap": {
            "type": "object",
            "properties": {
                "malicious_packets_count": {
                    "type": "integer"
                },
                "packets_count": {
                    "type": "integer"
                }
            },
            "required": [
                "malicious_packets_count",
                "packets_count"
            ]
        },
        "iodintet_dump2.pcap": {
            "type": "object",
            "properties": {
                "malicious_packets_count": {
                    "type": "integer"
                },
                "packets_count": {
                    "type": "integer"
                }
            },
            "required": [
                "malicious_packets_count",
                "packets_count"
            ]
        },
        "packets_per_second": {
            "type": "number"
        },
        "total_malicious_packets": {
            "type": "integer"
        },
        "total_packets": {
            "type": "integer"
        },
        "total_time": {
            "type": "number"
        }
    },
    "required": [
        "clean.pcap",
        "dnsex_dump.pcap",
        "iodintet_dump2.pcap",
        "packets_per_second",
        "total_malicious_packets",
        "total_packets",
        "total_time"
    ]
}


class TestMain(unittest.TestCase):
    stats_path = os.path.join("example_output", "stats.json")
    csv_path = os.path.join("example_output", "out.csv")
    log_path = os.path.join("example_output", "out.log")

    pcap_dir = "pcap_examples"
    output_dir = "example_output"

    @classmethod
    def setUpClass(cls):
        # we need to change directory before importing main in order to relative file paths to work
        os.chdir("dns_tunneling_detector")
        from dns_tunneling_detector.main import main

        # check that input and output dirs exist
        if not os.path.exists(cls.pcap_dir) or not os.path.exists(cls.output_dir):
            raise unittest.SkipTest("Tests were skipped as no input/output directories presented")

        main()
        concat_csv(cls.csv_path, cls.output_dir)
        delete_temp_csv(cls.output_dir)

    def test_output_files_exist(self):
        """assert files exist in output folder"""
        self.assertTrue(os.path.exists(self.csv_path))
        self.assertTrue(os.path.exists(self.stats_path))
        self.assertTrue(os.path.exists(self.log_path))

    def test_csv_file_has_proper_format(self):
        with open(self.csv_path) as out_csv:
            csv_reader = csv.reader(out_csv, delimiter='|', quotechar='^', quoting=csv.QUOTE_MINIMAL)
            first_row = next(iter(csv_reader))
            self.assertTrue(len(first_row) == 4)

    def test_stats_file_has_proper_format(self):
        with open(self.stats_path) as out_stats:
            stats = json.load(out_stats)
            jsonschema.validate(stats, JSON_SCHEMA)
            if stats["clean.pcap"]["malicious_packets_count"] != 0:
                print("There should be no dns tunnels detected in clean.pcap!")

    @classmethod
    def tearDownClass(cls):
        # remove _parsed pcap postfix after main() run
        pcaps = get_pcaps(cls.pcap_dir, ignore_parsed=False)
        for pcap in pcaps:
            path, filename = os.path.split(pcap)
            filename, ext = filename.rsplit(".", maxsplit=1)
            os.rename(pcap, os.path.join(path, filename.replace("_parsed", "") + "." + ext))

        os.remove(cls.csv_path)
        os.remove(cls.stats_path)

        # release file handler
        logging.shutdown()
        os.remove(cls.log_path)


if __name__ == '__main__':
    unittest.main()
