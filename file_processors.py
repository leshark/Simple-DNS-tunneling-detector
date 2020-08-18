import glob
import os


def get_pcaps(directory):
    return glob.glob(os.path.join(directory, "*.pcap*"))


def get_temp_csv(directory):
    return glob.glob(os.path.join(directory, "temp*.csv"))


def concat_cvs(csv_path, temp_csv_directory):
    with open(csv_path, "a") as res_csv:
        for temp_csv in get_temp_csv(temp_csv_directory):
            temp_file = open(temp_csv)
            for line in temp_file:
                res_csv.write(line)
            temp_file.close()
            # remove temporary csv file
            os.remove(temp_csv)


def mark_pcap_as_read(pcap_file):
    path, filename = pcap_file.rsplit(os.sep, maxsplit=1)
    filename, ext = filename.rsplit(".", maxsplit=1)
    os.rename(pcap_file, os.path.join(path, filename + "_parsed." + ext))
