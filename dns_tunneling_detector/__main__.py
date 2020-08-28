import logging

from dns_tunneling_detector.file_processors import concat_csv, delete_temp_csv
from dns_tunneling_detector.main import main, OUT_CSV, OUTPUT_DIR

logger = logging.getLogger()

# check just for running with python __main__.py possibility
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
