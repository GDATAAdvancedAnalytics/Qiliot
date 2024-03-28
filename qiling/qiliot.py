#!/usr/local/bin/python
import os as sys_os
import argparse
from datetime import datetime
from qiling import Qiling
from qiling.const import QL_VERBOSE

# Define absolute path
ABSOLUTE_PATH = sys_os.path.dirname(sys_os.path.abspath(__file__))


class Qiliot:
    '''
    Initialize Qiliot emulate Wrapper for AcidRain emulation with Qiliot.
    '''
    def __init__(self, binary_path: str, rootfs_path: str, log_level: str, timestamp: str):
        self.binary_path = binary_path
        self.binary_name = self.extract_binary_name_from_path(binary_path)
        self.rootfs_path = rootfs_path
        self.log_level = log_level
        self.timestamp = timestamp
        self.syscalls = []
        self.instruction_addresses = []
        self.mtd_type = 0
        self.root = 0

    #####################################################################
    #####################    HELPING METHODS   ##########################
    #####################################################################

    def get_logging_level(self) -> QL_VERBOSE:
        '''
        Return the wanted log level for qiling.
        '''
        match self.log_level:
            case "DEBUG":
                return QL_VERBOSE.DEBUG
            case "DISABLED":
                return QL_VERBOSE.DISABLED
            case "OFF":
                return QL_VERBOSE.OFF
            case "DEFAULT":
                return QL_VERBOSE.DEFAULT
            case "DISASM":
                return QL_VERBOSE.DISASM
            case "DUMP":
                return QL_VERBOSE.DUMP
            case _:
                return QL_VERBOSE.DEFAULT

    def extract_binary_name_from_path(self, binary_path: str) -> str:
        '''
        Extract binary name from binary path.
        '''
        bin_name_index = binary_path.rfind("/")
        binary_name = binary_path[bin_name_index+1:] if bin_name_index != -1 else binary_path
        return binary_name

    #####################################################################
    ####################  INITIALIZE EMULATION  #########################
    #####################################################################

    def run_qiliot(self, path: list, rootfs: str):
        '''
        Prepare everything which is relevant for emulating AcidRain with Qiling.
        Args:
            path: List of binarys which can be emulated by qiling
            rootfs: Path to root filesystem for the emulated binary
        '''
        # Log file name for current emulation
        logfile_name = f"{sys_os.path.dirname(ABSOLUTE_PATH)}/logs/{self.timestamp}.log"
        # Init Qiling
        ql = Qiling(path, rootfs=rootfs, log_file=logfile_name)
        # Set log level
        ql.verbose = self.get_logging_level()

        # Dynamically add files to the filesystem
        image_path = f"{sys_os.path.dirname(ABSOLUTE_PATH)}"
        ql.add_fs_mapper("/dev/null", "/dev/null")
        ql.add_fs_mapper("/dev/sda", f"{image_path}/sda")
        ql.add_fs_mapper("/dev/mtd0", f"{image_path}/mtd0")

        ql.run()


def parse_args() -> object:
    '''
    Parse argmuments which are relevant for Qiliot.
    '''
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-b', '--binary', required=True, type=str, metavar="PATH TO BINARY")  # noqa
    parser.add_argument('-r', '--rootfs', required=True, type=str, metavar="PATH TO ROOTFS DIR")  # noqa
    parser.add_argument('-l', '--loglevel', required=False, type=str, metavar="LOGLEVEL", default="INFO", choices=["DISABLED", "OFF", "DEFAULT", "DEBUG", "DISASM", "DUMP"]) # noqa

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")

    # Init Qiliot
    qiliot = Qiliot(args.binary, args.rootfs, args.loglevel, timestamp)
    qiliot.run_qiliot([qiliot.binary_path], qiliot.rootfs_path)
