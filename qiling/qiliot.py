#!/usr/local/bin/python
from enum import Enum
import fcntl
import json
import os as sys_os
import argparse
from datetime import datetime
from qiling import Qiling
from qiling.const import *
from qiling.const import QL_VERBOSE
from functools import partial
from qiliot_cov import QiliotCov
import qiling.os.linux.map_syscall as lin

# Define absolute path
ABSOLUTE_PATH = sys_os.path.dirname(sys_os.path.abspath(__file__))

class IoctlCommands(Enum):
    BLKGETSIZE64 = 0x40041272
    MEMGETINFO = 0x40204d01
    MEMUNLOCK = 0x80084d06
    MEMERASE = 0x80084d02
    MEMWRITEOOB = 0xc00c4d03
    MEMLOCK = 0x80084d05

class MtdInfoUser:
    '''
    Initialize struct for mtd_type. Is utilzed for ioctl syscall with MEMGETINFO.
    Needed for MTD type = 4 (NANDFLASH)
    '''
    def __init__(self, type:int):
        self.type = type # Type 0 or Type 4
        self.flags = 0
        self.size = 100  # 1 MB in local_d4l
        self.erasesize = 50 # 0x1000 in local_d0
        self.writesize = 256
        self.oobsize = 64

class EraseInfoUser:
    '''
    Initialize struct for erase_info_user. Is utilzed for ioctl syscall with MEMUNLOCK and MEMERASE request.
    Needed for MTD type = 4 (NANDFLASH)
    '''
    def __init__(self, start, length):
        self.start = start
        self.length = length


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

    def log_syscall_with_id(self, ql: Qiling, address, size, *args, **kwargs) -> None:
        '''
        Hook on code level for tracking virtuall addresses of instructions and syscalls.
        
        Args:
            ql (Qiling): The Qiling emulator instance
            address: Current address
            size: Size of current instruction
            *args, **kwards: Additional and keyword argumentd 
        '''

        # Get the mips syscall table for translating ids into syscall function names
        mapper = lin.mips_syscall_table

        # Append every instruction address
        ins_address = hex(address)
        if ins_address not in self.instruction_addresses:
            self.instruction_addresses.append(ins_address)


        if ql.mem.read(address, size) == b'\x00\x00\x00\x0c':
            # In case of system call

            syscall_id = ql.arch.regs.read("v0") # stored syscall id
            syscall_name = mapper.get(syscall_id)
            # Create syscall element and append it for results file
            syscall_info = {
                "syscall_num": syscall_id,
                "syscall_name": syscall_name
            }
            if syscall_info not in self.syscalls:
                self.syscalls.append(syscall_info)


    def hook_fork(self, ql:Qiling, *args, **kwargs):
        '''
        Hook fork to set ql.os.child_processes to False for every child to prevent qiling to do os.exit()
        and to clear collected informations like coverage, instructions adresses and syscalls.
        
        Args:
            ql (Qiling): The Qiling emulator instance
            *args, **kwards: Additional and keyword argumentd
        '''

        # In case of childprocesses
        if ql.os.child_processes:
            # Clear collected informations in child cause parent will keep it
            self.cov.clear()
            self.instruction_addresses.clear()
            self.syscalls.clear()
            # Prevent qiliots child processes from running run_qiliot()
        # Prevent qiling doing os.exit()
        ql.os.child_processes = False

    
    def hook_ioctl(self, ql: Qiling , fd:int, request, pointer, mtd_type, *args, **kwargs):
        '''
        Hook ioctl to simulate request commands with MTD_NANDFLASH storage devices.
        Return successful operation and write needed values of structs onto the stack.
        
        Args:
            ql (Qiling): The Qiling emulator instance
            fd: Filedescriptor 
            request: Commands to operate with NANDFLASH decices. Like MEMGETINFO.
            pointer: current pointer
            mtd_type: type of the mtd device
            *args, **kwards: Additional and keyword argumentd
        
        Returns:
        int: Status code of the IOCTL operation (0 for success, -1 for error).
        '''

        if request == IoctlCommands.BLKGETSIZE64.value:
            # Write size for block devices onto stack. Value of 270008320 is 1026 x 0x40000
            # to trigger in AcidRain the fsync after every 1024 x 0x40000 write syscall
            ql.mem.write(pointer , ql.pack64(270008320))
            return 0x0
        elif request == IoctlCommands.MEMGETINFO.value:
            # Handle MEMGETINFO and write onto stack the mtd_info_user structure with values.
            mtd_info = MtdInfoUser(type=mtd_type)
            ql.mem.write(pointer, ql.pack8(mtd_info.type))
            ql.mem.write(pointer + 4, ql.pack32(mtd_info.flags))
            ql.mem.write(pointer + 8, ql.pack32(mtd_info.size))
            ql.mem.write(pointer + 12, ql.pack32(mtd_info.erasesize))
            ql.mem.write(pointer + 16, ql.pack32(mtd_info.writesize))
            ql.mem.write(pointer + 20, ql.pack32(mtd_info.oobsize))
            return 0x0
        elif request == IoctlCommands.MEMUNLOCK.value:
            # Handle MEMUNLOCK to unlock a device and write onto stack the erase_info_user struct
            # with informations where acidrain starts to erase the flash and the length
            erase_info_user = EraseInfoUser(20, 40)
            ql.mem.write(pointer, ql.pack32(erase_info_user.start))
            ql.mem.write(pointer, ql.pack32(erase_info_user.length))
            return 0x0
        elif request == IoctlCommands.MEMERASE.value:
            # Handle MEMERASE and write new section onto stack which acidrain trys to deletes next
            erase_info_user = EraseInfoUser(80, 250)
            ql.mem.write(pointer, ql.pack32(erase_info_user.start))
            ql.mem.write(pointer, ql.pack32(erase_info_user.length))
            return 0x0
        elif request == IoctlCommands.MEMWRITEOOB.value:
            return 0x0
        elif request == IoctlCommands.MEMLOCK.value:
            return 0x0
        return -0x1

    def hook_reboot(self, ql:Qiling, magic:int, magic2: int , cmd:int, *arg):
        return 0x0

    def hook_execve(self, ql: Qiling, filename, argv, envp, **kwargs):
        '''
        Hook for execve in AcidRain. AcidRain uses this syscall to execute the reboot binary.
        This hook simulates the action by doing nothing and returning 0x0
        
        Args:
            ql (Qiling): The Qiling emulator instance
            filename: Name of Binary which should be executed
            *args, **kwards: Additional and keyword argumentd
        
        Returns:
        int: Always status code 0 for success
        
        (Note: Qiling will emulate the executed binary, this means informations will be appear in logs and results.)
        '''
        ql.log.info(f"Simulates execve: {ql.os.utils.read_cstring(filename)}")
        return 0x0

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

    def generate_result_file(self):
        '''
        Generate resultfile for current emulation. Each process will write its result into the file.
        '''
        # Unique path for each emulation
        result_path = f"{sys_os.path.dirname(ABSOLUTE_PATH)}/results/{self.timestamp}_{self.binary_name}/"
        self.result_path = result_path
        result_file_path = f"{result_path}results_{self.mtd_type}_{self.root}.json"


        with open(result_file_path, 'r+') as file:
            fcntl.flock(file.fileno(), fcntl.LOCK_EX)
            try:
                # Load content of the result file
                existing_data = json.load(file)
            except json.JSONDecodeError:
                # If content is empty, set basic structure
                existing_data = {"syscalls": [], "instruction_addresses": [], "blocks": []}

            # Expand instruction address only in case, if its not already in the result file
            for address in self.instruction_addresses:
                if address not in existing_data["instruction_addresses"]:
                    existing_data["instruction_addresses"].append(address)
            # Expand syscall only when it does not exist in result file
            for syscall in self.syscalls:
                if syscall not in existing_data["syscalls"]:
                    existing_data["syscalls"].append(syscall)

            # Write content back to result file and unlock
            file.seek(0)
            json.dump(existing_data, file, indent=4)
            file.truncate()
            fcntl.flock(file.fileno(), fcntl.LOCK_UN)

    def write_result_file_for_each_process(self):
        '''
        Creates result file for each process.
        '''
        # Get current process id and current timestamp
        pid = sys_os.getpid()
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        result_file = f"result_{pid}_{timestamp}.json"

        with open(self.result_path + result_file, 'a+') as file:
            fcntl.flock(file.fileno(), fcntl.LOCK_EX)

            try:
                # Load content of result file
                existing_data = json.load(file)
            except json.JSONDecodeError:
                # If content is empty, set basic structure
                existing_data = {"blocks":[],"syscalls":[], "instruction_addresses": []}

            # Expand data
            existing_data["syscalls"].extend(self.syscalls)
            existing_data["instruction_addresses"].extend(self.instruction_addresses)
            #existing_data.get("blocks").extend(addressbook_blocks.values())

            # Write result into file
            json.dump(existing_data, file, indent=4)
            fcntl.flock(file.fileno(), fcntl.LOCK_UN)
            
    #####################################################################
    ####################  INITIALIZE EMULATION  #########################
    #####################################################################

    def run_qiliot(self, path: list, rootfs: str, emucase: int):
        '''
        Prepare everything which is relevant for emulating AcidRain with Qiling.
        Args:
            path: List of binarys which can be emulated by qiling
            rootfs: Path to root filesystem for the emulated binary
            emucase: Describes which case should be remulatet.
                AcidRain has root permissons or not.
                AcidRain operates with mtd_type = 4 (NANDFLASH) and ioctl syscalls
                         or operates with write syscall when type equals:
                                      mtd_type = 0 (MTD_ABSENT)
                                      mtd_type = 1 (MTD_RAM)
                                      mtd_type = 2 (MTD_ROM)
                                      mtd_type = 3 (MTD_NORFLASH)
                                      mtd_type = 6 (MTD_DATAFLASH)
                                      mtd_type = 7 (MTD_UBIVOLUME)
                                      mtd_type = 8 (MTD_MLCNANFLASH)
        '''

        # Set attributes for AcidRain cases.
        match emucase:
            case 0:
                self.root = True
                self.mtd_type = 4
            case 1: 
                self.root = True
                self.mtd_type = 0
            case 2:
                self.root = False
                self.mtd_type = 4
            case 3:
                self.root = False
                self.mtd_type = 0

        # Create directory for resutls of current emulation
        result_path = f"{sys_os.path.dirname(ABSOLUTE_PATH)}/results/{self.timestamp}_{self.binary_name}/"
        sys_os.makedirs(result_path, exist_ok=True)
        
        # create result file for whole emulation
        result_path = f"{result_path}results_{self.mtd_type}_{self.root}.json"
        open(result_path, 'w').close()

                
        # Log file name for current emulation
        logfile_name = f"{sys_os.path.dirname(ABSOLUTE_PATH)}/logs/{self.timestamp}.log"
        # Init Qiling
        ql = Qiling(path, rootfs=rootfs, log_file=logfile_name)
        # Set log level
        ql.verbose = self.get_logging_level()
        

        # Set up everything relevant for root
        if self.root:
            ql.os.uid = 0
            ql.os.gid = 0
            ql.os.euid = 0
            ql.os.egid = 0
            ql.os.root = True
                
        # Dynamically add files to the filesystem
        image_path = f"{sys_os.path.dirname(ABSOLUTE_PATH)}"
        ql.add_fs_mapper("/dev/null", "/dev/null")
        ql.add_fs_mapper("/dev/sda", f"{image_path}/sda")
        ql.add_fs_mapper("/dev/mtd0", f"{image_path}/mtd0")

        # Add hooks
        ql.hook_code(self.log_syscall_with_id)
        custom_hook = partial(self.hook_ioctl, mtd_type=self.mtd_type)
        custom_hook.__name__ = "hook_ioctl"
        ql.os.set_syscall('ioctl', custom_hook, QL_INTERCEPT.CALL)
        ql.os.set_syscall("fork", self.hook_fork, QL_INTERCEPT.EXIT)
        ql.os.set_syscall('execve', self.hook_execve, QL_INTERCEPT.CALL)
        ql.os.set_syscall('reboot', self.hook_reboot, QL_INTERCEPT.CALL)
        


        # Set up ervything for Coverage
        coverage_file = f"{sys_os.path.dirname(ABSOLUTE_PATH)}/coverage/{self.root}_{self.mtd_type}.cov"
        qiliot_cov = QiliotCov(ql, coverage_file)
        self.cov = qiliot_cov

        # Activate hook on blocks for coverage tracking
        qiliot_cov.activate()
        ql.run()
        # Deactivate hook on blocks for coverage
        qiliot_cov.deactivate()
        # Write and update blocks in coverage file
        qiliot_cov.write_blocks()
        # Generate complete result file after emulation
        self.generate_result_file()
        
        # Generate result file after each process
        self.write_result_file_for_each_process()

def parse_args() -> object:
    '''
    Parse argmuments which are relevant for Qiliot.
    '''
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-b', '--binary', required=True, type=str, metavar="PATH TO BINARY")  # noqa
    parser.add_argument('-r', '--rootfs', required=True, type=str, metavar="PATH TO ROOTFS DIR")  # noqa
    parser.add_argument('-c', '--emucase', required=True, type=int, metavar="EMULATION CASE", default="INFO", choices=[0, 1, 2, 3])
    parser.add_argument('-l', '--loglevel', required=False, type=str, metavar="LOGLEVEL", default="INFO", choices=["DISABLED", "OFF", "DEFAULT", "DEBUG", "DISASM", "DUMP"]) # noqa

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")

    # Init Qiliot
    qiliot = Qiliot(args.binary, args.rootfs, args.loglevel, timestamp)
    qiliot.run_qiliot([qiliot.binary_path], qiliot.rootfs_path, args.emucase)
