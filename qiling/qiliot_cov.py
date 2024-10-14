import os
import fcntl
from qiling.extensions.coverage.formats.drcov import QlDrCoverage

class QiliotCov(QlDrCoverage):
    '''
    Qiliot coverage build on Qiling coverage. 
    This enables to have a coverage file included every created process.
    '''
    
    def __init__(self, ql, filename):
        '''
        Initialize Qiliot coverage with extanded attributes.
        '''
        super().__init__(ql)
        self.filename = filename
        self._init_file()


    def _init_file(self) -> None:
        '''
        Internal function to initalize the coverage file.
        '''
        with open(self.filename, "wb"):
            pass


    def clear(self) -> None:
        '''
        Clear basic blocks.
        '''
        self.basic_blocks.clear()


    def write_header(self, cov) -> None:
        '''
        Writes the header for the coverage file.
        
        Args: 
            cov: Coverage file which need to be updated.
        '''
        cov.write(f"DRCOV VERSION: {self.drcov_version}\n".encode())
        cov.write(f"DRCOV FLAVOR: {self.drcov_flavor}\n".encode())
        cov.write(f"Module Table: version {self.drcov_version}, count {len(self.ql.loader.images)}\n".encode())
        cov.write("Columns: id, base, end, entry, checksum, timestamp, path\n".encode())
        for mod_id, mod in enumerate(self. ql.loader.images):
            cov.write(f"{mod_id}, {mod.base}, {mod.end}, 0, 0, 0, {mod.path}\n".encode())
        cov.write("BB Table: 000000000 bbs\n".encode())


    def write_blocks(self) -> None:
        '''
        Write blocks into the coverage file.
        If there is already data, the BB Table and its length needs to be updated.
        '''
        # Open coverage file
        with open(self.filename, "rb+") as cov:
            fcntl.flock(cov.fileno(), fcntl.LOCK_EX)
            if cov.seek(0, os.SEEK_END) == 0:
                # Initalize header in empty file
                self.write_header(cov)
            # Write basic block into file
            for bb in self.basic_blocks:
                cov.write(bytes(bb))

            cov.seek(0, os.SEEK_SET)
            #header = cov.read(1000)
            while True:
                # Read the file to get needed information in header
                line = cov.readline()
                if not line:
                    raise Exception("Coverage file seems to be corrupted.")

                if  line.startswith(b"BB Table:"):
                    # Get the BasicBlock header, update length and write basic blocks into the file.
                    new_len = int(line[10:19]) + len(self.basic_blocks)
                    print(f"filename: {self.filename} Update length from {line[10:19]} to {new_len}", flush=True)
                    cov.seek(-len(line) + 10, os.SEEK_CUR)
                    cov.write(f"{new_len:09d}".encode())
                    break

            fcntl.flock(cov.fileno(), fcntl.LOCK_UN)