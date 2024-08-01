FROM python:3.10

RUN apt-get update && apt-get install -y cmake patch \
	&& pip install qiling==1.4.6 pefile==2023.2.7

RUN mkdir /home/qiling/ && mkdir /home/logs/

COPY qiling/ /home/qiling/ 
COPY rootfs /home/rootfs

COPY qiling/run_qiliot.sh /home/qiling/
RUN chmod +x /home/qiling/run_qiliot.sh

RUN mknod /home/sda c 1 3 && \
 	mknod /home/mtd0 c 1 3 && \
 	chmod 666 /home/sda && \
 	chmod 666 /home/mtd0

COPY patches /home/patches
RUN patch /usr/local/lib/python3.10/site-packages/qiling/os/posix/syscall/unistd.py /home/patches/unistd.patch
RUN patch /usr/local/lib/python3.10/site-packages/qiling/os/posix/posix.py /home/patches/posix.patch