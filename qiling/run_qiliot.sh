#!/bin/bash
cd /home/qiling/
python qiliot.py -b 9b4dfaca873961174ba935fddaf696145afe7bbf5734509f95feb54f3584fd9a -r ../rootfs -c 0 &
PYTHON_PID=$!

while true; do
    NUM_PROCS=$(ps -e --no-headers | wc -l)
    # Substract 3 because of the process ps, wc and the sub_shell
    NUM_PROCS=$((NUM_PROCS - 3))
    echo "Current Numbers of processes: $NUM_PROCS"

    if [ $NUM_PROCS -lt 2 ]; then
        echo "Less than 2 Processes are running. Stop the script"
        break
    fi
    sleep 5
done
kill $PYTHON_PID 2>/dev/null || true
echo "Exit emulation"

# OUTPUT FROM: echo $(ps -e --no-headers | tee /dev/stderr | wc -l)
#
# qiling_1  |       1 ?        00:00:00 run_qiliot.sh
# qiling_1  |       7 ?        00:00:00 python         
# qiling_1  |       9 ?        00:00:00 run_qiliot.sh  # sub_shell
# qiling_1  |      10 ?        00:00:00 ps
# qiling_1  |      11 ?        00:00:00 tee            # ignore this 
# qiling_1  |      12 ?        00:00:00 wc
