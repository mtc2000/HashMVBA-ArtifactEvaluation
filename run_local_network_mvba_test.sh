#!/bin/bash

# usage:
# bash run_local_newwork_mvba_test.sh \
# scale_N \
# adversory_f \
# batch_size_B \
# repeating_count_K \
# warmup_count_C \
# protocol_P

# valid protocols are:
# hmvba
# dumbomvbastar
# finmvba

killall --quiet python3

if [[ "$6" == *"dumbo"* ]]; then
    echo "prepare keys"
    python3 run_trusted_key_gen.py --N $1 --f $2
    echo "key generation completed"
fi

mkdir -p verbose_log log

i=0
while [ "$i" -lt $1 ]; do
    echo "start node $i..."
    /usr/bin/time -v \
        python3 run_socket_mvba_node.py \
        --sid 'sidA' \
        --id $i \
        --N $1 \
        --f $2 \
        --B $3 \
        --P $6 \
        --D True \
        --O True \
        --K $4 \
        --C $5 \
        > verbose_log/$i.stdout.log \
        2> verbose_log/$i.stderr.log &
    i=$(( i + 1 ))
done

echo logs can be found later in log/ and verbose_log/ when the protocol completes execution
echo each execution takes at least 15 seconds, a hard-coded delay to sync up nodes
echo be patient ":)"
