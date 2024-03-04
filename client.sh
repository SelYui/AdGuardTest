#!/bin/bash
for k in {1..10}
do
    for i in {1..10}
    do
        curl https://localhost:4433/path$i --cacert cert.pem --key key.pem -k --header "User-Agent: test$i" &
    done
    sleep 0.01
done
wait




