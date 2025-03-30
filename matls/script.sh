#!/bin/bash

PID_FILE="santls_pids.txt"
CLIENT_INPUT_FILE="largefile"

SERVER_START_PORT=5544

if [ "$1" == "start" ]; then

    ./matls server $SERVER_START_PORT server.crt server.key logs/server_.out > logs/stdout_server.log & 
    SERVER_PID=$!
    echo $SERVER_PID > "$PID_FILE"

    start_port=3000
    prev_port=$SERVER_START_PORT

    for i in $(seq 0 10); do
        sleep 1
        current_port=$((start_port + i))
        echo "Starting middlebox $((i+1)): listening on port $current_port, connecting to 127.0.0.1:$prev_port"
        ./matls middlebox $current_port 127.0.0.1 $prev_port server.crt server.key logs/mb_$i.log & > logs/stdout_mb_$i.log
        MB_PID=$!
        echo $MB_PID >> "$PID_FILE"
        prev_port=$current_port
    done
    sleep 1

    echo "Hello World" > "$CLIENT_INPUT_FILE"

    echo "Starting client connecting to 127.0.0.1:$prev_port with input from $CLIENT_INPUT_FILE"

    ./matls client 127.0.0.1 $prev_port logs/client.log < "$CLIENT_INPUT_FILE"  
    CLIENT_PID=$!
    echo $CLIENT_PID >> "$PID_FILE"

elif [ "$1" == "kill" ]; then
    if [ -f "$PID_FILE" ]; then
        echo "Killing processes..."
        while IFS= read -r pid; do
            echo "Killing PID $pid"
            kill "$pid" 2>/dev/null
        done < "$PID_FILE"
        rm -f "$PID_FILE"
        echo "Processes killed."
    else
        echo "No PID file found. Are the processes running?"
    fi
else
    echo "Usage: $0 start|kill"
    exit 1
fi