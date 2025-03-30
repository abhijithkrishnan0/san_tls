#!/bin/bash

PID_FILE="santls_pids.txt"
CLIENT_INPUT_FILE="largefile"

SERVER_START_PORT=5544

if [ "$1" == "start" ]; then
    # Start the server on port 5544
    # echo "./santls server $SERVER_START_PORT server.crt server.key logs/server.log"

    ./santls server $SERVER_START_PORT server.crt server.key logs/server.log & > logs/stdout_server.log
    SERVER_PID=$!
    echo $SERVER_PID > "$PID_FILE"
    # echo "Started server on port $SERVER_START_PORT with PID $SERVER_PID"

    # Initialize starting port and connection target
    start_port=3000
    prev_port=$SERVER_START_PORT

    # Spawn 10 middleboxes in a loop
    for i in $(seq 0 10); do
        sleep 1
        current_port=$((start_port + i))
        # echo "Starting middlebox $((i+1)): listening on port $current_port, connecting to 127.0.0.1:$prev_port"
        ./santls middlebox $current_port 127.0.0.1 $prev_port server.crt server.key logs/mb_$i.log & > logs/stdout_mb_$i.log
        MB_PID=$!
        echo $MB_PID >> "$PID_FILE"
        prev_port=$current_port
    done
    sleep 1

    # Create a file containing the hardcoded input for the client
    echo "Hello World" > "$CLIENT_INPUT_FILE"

    # Start the client connecting to the last middlebox (listening on the last port)
    # and supply the hardcoded input from the file
    # echo "Starting client connecting to 127.0.0.1:$prev_port with input from $CLIENT_INPUT_FILE"
    echo "./santls client 127.0.0.1 $prev_port logs/client.log < "$CLIENT_INPUT_FILE"  "
    ./santls client 127.0.0.1 $prev_port logs/client.log < "$CLIENT_INPUT_FILE"  
    CLIENT_PID=$!
    echo $CLIENT_PID >> "$PID_FILE"

    # echo "-------------------------------------------------"
    # echo "Server (port $SERVER_START_PORT), 10 middleboxes (ports 3000 to $prev_port), and client (connecting to port $prev_port) have started."
    # echo "Press Ctrl+C to stop them, or run this script with 'kill'."
    # echo "-------------------------------------------------"

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