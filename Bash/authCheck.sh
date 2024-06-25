#!/bin/bash

LOG_FILES=("/var/log/auth.log" "/var/log/auth.log.1" "/var/log/secure" "/var/log/secure.1")
REPORT="analysis_report.txt"

analyse_auth() {
    echo "Assessing Authentications" > "$REPORT"
    echo "Task run: $(date)" >> "$REPORT"
    echo >> "$REPORT"

    total_fails=0
    total_success=0

    for LOG_FILE in "${LOG_FILES[@]}"; do
        if [ -f "$LOG_FILE" ]; then
            fails=$(grep 'Failed password' "$LOG_FILE")
            if [ -n "$fails" ]; then
                num_fails=$(echo "$fails" | wc -l)
                total_fails=$((total_fails + num_fails))
                echo "Failed authentication attempts in $LOG_FILE: $num_fails" >> "$REPORT"
                echo "$fails" >> "$REPORT"
            fi

            success=$(grep 'Accepted password' "$LOG_FILE")
            if [ -n "$success" ]; then
                num_success=$(echo "$success" | wc -l)
                total_success=$((total_success + num_success))
                echo "Successful logins in $LOG_FILE: $num_success" >> "$REPORT"
                echo "$success" >> "$REPORT"
            fi
        fi
    done

    echo >> "$REPORT"
    echo "Total failed authentication attempts: $total_fails" >> "$REPORT"
    echo "Total successful logins: $total_success" >> "$REPORT"

    echo "Assessment complete. Analysis stored in $REPORT"
}

analyse_auth
