#!/bin/bash

echo "[ ] Started"

curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9090/ &> /dev/null

for i in {1..14}
do
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/ &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" http://127.0.0.1:9999/ &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9999/ &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/favicon.ico &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" http://127.0.0.1:9999/favicon.ico &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/favicon.ico &> /dev/null
    sleep 0.1
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" http://127.0.0.1:9999/ &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15" http://127.0.0.1:9999/ &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" http://127.0.0.1:9999/favicon.ico &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15" http://127.0.0.1:9999/favicon.ico &> /dev/null
    curl -X POST -d "name=dagon" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9999/lookup.php &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" http://127.0.0.1:9999/ &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/ &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15" http://127.0.0.1:9999/ &> /dev/null
    sleep 0.1
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" http://127.0.0.1:9999/ &> /dev/null
    if [ $i -eq 3 ]
    then
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/forgotpass.php &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15" http://127.0.0.1:9999/ &> /dev/null
        sleep 0.1
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/forgotpass.php &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15" http://127.0.0.1:9999/forgotpass.php &> /dev/null
        curl -X POST -d "name=root" -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.1" http://127.0.0.1:9999/lookup.php &> /dev/null
    fi
    curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11.6; rv:93.0) Gecko/20100101 Firefox/93.0" http://127.0.0.1:9999/ &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" http://127.0.0.1:9999/ &> /dev/null
    sleep 0.2
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/ &> /dev/null
    curl -X POST -d "name=superfan" -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11.6; rv:93.0) Gecko/20100101 Firefox/93.0" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9999/lookup.php &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" http://127.0.0.1:9999/ &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15" http://127.0.0.1:9999/ &> /dev/null
    curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" http://127.0.0.1:9999/ &> /dev/null
    sleep 0.1
    curl -X POST -d "name=usermoose" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9999/lookup.php &> /dev/null
    curl -X POST -d "pma_username=root&pma_password=NINJAROOTPASSWORD" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9090/ &> /dev/null
done
sleep 0.1
for i in {1..20}
do
    for i in {1..6}
    do
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" http://127.0.0.1:9999/ &> /dev/null
        curl -X POST -d "name=acom" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9999/lookup.php &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edge/94.0.992.50" http://127.0.0.1:9999/ &> /dev/null
        sleep 0.1
        if [ $i -eq 1 ]
        then 
            curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" http://127.0.0.1:9999/users.php &> /dev/null
            curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/forgotpass.php &> /dev/null
        fi
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/favicon.ico &> /dev/null
        curl -X POST -d "name=root" -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.1" http://127.0.0.1:9999/lookup.php &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9999/favicon.ico &> /dev/null
        sleep 0.2
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" http://127.0.0.1:9999/ &> /dev/null
        curl -X POST -d "name=yopp" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9999/lookup.php &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15" http://127.0.0.1:9999/ &> /dev/null
        if [ $i -eq 3 ]
        then 
            curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" http://127.0.0.1:9999/innodb.php &> /dev/null
            curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/accounts.php &> /dev/null
            curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" http://127.0.0.1:9999/helpfile &> /dev/null
            curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" http://127.0.0.1:9999/favicon.ico &> /dev/null
            curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/favicon.ico &> /dev/null
        fi
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9999/favicon.ico &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9999/phpinfo.php &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/favicon.ico &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" http://127.0.0.1:9999/favicon.ico &> /dev/null
        if [ $i -eq 5 ]
        then 
            curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" http://127.0.0.1:9999/forgotpass.php &> /dev/null
            curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/baseline$i.php &> /dev/null
            curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" http://127.0.0.1:9999/$i.php &> /dev/null
            curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9999/favicon.ico &> /dev/null
            curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/favicon.ico &> /dev/null
        fi
        curl -X POST -d "name=nerfy" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9999/lookup.php &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/94.0.992.50" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36" http://127.0.0.1:9999/ &> /dev/null
        curl -X POST -d "name=zonal" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" -e http://127.0.0.1:9999/index.php http://127.0.0.1:9999/lookup.php &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15" http://127.0.0.1:9999/ &> /dev/null
        curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.3" http://127.0.0.1:9999/ &> /dev/null
    done
    sleep 0.2
done

echo "[ ] Finished"
