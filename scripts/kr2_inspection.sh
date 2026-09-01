#!/bin/bash

mkdir -p /home/probe/kr2_inspection
cd /home/probe/kr2_inspection
LOG_FILE=/home/probe/kr2_inspection/kr2_inspection_${HOSTNAME}.log
touch $LOG_FILE

echo -e "================ Step 1. KEP_Hash Check ================" >> $LOG_FILE

echo "[+] 위장 가능성이 있는 프로세스 바이너리 해시 검사 중..." >> $LOG_FILE

TARGETS=(
    "/usr/sbin/smartd"
    "/usr/libexec/hald-addon-volume"
    "/usr/bin/dbus-daemon"
    "/usr/sbin/hpasmlited"
)

for exe in "${TARGETS[@]}"; do
    if [ -f "$exe" ]; then
        HASH=$(sudo sha256sum "$exe" | awk '{print $1}')
        case $HASH in
            "3f6f108db37d18519f47c5e4182e5e33cc795564f286ae770aa03372133d15c4") echo "[악성 의심] $exe (SHA256: $HASH)" >> $LOG_FILE;;
            "aa779e83ff5271d3f2d270eaed16751a109eb722fca61465d86317e03bbf49e4") echo "[악성 의심] $exe (SHA256: $HASH)" >> $LOG_FILE;;
            "95fd8a70c4b18a9a669fec6eb82dac0ba6a9236ac42a5ecde270330b66f51595") echo "[악성 의심] $exe (SHA256: $HASH)" >> $LOG_FILE;;
            "c7f693f7f85b01a8c0e561bd369845f40bff423b0743c7aa0f4c323d9133b5d4") echo "[악성 의심] $exe (SHA256: $HASH)" >> $LOG_FILE;;
            *) echo "[정상 또는 미확인] $exe (SHA256: $HASH)" >> $LOG_FILE;;
        esac
    else
        echo "[!] 파일 없음: $exe" >> $LOG_FILE
    fi
done

echo -e "\n\n================ Step 2. Network Check ================" >> $LOG_FILE

C2_IP="165.232.174.130"

if ! netstat -ntp | grep "$C2_IP" 2>/dev/null; then
    echo "* netstat_TCP_C2_IP 미존재" >> $LOG_FILE
    else
    echo "[악성 의심] netstat_TCP_C2_IP 존재" >> $LOG_FILE
    netstat -ntp | grep "$C2_IP"  >> $LOG_FILE
fi

if ! netstat -nup | grep "$C2_IP" 2>/dev/null; then
    echo "* netstat_UDP_C2_IP 미존재" >> $LOG_FILE
    else
    echo "[악성 의심] netstat_UDP_C2_IP 존재" >> $LOG_FILE
    netstat -nup | grep "$C2_IP"  >> $LOG_FILE
fi

if ! ss -ntp | grep "$C2_IP" 2>/dev/null; then
    echo "* ss_TCP_C2_IP 미존재" >> $LOG_FILE
    else
    echo "[악성 의심] ss_TCP_C2_IP 존재" >> $LOG_FILE
    ss -ntp | grep "$C2_IP"  >> $LOG_FILE
fi

if ! ss -nup | grep "$C2_IP" 2>/dev/null; then
    echo "* ss_UDP_C2_IP 미존재" >> $LOG_FILE
    else
    echo "[악성 의심] ss_UDP_C2_IP 존재" >> $LOG_FILE
    ss -nup | grep "$C2_IP"  >> $LOG_FILE
fi

echo -e "\n\n================ Step 3. Hash Check ================" >> $LOG_FILE

declare -A MALWARE_HASHES=(
    ["c7f693f7f85b01a8c0e561bd369845f40bff423b0743c7aa0f4c323d9133b5d4"]="hpasmmld"
    ["3f6f108db37d18519f47c5e4182e5e33cc795564f286ae770aa03372133d15c4"]="smartadm"
    ["95fd8a70c4b18a9a669fec6eb82dac0ba6a9236ac42a5ecde270330b66f51595"]="hald-addon-volume"
    ["aa779e83ff5271d3f2d270eaed16751a109eb722fca61465d86317e03bbf49e4"]="dbus-srv-bin.txt"
    ["925ec4e617adc81d6fcee60876f6b878e0313a11f25526179716a90c3b743173"]="dbus-srv"
    ["29564c19a15b06dd5be2a73d7543288f5b4e9e6668bbd5e48d3093fb6ddf1fdb"]="inode262394"
    ["be7d952d37812b7482c1d770433a499372fde7254981ce2e8e974a67f6a088b5"]="dbus-srv"
    ["027b1fed1b8213b86d8faebf51879ccc9b1afec7176e31354fbac695e8daf416"]="dbus-srv"
    ["a2ea82b3f5be30916c4a00a7759aa6ec1ae6ddadc4d82b3481640d8f6a325d59"]="dbus-srv"
    ["e04586672874685b019e9120fcd1509d68af6f9bc513e739575fc73edefd511d"]="File_in_Inode"
    ["adfdd11d69f4e971c87ca5b2073682d90118c0b3a3a9f5fbbda872ab1fb335c6"]="gm"
    ["7c39f3c3120e35b8ab89181f191f01e2556ca558475a2803cb1f02c05c830423"]="rad"
)

SEARCH_PATHS_HASH=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/lib" "/usr/lib" "/etc" "/tmp" "/var/tmp" "/dev/shm" "/opt" "/home" "/run" "/usr/local/bin" "/usr/local/sbin" "/usr/libexec")

for search_dir in "${SEARCH_PATHS_HASH[@]}"; do
    if [ ! -d "$search_dir" ]; then
        echo "Directory '$search_dir' not found." >> $LOG_FILE
        continue
    fi

    find "$search_dir" -type f -print0 2>/dev/null | while IFS= read -r -d $'\0' file_path; do
        [ ! -r "$file_path" ] && continue
        current_sha256=$(sha256sum "$file_path" 2>/dev/null | awk '{print $1}')
        [ -z "$current_sha256" ] && continue 

        for known_hash_val in "${!MALWARE_HASHES[@]}"; do
            if [[ "$current_sha256" == "$known_hash_val" ]]; then
                echo "[악성 의심] $file_path, $current_sha256 (탐지명: ${MALWARE_HASHES[$known_hash_val]})" >> $LOG_FILE
            fi
        done
    done
done

echo -e "\n\n================ End ================" >> $LOG_FILE

FILE_PATTERN=$LOG_FILE
UPLOAD_URL="http://<UPLOAD_SERVER_IP>:5000/upload"

for file in $FILE_PATTERN; do
    if [[ -f "$file" ]]; then
        curl -X POST -F "file=@$file" $UPLOAD_URL 2>/dev/null
    fi
done

rm -rf /home/probe/kr2_inspection
rm -rf /home/probe/kr2_inspection.sh