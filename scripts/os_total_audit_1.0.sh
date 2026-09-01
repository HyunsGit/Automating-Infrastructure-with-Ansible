#!/bin/bash
# total os audit.sh (25.03.12)
# available version list (Centos7/Rocky/Ubuntu20/22/24)

# OS 확인
OS_TYPE=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

# OS별 진단 함수
check_ubuntu() {
echo ""
echo "Ubuntu 운영 체제 보안 취약점 진단 스크립트를 실행합니다."
echo ""
echo "==============================  START  ==============================" 
echo ""

IP=`ifconfig -a | grep  "inet" | head -1 | awk '{print $2}'`
RESULT_FILE=./UbuntuOO`hostname`OO$IP.txt

echo [U-1]root 계정 원격 접속 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-1]root 계정 원격 접속 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [1-START] >> $RESULT_FILE 2>&1
if [ `find /etc -type f -name "sshd_config" | wc -l` -eq 0 ]
	then
		echo "★ sshd_config 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [1-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-1]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SSHCONFIG=`find /etc -type f -name "sshd_config"`
		if [ `grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "#" | grep -i "no" | wc -l` -eq 0 ]
			then
				echo "★ root 계정 원격 접속이 제한되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "without" >> $RESULT_FILE 2>&1
				echo [1-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-1]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ root 계정 원격 접속이 제한됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "without" >> $RESULT_FILE 2>&1
				echo [1-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-1]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-2]패스워드 복잡성 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-2]패스워드 복잡성 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [2-START] >> $RESULT_FILE 2>&1
if [ `find /etc/pam.d -name "common-password" | wc -l` -eq 0 ]
		then
			echo "★ common-password 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
			echo [2-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-2]Result : MANUAL >> $RESULT_FILE 2>&1
		else
			SYSAUTH=`find /etc/pam.d -name "common-password"`
			if [ `grep -i "password" $SYSAUTH | grep "requisite" | grep "lcredit" | grep "dcredit" | grep "ocredit" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 복잡성 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-2]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 패스워드 복잡성 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "password" $SYSAUTH >> $RESULT_FILE 2>&1
				echo [2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-2]Result : GOOD >> $RESULT_FILE 2>&1
			fi
		fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-3]계정 잠금 임계값 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-3]계정 잠금 임계값 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [3-START] >> $RESULT_FILE 2>&1
if [ `find /etc -name "system-auth" | wc -l` -eq 0 ]
	then
		echo "★ system-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [3-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-3]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SYSAUTHAC=`find /etc -name "system-auth"`
		if [ `grep -i "pam_tally2.so" $SYSAUTHAC | grep -i "deny" | wc -l` -eq 0 ]
			then
				echo "★ 계정 잠금 임계값 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "^auth" $SYSAUTHAC >> $RESULT_FILE 2>&1 
				echo [3-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-3]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 계정 잠금 임계값 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "^auth" $SYSAUTHAC >> $RESULT_FILE 2>&1 
				echo [3-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1			
				echo [U-3]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-4]패스워드 파일 보호
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-4]패스워드 파일 보호  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [4-START] >> $RESULT_FILE 2>&1
if [ -f /etc/shadow ]; then
    echo "/etc/shadow 파일이 존재합니다." >> $RESULT_FILE 2>&1
	echo "[현황]" >> $RESULT_FILE 2>&1
	echo cat /etc/shadow >> $RESULT_FILE 2>&1
    echo [4-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1			
	echo [U-4]Result : GOOD >> $RESULT_FILE 2>&1
else
    passwd_field=$(head -1 /etc/passwd | cut -d: -f2)    
    if [ "$passwd_field" == "x" ]; then
	    echo "★ 패스워드 /etc/passwd 파일에 저장하지 않고 별도의 파일에 저장함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo cat /etc/shadow >> $RESULT_FILE 2>&1
		echo [4-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1			
		echo [U-4]Result : GOOD >> $RESULT_FILE 2>&1
    else
		echo "★ 패스워드 /etc/passwd 파일에 저장함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo cat /etc/shadow >> $RESULT_FILE 2>&1
        echo [4-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-4]Result : VULNERABLE >> $RESULT_FILE 2>&1
    fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-5]root 홈, 패스 디렉터리 권한 및 패스 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-5]root 홈, 패스 디렉터리 권한 및 패스 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [5-START] >> $RESULT_FILE 2>&1
if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]
	then
		echo "★ PATH 환경변수에 '.'이 맨 앞 또는 중간에 위치하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $PATH >> $RESULT_FILE 2>&1
		echo [5-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-5]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ PATH 환경변수에 '.'이 맨 앞 또는 중간에 위치함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $PATH >> $RESULT_FILE 2>&1
		echo [5-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-5]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-6]파일 및 디렉터리 소유자 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-6]파일 및 디렉터리 소유자 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
	ls -l /home | awk '{print $3}' | grep "^[0-9]" > tmp_6_1.txt
	for i in `cat tmp_6_1.txt`; do ls -l /home | grep -w $i >> tmp_6_2.txt; done
	if [ -f tmp_6_2.txt ]
	then
		echo "★ /home 디렉토리에 소유자가 존재하지 않는 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_6_2.txt | tail -50 >> $RESULT_FILE 2>&1
		echo 총 갯수 : >> $RESULT_FILE 2>&1
		cat tmp_6_2.txt | wc -l >> $RESULT_FILE 2>&1
		echo [6-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-6]Result : VULNERABLE >> $RESULT_FILE 2>&1		
	else
		echo "★ /home 디렉토리에 소유자가 존재하지 않는 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [6-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-6]Result : GOOD >> $RESULT_FILE 2>&1
	fi
	rm -rf tmp_6_1.txt
	rm -rf tmp_6_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-7]/etc/passwd 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-7]/etc/passwd 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [7-START] >> $RESULT_FILE 2>&1
file="/etc/passwd"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 644 ]; then
		echo "★ /etc/passwd 파일의 소유자 및 퍼미션(644)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [7-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-7]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
		echo "★ /etc/passwd 파일의 소유자 및 퍼미션(644)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [7-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-7]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/passwd 파일을 찾을 수 없음" >> "$RESULT_FILE" 2>&1
    echo [7-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-7]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-8]/etc/shadow 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-8]/etc/shadow 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [8-START] >> $RESULT_FILE 2>&1
file="/etc/shadow"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 400 ]; then
		echo "★ /etc/shadow 파일의 소유자 및 퍼미션(400)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [8-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-8]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
		echo "★ /etc/shadow 파일의 소유자 및 퍼미션(400)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [8-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-8]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/shadow file not found" >> "$RESULT_FILE" 2>&1
    echo [8-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-8]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-9]/etc/hosts 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-9]/etc/hosts 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [9-START] >> $RESULT_FILE 2>&1
file="/etc/hosts"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 600 ]; then
        echo "★ /etc/hosts 파일의 소유자 및 퍼미션(600)이하로 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [9-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-9]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
        echo "★ /etc/hosts 파일의 소유자 및 퍼미션(600)이하로 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [9-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-9]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/hosts 파일을 찾을 수 없음" >> "$RESULT_FILE" 2>&1
    echo [9-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-9]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-10]/etc/xinetd.conf 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-10]/etc/xinetd.conf 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [10-START] >> $RESULT_FILE 2>&1
file1="/etc/xinetd.conf"
file2="/etc/inetd.conf"
if [ -f "$file1" ]
	then
		owner="$(stat -c %U "$file1")"
		permissions="$(stat -c %a "$file1")"
		if [ "$owner" = "root" ] && [ "$permissions" -eq 600 ]
			then
				echo "★ /etc/xinetd.conf 파일의 소유자 및 퍼미션(600)으로 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
				echo "[현황]" >> "$RESULT_FILE" 2>&1
				ls -alL "$file1" >> "$RESULT_FILE" 2>&1
				echo [10-END] >> "$RESULT_FILE" 2>&1
				echo >> "$RESULT_FILE" 2>&1
				echo "[U-10]Result : GOOD" >> "$RESULT_FILE" 2>&1
			else
				echo "★ /etc/xinetd.conf 파일의 소유자 및 퍼미션(600)으로 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
				echo "[현황]" >> "$RESULT_FILE" 2>&1
				ls -alL "$file1" >> "$RESULT_FILE" 2>&1
				echo [10-END] >> "$RESULT_FILE" 2>&1
				echo >> "$RESULT_FILE" 2>&1
				echo "[U-10]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
		fi
	else
		if [ -f "$file2" ]
			then
				owner="$(stat -c %U "$file2")"
				permissions="$(stat -c %a "$file2")"
				if [ "$owner" = "root" ] && [ "$permissions" -eq 600 ]
					then
						echo "★ /etc/inetd.conf 파일의 소유자 및 퍼미션(600)으로 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
						echo "[현황]" >> "$RESULT_FILE" 2>&1
						ls -alL "$file2" >> "$RESULT_FILE" 2>&1
						echo [10-END] >> "$RESULT_FILE" 2>&1
						echo >> "$RESULT_FILE" 2>&1
						echo "[U-10]Result : GOOD" >> "$RESULT_FILE" 2>&1
					else
						echo "★ /etc/inetd.conf 파일의 소유자 및 퍼미션(600)으로 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
						echo "[현황]" >> "$RESULT_FILE" 2>&1
						ls -alL "$file2" >> "$RESULT_FILE" 2>&1
						echo [10-END] >> "$RESULT_FILE" 2>&1
						echo >> "$RESULT_FILE" 2>&1
						echo "[U-10]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
				fi			
					else
						echo "★ /etc/inetd.conf 파일과 /etc/inetd.d 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
						echo [10-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-10]Result : GOOD >> $RESULT_FILE 2>&1 
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-11]/etc/rsyslog.conf 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-11]/etc/rsyslog.conf 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [11-START] >> $RESULT_FILE 2>&1
file="/etc/rsyslog.conf"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 640 ]; then
		echo "★ /etc/rsyslog.conf 파일의 소유자 및 퍼미션(640)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [11-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-11]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
		echo "★ /etc/rsyslog.conf 파일의 소유자 및 퍼미션(640)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [11-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-11]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/rsyslog.conf file not found." >> "$RESULT_FILE" 2>&1
    echo [11-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-11]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-12]/etc/services 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-12]/etc/services 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [12-START] >> $RESULT_FILE 2>&1
file="/etc/services"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 644 ]; then
		echo "★ /etc/services 파일의 소유자 및 퍼미션(644)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [12-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-12]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
		echo "★ /etc/services 파일의 소유자 및 퍼미션(644)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [12-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-12]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "The /etc/services file is missing." >> "$RESULT_FILE" 2>&1
    echo [12-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-12]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-13]SUID, SGID, 설정 파일점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-13]SUID, SGID, 설정 파일점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [13-START] >> $RESULT_FILE 2>&1
CheckSuidSgid1=$(find / -user root -type f \( -perm -04000 -o -perm -02000 \) -exec ls -l {} \ >> CheckSuidSgid.txt 2>&1)
for i in /sbin/dump /sbin/restore /sbin/unix_chkpwd /usr/bin/at /usr/bin/lpq /usr/bin/lpq-lpd /usr/bin/lpr /usr/bin/lpr-lpd /usr/bin/lprm /usr/bin/lprm-lqp /usr/bin/newgrp /usr/sbin/lpc /usr/sbin/lpc-lpd /usr/sbin/traceroute
do
	cat CheckSuidSgid.txt | grep $i >> ResultSuidSgid.txt
done
CheckSuidSgid2=$(cat ResultSuidSgid.txt | wc -l )
if [ $CheckSuidSgid2 = 0 ]
	then
		echo "주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [13-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-13]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1 
		cat CheckSuidSgid.txt  >> $RESULT_FILE 2>&1 
		echo [13-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-13]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf CheckSuidSgid.txt
rm -rf ResultSuidSgid.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1



echo [U-14]사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [14-START] >> $RESULT_FILE 2>&1
if [ -f /etc/profile ]; then
    if [ "$(stat -c %U /etc/profile)" = "root" ] && [ "$(stat -c %a /etc/profile)" -le "644" ]; then
        echo "★ /etc/profile 파일의 소유자 및 퍼미션(g-w,o-w)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -al /etc/profile >> "$RESULT_FILE" 2>&1
        echo "[14-END]" >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-14]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
        echo "★ /etc/profile 파일의 소유자 및 퍼미션(g-w,o-w)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -al /etc/profile >> "$RESULT_FILE" 2>&1
        echo "[14-END]" >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-14]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/profile file missing" >> "$RESULT_FILE" 2>&1
    echo "[14-END]" >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-14]Result : N/A" >> "$RESULT_FILE" 2>&1
fi

echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


# 일반사용자 및 비인가된 사용자가 해당 파일을 임의로 수정, 삭제가 가능함
# 많은 파일이 출력되기에, 특정 중요 디렉토리 대상으로만 검색하면 어떨까? 앞으로 고려 대상임
echo [U-15]world writable 파일 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-15]world writable 파일 점검 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [15-START] >> $RESULT_FILE 2>&1
important_directories=(
    "/bin"
    "/boot"
    "/etc"
    "/lib"
    "/lib64"
    "/sbin"
    "/usr"
)
echo "일반 사용자 및 비인가된 사용자에게 쓰기 권한이 있는 파일 리스트 전체를 출력합니다." >> $RESULT_FILE 2>&1
for directory in "${important_directories[@]}"; do
    echo "중요 디렉토리 $directory 에 대해 검색 중.." >> $RESULT_FILE 2>&1
    find "$directory" -type f -perm -2 -exec ls -l {} \; >> $RESULT_FILE 2>&1
done
echo " 검색 결과가 없다면 양호 " >> $RESULT_FILE 2>&1
echo [15-END] >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [U-15]Result : MANUAL >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-16]dev에 존재하지 않는 device 파일 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-16]dev에 존재하지 않는 device 파일 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [16-START] >> $RESULT_FILE 2>&1
find /dev -type f -exec ls -l {} \; > U_16.txt
if [ `cat U_16.txt | wc -l` -eq 0 ]
then
    echo "★ /dev 디렉토리에 major, minor number를 가지지 않는 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
    echo [16-END] >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo [U-16]Result : GOOD >> $RESULT_FILE 2>&1
else
    echo "★ /dev 디렉토리에 major, minor number를 가지지 않는 파일이 존재함" >> $RESULT_FILE 2>&1
    echo "[현황]" >> $RESULT_FILE 2>&1
    cat U_16.txt | tail -50 >> $RESULT_FILE 2>&1
    echo "총 갯수 : $(cat U_16.txt | wc -l)" >>  $RESULT_FILE 2>&1
    echo [16-END] >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo [U-16]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf U_16.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-17]$HOME/.rhosts, hosts.equiv 사용 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-17]$HOME/.rhosts, hosts.equiv 사용 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [17-START] >> $RESULT_FILE 2>&1
	ls -l /home/ | grep -v "+found" | sed -n '2,$p' | awk '{print $9}' > U_17_1.txt
	for i in `cat U_17_1.txt`; do ls -al /home/$i/.rhosts; done 2>/dev/null > U_17_2.txt
	if [ -f /etc/hosts.equiv ]; then ls -l /etc/hosts.equiv >> U_17_2.txt; else true; fi 
	if [ `cat U_17_2.txt | wc -l` -eq 0 ]
	then
		echo "★ .rhosts, hosts.equiv 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [17-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-17]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat U_17_2.txt | wc -l` -eq `cat U_17_2.txt | grep "^....------" | wc -l` ]
		then
			for i in `cat U_17_2.txt | awk '{print $9}'`; do cat $i; done >> U_17_3.txt
			if [ `cat U_17_3.txt | grep "\+" | wc -l` -eq 0 ] 
			then
				echo "★ .rhosts, hosts.equiv 파일의 퍼미션 및 설정이 적절하게 적용됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				for i in `cat U_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
				echo [17-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-17]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ .rhosts, hosts.equiv 파일의 설정이 적절하지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				for i in `cat U_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
				echo [17-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-17]Result : VULNERABLE >> $RESULT_FILE 2>&1
			fi
		else
			echo "★ .rhosts, hosts.equiv 파일의 퍼미션이 적절하지 않음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			for i in `cat U_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
			echo [17-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-17]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	fi
	rm -rf U_17_1.txt
	rm -rf U_17_2.txt				
	rm -rf U_17_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-18]접속 IP 및 포트 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-18]접속 IP 및 포트 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [18-START] >> $RESULT_FILE 2>&1
### /etc/hosts.allow 파일에 ALL 설정이 되어 있지 않은지 .deny 파일에 설정이 추가 되어 있는지 확인
if [ `cat /etc/hosts.allow | grep -v "^#" | grep ALL | wc -l` -eq 0 ] && [ `cat /etc/hosts.deny | grep -v "^#" | wc -l` -eq 1 ]
  then
	echo "hosts.allow ALL 설정이 존재 하지 않고 hosts.deny 옵션이 적용되어 있음" >> $RESULT_FILE 2>&1
	echo [18-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
    echo [U-18]Result : GOOD >> $RESULT_FILE 2>&1
 else
	echo "hosts.allow 또는 hosts.deny 파일에 ALL 설정이 존재함" >> $RESULT_FILE 2>&1
	echo "[현황]" >> $RESULT_FILE 2>&1
	echo "etc/hosts.allow" >> $RESULT_FILE 2>&1
	cat /etc/hosts.allow | grep -v "^#" >> $RESULT_FILE 2>&1
	echo "etc/hosts.deny" >> $RESULT_FILE 2>&1
	cat /etc/hosts.deny | grep -v "^#" >> $RESULT_FILE 2>&1
	echo [18-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
    echo [U-18]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-19]Finger 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-19]Finger 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [19-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "finger" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Finger 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [19-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-19]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ Finger 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep -i "finger" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [19-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-19]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-20]Anonymous FTP 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-20]Anonymous FTP 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [20-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [20-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "vsftpd.conf" -exec cat {} \; > vsftpdcheck.txt
		if [ `cat vsftpdcheck.txt | wc -l` -eq 0 ]
			then
				if [ `cat /etc/passwd | egrep -w "ftp|anonymous" | wc -l` -eq 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, ftp 또는 anonymous 계정이 존재하지 않음 " >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, ftp 또는 anonymous 계정이 존재함 " >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat /etc/passwd | egrep -w "ftp|anonymous" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				if [ `cat vsftpdcheck.txt | grep "anonymous_enable" | grep -v "#" | grep -i -v "no$" | wc -l` -eq 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, Anonymous 접속이 차단됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat vsftpdcheck.txt | grep "anonymous_enable" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, Anonymous 접속이 허용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat vsftpdcheck.txt | grep "anonymous_enable" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi	
fi
rm -rf vsftpdcheck.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "[U-21]r 계열 서비스 비활성화" >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo "[U-21]r 계열 서비스 비활성화" >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo "[21-START]" >> $RESULT_FILE 2>&1

# 파일 생성, /proc 디렉토리를 제외한 검색
find / -path /proc -prune -o \( -name "rsh" -o -name "rexec" -o -name "rlogin" \) -print > U_21_1.txt
service --status-all > U_21_2.txt

if [ ! -s "U_21_1.txt" ]; then
    echo "★ r 계열 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
    echo "[21-END]" >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo "[U-21]Result : GOOD" >> $RESULT_FILE 2>&1
else
    if grep -q "[ + ] rsh" U_21_2.txt || grep -q "[ + ] rlogin" U_21_2.txt || grep -q "[ + ] rexec" U_21_2.txt; then
        echo "★ r 계열 서비스가 실행중임" >> $RESULT_FILE 2>&1
        echo "[현황]" >> $RESULT_FILE 2>&1
        cat U_21_2.txt >> $RESULT_FILE 2>&1
        echo "[21-END]" >> $RESULT_FILE 2>&1
        echo >> $RESULT_FILE 2>&1
        echo "[U-21]Result : VULNERABLE" >> $RESULT_FILE 2>&1
    else
        echo "★ r 계열 서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> $RESULT_FILE 2>&1
        cat U_21_1.txt >> $RESULT_FILE 2>&1
        echo "[21-END]" >> $RESULT_FILE 2>&1
        echo >> $RESULT_FILE 2>&1
        echo "[U-21]Result : GOOD" >> $RESULT_FILE 2>&1
    fi
fi

rm -rf U_21_1.txt
rm -rf U_21_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-22]crond 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-22]crond 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [22-START] >> $RESULT_FILE 2>&1
echo "[현황]" >> "$RESULT_FILE" 2>&1
cnt=0
lists=(
    "/etc/crontab 640 root"
    "/etc/cron.hourly 640 root"
    "/etc/cron.daily 640 root"
    "/etc/cron.weekly 640 root"
    "/etc/cron.monthly 640 root"
    "/etc/cron.allow 640 root"
    "/etc/cron.deny 640 root"
    "/etc/cron.d 640 root"
	"/usr/bin/crontab 750 root"
)

for list in "${lists[@]}"; do
    path=$(echo "$list" | awk '{ print $1 }')
    perm=$(echo "$list" | awk '{ print $2 }')
    owner=$(echo "$list" | awk '{ print $3 }')

    if [ ! -d "$path" ]; then
        if [ -e "$path" ]; then
            list_perm=$(stat -c "%a" "$path")
            file_owner=$(stat -c "%U" "$path")
            if [ "$perm" -lt "$list_perm" ] || [ "$owner" != "$file_owner" ]; then
                echo -e "$path 파일의 소유자($owner) 또는 퍼미션($perm)이 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
                echo -e "  $(ls -al $path)" >> "$RESULT_FILE" 2>&1
                cnt=$((cnt+1))
            else
                echo -e "$path 파일의 소유자 및 퍼미션이 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
            fi
        fi
    elif [ -d "$path" ]; then
        for file in "$path"/*; do
            if [ -e "$file" ]; then
                list_perm=$(stat -c "%a" "$file")
                file_owner=$(stat -c "%U" "$file")
                if [ "$perm" -lt "$list_perm" ] || [ "$owner" != "$file_owner" ]; then
                    echo -e "$file 파일의 소유자($owner) 또는 퍼미션($perm)이 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
                    echo -e "  $(ls -al $file)" >> "$RESULT_FILE" 2>&1
                    cnt=$((cnt+1))
                else
                    echo -e "$file 파일의 소유자 및 퍼미션이 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
                fi
            fi
        done
    fi
done

echo -e "[22-END]\n" >> $RESULT_FILE 2>&1

if [ $cnt -ge 1 ]; then
        echo -e "[U-22]Result : VULNERABLE\n" >> $RESULT_FILE 2>&1
else
        echo -e "[U-22]Result : GOOD\n" >> $RESULT_FILE 2>&1

fi

# 우분투 운영체제에서는 xineted.d 파일이 없습니다. 따라서 /etc/systemd/system 파일 안에서 존재하는지 점검합니다.
echo [U-23]DoS 공격에 취약한 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-23]DoS 공격에 취약한 서비스 비활성화 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [23-START] >> $RESULT_FILE 2>&1
# 서비스 실행 여부 저장
echo echo.service status >> U_23_1.txt 2>&1
systemctl is-active echo.service >> U_23_1.txt 2>&1
echo discard.service status >> U_23_1.txt 2>&1
systemctl is-active discard.service >> U_23_1.txt 2>&1
echo daytime.service status >> U_23_1.txt 2>&1
systemctl is-active daytime.service >> U_23_1.txt 2>&1
echo chargen.service status >> U_23_1.txt 2>&1
systemctl is-active chargen.service >> U_23_1.txt 2>&1
if [ `find /etc/systemd/system -name "echo" -o -name "discard" -o -name "daytime" -o -name "chargen" | wc -l` -eq 0 ]
	then
		echo "★ DoS 공격에 취약한 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [23-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-23]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat U_23_1.txt | grep "active" | wc -l` -eq 0 ]
			then
				echo "★ DoS 공격에 취약한 서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat U_23_1.txt >> $RESULT_FILE 2>&1
				echo [40-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-40]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ DoS 공격에 취약한 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat U_23_1.txt | grep "active" >> $RESULT_FILE 2>&1
				echo [40-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-40]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf U_23_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-24]NFS 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-24]NFS 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [24-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "NFS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [24-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-24]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "NFS 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [24-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-24]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-25]NFS 접근 통제
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-25]NFS 접근 통제  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [25-START] >> $RESULT_FILE 2>&1
	if [ `ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "NFS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [25-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-25]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ -f /etc/exports ]
		then
			if [ `cat /etc/exports | grep -i "everyone" | grep -v "^ *#" | wc -l` -eq 0 ]
			then
				echo "NFS 서비스가 실행중이나 everyone 공유가 존재하지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" >> $RESULT_FILE 2>&1
				cat /etc/exports >> $RESULT_FILE 2>&1 
				echo [25-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-25]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "NFS 서비스가 실행중이고 everyone 공유가 존재함" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" >> $RESULT_FILE 2>&1
				cat /etc/exports >> $RESULT_FILE 2>&1 
				echo [25-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-25]Result : VULNERABLE >> $RESULT_FILE 2>&1
			fi
		else
			echo "NFS 서비스가 실행중이나 /etc/exports 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" >> $RESULT_FILE 2>&1
			echo [25-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-25]Result : MANUAL >> $RESULT_FILE 2>&1
		fi
	fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

### automountd 서비스 대신에 우분투에서는 autofs 서비스가 존재함
echo [U-26]automountd 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-26]automountd 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [26-START] >> $RESULT_FILE 2>&1

if [ `ps -ef | egrep "autofs" | grep -v "grep" | grep -v 'node_exporter' | wc -l` -eq 0 ]
	then
		echo "autofs 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [26-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-26]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "autofs 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep -i "autofs" | grep -v "grep" | grep -v 'node_exporter' >> $RESULT_FILE 2>&1
		echo [26-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-26]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

# 우분투 운영체제에서는 xineted.d 파일이 없습니다. 따라서 /etc/systemd/system 파일 안에서 존재하는지 점검합니다.
echo [U-27]RPC 서비스 확인
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-27]RPC 서비스 확인  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [27-START] >> $RESULT_FILE 2>&1
find /etc/systemd/system -name "rpc.cmsd" -o -name "rpc.ttdbserverd" -o -name "sadmind" -o -name "rusersd" -o -name "walld" -o -name "sprayd" -o -name "rstatd" -o -name "rpc.nisd" -o -name "rpc.pcnfsd" -o -name "rpc.statd" -o -name "rpc.ypupdated" -o -name "rpc.rquotad" -o -name "kcms_server" -o -name "cachefsd"  -o -name "rexd" >> U_27_1.txt 2>&1
if [ `cat U_27_1.txt | wc -l` -eq 0 ]
	then
		echo "★ DoS 공격에 취약한 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [27-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-27]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat U_27_1.txt | grep "active" | wc -l` -eq 0 ]
			then
				echo "RPC서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat U_27_1.txt >> $RESULT_FILE 2>&1
				echo [27-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-27]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ DoS 공격에 취약한 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat U_27_1.txt | grep "active" >> $RESULT_FILE 2>&1
				echo [27-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-27]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf U_27_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-28]NIS, NIS+ 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-28]NIS, NIS+ 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [28-START] >> $RESULT_FILE 2>&1
SERVICE_NIS="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nisd"
	if [ `ps -ef | egrep $SERVICE_NIS | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ NIS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [28-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-28]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ NIS 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | egrep $SERVICE_NIS | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [28-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-28]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


# 점검 필요
echo [U-29]tftp, talk 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-29]tftp, talk 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [29-START] >> $RESULT_FILE 2>&1
	if [ `ps -ef | egrep "tftp|talk|ntalk" | grep -v "grep" | wc -l` -eq 0 ]
		then
			echo "★ tftp, talk 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
			echo [29-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-29]Result : GOOD >> $RESULT_FILE 2>&1		
		else
			echo "★ tftp, talk 서비스가 실행중임" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			ps -ef | egrep "tftp|talk|ntalk" >> $RESULT_FILE 2>&1
			echo [29-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-29]Result : VULNERABLE >> $RESULT_FILE 2>&1	
	fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-30]Sendmail 버전 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-30]Sendmail 버전 점검 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [30-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [30-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-30]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [30-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-30]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > sendmailcheck.txt \;			
				if [ `cat sendmailcheck | grep -v '^ *#' | grep DZ | egrep "8.15" | wc -l` -eq 0 ]
					then
						echo "취약한 버전의 Sendmail 서비스가 실행중임" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						echo "Sendmail 버전 : `cat sendmailcheck.txt | grep -v '^ *#' | grep DZ`" >> $RESULT_FILE 2>&1
						echo [30-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-30]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ 취약하지 않은 버전의 Sendmail 서비스가 실행중임" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						echo "Sendmail 버전 : `cat sendmailcheck.txt | grep -v '^ *#' | grep DZ`" >> $RESULT_FILE 2>&1
						echo [30-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-30]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf sendmailcheck.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "[U-31]스팸 메일 릴레이 제한"
echo "============================================================" >> "$RESULT_FILE" 2>&1
echo "[U-31]스팸 메일 릴레이 제한" >> "$RESULT_FILE" 2>&1
echo "============================================================" >> "$RESULT_FILE" 2>&1
echo "[31-START]" >> "$RESULT_FILE" 2>&1
# Check if postfix service is running
if systemctl is-active --quiet postfix; then
    # Check if main.cf file exists
    if [ -f /etc/postfix/main.cf ]; then
        # Check if relaying is denied in main.cf
        if grep -q "smtpd_relay_restrictions" /etc/postfix/main.cf && grep -q "permit_mynetworks" /etc/postfix/main.cf && grep -q "reject_unauth_destination" /etc/postfix/main.cf; then
            echo "스팸 메일 릴레이 제한 설정이 적용됨" >> "$RESULT_FILE" 2>&1
            echo "[현황]" >> "$RESULT_FILE" 2>&1
            systemctl status postfix | grep -A 5 "Active" >> "$RESULT_FILE" 2>&1
            grep "smtpd_relay_restrictions" /etc/postfix/main.cf >> "$RESULT_FILE" 2>&1
            echo "[31-END]" >> "$RESULT_FILE" 2>&1
            echo >> "$RESULT_FILE" 2>&1
            echo "[U-31]Result : GOOD" >> "$RESULT_FILE" 2>&1
        else
            echo "스팸 메일 릴레이 제한 설정이 적용되지 않음" >> "$RESULT_FILE" 2>&1
            echo "[현황]" >> "$RESULT_FILE" 2>&1
            systemctl status postfix | grep -A 5 "Active" >> "$RESULT_FILE" 2>&1
            echo "[31-END]" >> "$RESULT_FILE" 2>&1
            echo >> "$RESULT_FILE" 2>&1
            echo "[U-31]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
        fi
    else
        echo "Postfix 서비스가 실행중이나 main.cf 파일을 찾을 수 없음" >> "$RESULT_FILE" 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        systemctl status postfix | grep -A 5 "Active" >> "$RESULT_FILE" 2>&1
        echo "[31-END]" >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-31]Result : MANUAL" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "Postfix 서비스가 실행중이지 않음" >> "$RESULT_FILE" 2>&1
    echo "[31-END]" >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-31]Result : GOOD" >> "$RESULT_FILE" 2>&1
fi
echo >> "$RESULT_FILE" 2>&1
echo >> $RESULT_FILE 2>&1


echo "[U-32]일반사용자의 Sendmail 실행 방지"
echo "============================================================" >> "$RESULT_FILE" 2>&1
echo "[U-32]일반사용자의 Sendmail 실행 방지" >> "$RESULT_FILE" 2>&1
echo "============================================================" >> "$RESULT_FILE" 2>&1
echo "[32-START]" >> "$RESULT_FILE" 2>&1
if ! pgrep -x "sendmail" > /dev/null; then
    # Sendmail service is not running
    echo "★ Sendmail 서비스가 실행중이지 않음" >> "$RESULT_FILE" 2>&1
    echo "[32-END]" >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-32]Result : GOOD" >> "$RESULT_FILE" 2>&1
else
    # Sendmail service is running
    if [ "$(find /etc -name "sendmail.cf" | wc -l)" -eq 0 ]; then
        # sendmail.cf 파일을 찾을 수 없음
        echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> "$RESULT_FILE" 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ps -ef | grep sendmail | grep -v "grep" >> "$RESULT_FILE" 2>&1
        echo "[32-END]" >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-32]Result : MANUAL" >> "$RESULT_FILE" 2>&1
    else
        # sendmail.cf 파일이 존재하는 경우
        find /etc -name "sendmail.cf" -exec grep -i "O PrivacyOptions" {} + | grep -i "restrictqrun" > sendmailNcheck.txt
        if grep -qi "restrictqrun" sendmailNcheck.txt; then
            # restrictqrun 설정이 적용됨
            echo "★ 일반사용자의 Sendmail 실행 방지 설정이 적용됨" >> "$RESULT_FILE" 2>&1
            echo "[현황]" >> "$RESULT_FILE" 2>&1
            ps -ef | grep sendmail | grep -v "grep" >> "$RESULT_FILE" 2>&1
            cat sendmailNcheck.txt >> "$RESULT_FILE" 2>&1
            echo "[32-END]" >> "$RESULT_FILE" 2>&1
            echo >> "$RESULT_FILE" 2>&1
            echo "[U-32]Result : GOOD" >> "$RESULT_FILE" 2>&1
        else
            # restrictqrun 설정이 적용되지 않음
            echo "★ 일반사용자의 Sendmail 실행 방지 설정이 적용되지 않음" >> "$RESULT_FILE" 2>&1
            echo "[현황]" >> "$RESULT_FILE" 2>&1
            ps -ef | grep sendmail | grep -v "grep" >> "$RESULT_FILE" 2>&1
            cat sendmailNcheck.txt >> "$RESULT_FILE" 2>&1
            echo "[32-END]" >> "$RESULT_FILE" 2>&1
            echo >> "$RESULT_FILE" 2>&1
            echo "[U-32]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
        fi
    fi
fi
rm -rf sendmailNcheck.txt
echo >> "$RESULT_FILE" 2>&1
echo >> "$RESULT_FILE" 2>&1


### 운영체제별 BIND DNS 서버 바이너리 실행 파일 경로가 다르기에 확인 필요함
echo [U-33] DNS 보안 버전 패치
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-33] DNS 보안 버전 패치 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [33-START] >> $RESULT_FILE 2>&1
if netstat -tuln | grep ":53 " > /dev/null; then
# DNS service is running
dns_command="named"
if ! command -v $dns_command > /dev/null; then
	for path in "/usr/sbin/named" "/usr/sbin/named9" "/usr/local/sbin/named"; do
    	if [ -f "$path" ]; then
        	dns_command="$path"
        break
    	fi
    	done
fi
    if [ "$dns_command" != "named" ]; then
      # If a valid DNS command was found
      echo "★ DNS 서비스가 실행중이며 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
      echo "[현황]" >> $RESULT_FILE 2>&1
      $dns_command -v >> $RESULT_FILE 2>&1
	  echo "[33-END]" >> "$RESULT_FILE" 2>&1
      result="[U-33]Result : MANUAL"
    else
      # If no valid DNS command was found
      echo "★ DNS 서비스가 실행중이나 실행 데몬을 찾을 수 없음" >> $RESULT_FILE 2>&1
      result="[U-33]Result : MANUAL"
	  echo "[33-END]" >> "$RESULT_FILE" 2>&1
    fi
	else
    # DNS service is not running
    echo "★ DNS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
	result="[U-33]Result : GOOD"
	echo "[33-END]" >> "$RESULT_FILE" 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "[U-34] DNS Zone Transfer 설정"
echo "============================================================" >> "$RESULT_FILE" 2>&1
echo "[U-34] DNS Zone Transfer 설정" >> "$RESULT_FILE" 2>&1
echo "============================================================" >> "$RESULT_FILE" 2>&1
echo "[34-START]" >> "$RESULT_FILE" 2>&1
if ! netstat -anp | grep ":53 " > /dev/null; then
    # DNS 서비스가 실행 중이지 않음
    echo "★ DNS 서비스가 실행중이지 않음" >> "$RESULT_FILE" 2>&1
    echo "[34-END]" >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-34]Result : GOOD" >> "$RESULT_FILE" 2>&1
else
    # DNS 서비스가 실행 중인 경우
    cat /etc/bind/named.conf /etc/bind/named.rfc1912.zones /etc/bind/named.boot > dnstransfercheck.txt 2> /dev/null
    if [ ! -s dnstransfercheck.txt ]; then
        # 설정 파일을 찾을 수 없음
        echo "★ DNS 서비스가 실행중이나 설정파일을 찾을 수 없음" >> "$RESULT_FILE" 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        netstat -anp | grep ":53 " >> "$RESULT_FILE" 2>&1
        echo "[34-END]" >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-34]Result : MANUAL" >> "$RESULT_FILE" 2>&1
    else
        if ! grep -q "allow-transfer" dnstransfercheck.txt; then
            # DNS ZoneTransfer 설정이 적용되지 않음
            echo "★ DNS 서비스가 실행중이며 DNS ZoneTransfer 설정이 적용되지 않음" >> "$RESULT_FILE" 2>&1
            echo "[현황]" >> "$RESULT_FILE" 2>&1
            netstat -anp | grep ":53 " >> "$RESULT_FILE" 2>&1
            echo "[34-END]" >> "$RESULT_FILE" 2>&1
            echo >> "$RESULT_FILE" 2>&1
            echo "[U-34]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
        else
            # DNS ZoneTransfer 설정이 적용됨
            echo "★ DNS 서비스가 실행중이며 DNS ZoneTransfer 설정이 적용됨" >> "$RESULT_FILE" 2>&1
            echo "[현황]" >> "$RESULT_FILE" 2>&1
            netstat -anp | grep ":53 " >> "$RESULT_FILE" 2>&1
            grep "allow-transfer" dnstransfercheck.txt | grep -v "#" >> "$RESULT_FILE" 2>&1
            echo "[34-END]" >> "$RESULT_FILE" 2>&1
            echo >> "$RESULT_FILE" 2>&1
            echo "[U-34]Result : GOOD" >> "$RESULT_FILE" 2>&1
        fi
    fi
fi
rm -rf dnstransfercheck.txt
echo >> "$RESULT_FILE" 2>&1
echo >> "$RESULT_FILE" 2>&1

### ubuntu os = /etc/apache2/apach2.conf 파일 경로에서 검색하면됨
echo [U-35]웹서비스 디렉토리 리스팅 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-35]웹서비스 디렉토리 리스팅 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [35-START] >> $RESULT_FILE 2>&1
if [ -f /etc/apache2/apache2.conf ]
	then
		if [ `cat /etc/apache2/apache2.conf | grep -v '^ *#' | grep "Options Indexes FollowSymLinks" | wc -l` -eq 0 ]
			then
				echo "Indexs 옵션이 설정 되어 있지 않음" >> $RESULT_FILE 2>&1
				echo [35-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-35]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "Index 옵션이 설정 되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat /etc/apache2/apache2.conf | grep "Options Indexes FollowSymLinks" >> $RESULT_FILE 2>&1
				echo [35-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-35]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
			else
				echo "사용 중인 웹 서비스가 없습니다." >> $RESULT_FILE 2>&1
				echo [35-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-35]Result : N/A >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

### ubuntu os = /etc/apache2/apach2.conf 파일 경로에서 검색하면됨
echo [U-36]웹서비스 웹 프로세스 권한 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-36]웹서비스 웹 프로세스 권한 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [36-START] >> $RESULT_FILE 2>&1
if [ -f /etc/apache2/apache2.conf ]
	then
		if [ `cat /etc/apache2/apache2.conf | grep -v '^ *#' | grep "User root" | wc -l` -gt 0 ] && [ `cat /etc/apache2/apache2.conf | grep -v '^ *#' | grep "Group root" | wc -l` -gt 0 ]
			then
				echo "User & Group 부분에 root가 아닌 별도 계정으로 변경 되어 있지 않음" >> $RESULT_FILE 2>&1
				echo [36-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-36]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "User & Group 부분에 root가 아닌 별도 계정으로 변경됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat /etc/apache2/apache2.conf | grep -v '^ *#' | grep "Options Indexes FollowSymLinks" >> $RESULT_FILE 2>&1
				echo [36-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-36]Result : VULNERABL >> $RESULT_FILE 2>&1
		fi
			else
				echo "사용 중인 웹 서비스가 없습니다." >> $RESULT_FILE 2>&1
				echo [36-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-36]Result : N/A >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-37]웹서비스 상위 디렉토리 접근 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-37]웹서비스 상위 디렉토리 접근 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [37-START] >> $RESULT_FILE 2>&1
if [ -f "$apache2_conf" ]; then
	if [ `cat /etc/apache2/apache2.conf | grep -v '^ *#' | grep "AllowOverride *" | wc -l` -eq 0 ]
		then
			echo "상위 디렉터리에 이동제한을 설정함" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			cat /etc/apache2/apache2.conf | grep -v '^ *#' | grep "AllowOverride *" >> $RESULT_FILE 2>&1
			echo [37-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-37]Result : GOOD >> $RESULT_FILE 2>&1
		else
			echo "상위 디렉터리에 이동제한을 설정하지 않음" >> $RESULT_FILE 2>&1
			echo [37-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-37]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
else
	echo "사용 중인 웹 서비스가 없습니다." >> $RESULT_FILE 2>&1
    echo [37-END] >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo [U-37]Result : N/A >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-38]웹서비스 불필요한 파일 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-38]웹서비스 불필요한 파일 제거 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [38-START] >> $RESULT_FILE 2>&1
if [ -f "$apache2_conf" ]; then
	if [ `find /etc/apache2/apache2.conf -type f -name "manual" | wc -l` -eq 0 ]
		then
			echo "불필요한 파일 및 디렉터리 존재 하지 않음" >> $RESULT_FILE 2>&1
			echo [38-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-38]Result : GOOD >> $RESULT_FILE 2>&1
		else
			echo "불필요한 파일 및 디렉터리 존재함" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			find /etc/apache2/apache2.conf -type f -name "manual"
			echo [38-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-38]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
else
	echo "사용 중인 웹 서비스가 없습니다." >> $RESULT_FILE 2>&1
    echo [38-END] >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo [U-38]Result : N/A >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-39]웹서비스 링크 사용금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-39]웹서비스 링크 사용금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [39-START] >> $RESULT_FILE 2>&1
if [ -f "$apache2_conf" ]; then
	if [ `cat /etc/apache2/apache2.conf | grep -v '^ *#' | grep "Options Indexes FollowSymLinks" | wc -l` -gt 0 ]
		then
			echo "상위 디렉터리에 이동제한을 설정하지 않음" >> $RESULT_FILE 2>&1
			echo [39-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-39]Result : GOOD >> $RESULT_FILE 2>&1
		else
			echo "상위 디렉터리에 이동제한을 설정함" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			cat /etc/apache2/apache2.conf | grep -v '^ *#' | grep "Options Indexes FollowSymLinks"
			echo [39-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-39]Result : VULNERABL >> $RESULT_FILE 2>&1
	fi
else
	echo "사용 중인 웹 서비스가 없습니다." >> $RESULT_FILE 2>&1
    echo [39-END] >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo [U-39]Result : N/A >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-40]웹서비스 파일 업로드 및 다운로드 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-40]웹서비스 파일 업로드 및 다운로드 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [40-START] >> $RESULT_FILE 2>&1
EXPECTED_LIMIT=5000000
if [ -f "$APACHE_CONF" ]; then
    limit_value=$(grep -E "^LimitRequestBody\s+" "$APACHE_CONF" | awk '{print $2}')
    if [ -n "$limit_value" ]; then
        if [ "$limit_value" -le "$MAX_LIMIT" ]; then
            echo "LimitRequestBody 적정 파일 사이즈 용량 설정됨 (5MB 이하)" >> $RESULT_FILE 2>&1
			echo [40-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-40]Result : GOOD >> $RESULT_FILE 2>&1
        else
            echo "LimitRequestBody 적정 파일 사이즈 용량 설정이 초과됨 (5MB 초과)" >> $RESULT_FILE 2>&1
			echo [40-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-40]Result : VULNERABLE >> $RESULT_FILE 2>&1
        fi
    else
        	echo "LimitRequestBody 용량 설정이 없습니다." >> $RESULT_FILE 2>&1
			echo [40-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-40]Result : VULNERABLE >> $RESULT_FILE 2>&1
    fi
else
    echo "사용 중인 웹 서비스가 없습니다." >> $RESULT_FILE 2>&1
	echo [40-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
	echo [U-40]Result : N/A >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-41]웹서비스 영역의 분리
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-41]웹서비스 영역의 분리  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [41-START] >> $RESULT_FILE 2>&1
apache2_conf="/etc/apache2/apache2.conf"
expected_documentroot="/var/apache2/htdocs"
if [ -x "$(command -v apache2)" ]; then
    if [ -f "$apache2_conf" ]; then
        documentroot=$(awk -F'[ "]+' '/DocumentRoot / {print $2;}' "$apache2_conf")
        if [ "$documentroot" = "$expected_documentroot" ]; then
			echo "htdocs 디렉토리를 DocumentRoot로 사용 중임" $expected_documentroot >> $RESULT_FILE 2>&1
            echo [41-END] >> $RESULT_FILE 2>&1
            echo >> $RESULT_FILE 2>&1
            echo [U-41]Result : VULNERABLE >> $RESULT_FILE 2>&1
        else
			echo "htdocs 디렉토리를 DocumentRoot로 사용중이지 않음" $documentroot >> $RESULT_FILE 2>&1
            echo [41-END] >> $RESULT_FILE 2>&1
            echo >> $RESULT_FILE 2>&1
            echo [U-41]Result : GOOD >> $RESULT_FILE 2>&1
        fi
    else
		echo "apache 설정 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
        echo [41-END] >> $RESULT_FILE 2>&1
        echo >> $RESULT_FILE 2>&1
        echo [U-41]Result : N/A >> $RESULT_FILE 2>&1
    fi
else
    echo "사용 중인 웹 서비스가 없습니다. " >> $RESULT_FILE 2>&1
    echo [41-END] >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo [U-41]Result : N/A >> $RESULT_FILE 2>&1
fi

echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-42]최신 보안패치 및 벤더 권고사항 적용
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-42]최신 보안패치 및 벤더 권고사항 적용   >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [42-START] >> $RESULT_FILE 2>&1
	echo "★ 아래 현황을 기반으로 수동분석" >> $RESULT_FILE 2>&1
	echo "[현황]" >> $RESULT_FILE 2>&1
	echo "1. openssl version" >> $RESULT_FILE 2>&1
	openssl version >> $RESULT_FILE 2>&1
	echo "2. bash shell version" >> $RESULT_FILE 2>&1
	bash --version | grep "bash" >> $RESULT_FILE 2>&1
	dpkg -l | grep bash >> $RESULT_FILE 2>&1
	echo "2.1 bash 취약점 테스트(벤더사 제공)" >> $RESULT_FILE 2>&1
	env x='() { :;}; echo vulnerable' bash -c "echo test" >> $RESULT_FILE 2>&1
	echo [42-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
	echo [U-42]RESULT : MANUAL >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

### uU, wU ,bU 등의 로그를 확인하여 마지막 로그인 시간, 접속 IP, 실패한 이력 등을 확인하여 계정 탈취 공격 및 시스템 해킹 여부를 검토
### sulog를 확인하여 허용된 계정 외에 su 명령어를 통해 권한상승을 시도하였는지 검토
### xferlog를 확인하여 비인가자의 ftp 접근 여부를 검토
### 로그 분석에 대한 결과 보고서 작성 및 분석 결과보고서 체계 수립 되어 있습니까?
echo [U-43]로그의 정기적 검토 및 보고
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-43]로그의 정기적 검토 및 보고  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [43-START] >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo "★ 인터뷰 점검 항목" >> $RESULT_FILE 2>&1
echo [43-END] >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [U-43]Result : MANUAL >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-44]root 이외의 UID가 ‘0’ 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-44]root 이외의 UID가 ‘0’ 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [44-START] >> $RESULT_FILE 2>&1
if [ `awk -F: '$3==0 {print $0}' /etc/passwd | grep -v 'root' | wc -l` -eq 0 ]
	then
		echo "★ root 이외의 UID가 '0'인 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F: '$3==0 {print $0}' /etc/passwd >> $RESULT_FILE 2>&1
		echo [44-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-44]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ root 이외의 UID가 '0'인 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F: '$3==0 {print $0}' /etc/passwd >> $RESULT_FILE 2>&1
		echo [44-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-44]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

### 우분투에는 wheel 그룹이 없습니다.
### 어쩄든 결과 파악하기 위해서 MANUAL 인터뷰 필요함 추후 개선 필요
echo [U-45]root 계정 su 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-45]root 계정 su 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [45-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/group | grep wheel | wc -l` -eq 0 ]
	then
		echo "wheel 그룹이 없습니다." >> $RESULT_FILE 2>&1
		echo "/etc/pam.d/su 파일을 통해 su 명령어 사용 제한 설정에 대해서 확인하도록 하겠습니다." >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/pam.d/su | grep -v '#'  >> $RESULT_FILE 2>&1
		echo [45-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-45]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		echo "wheel 그룹이 존재합니다. 추가된 사용자에 대한 검토 메뉴얼 필요." >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/group | grep wheel  >> $RESULT_FILE 2>&1
		echo [45-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-45]Result : MANUAL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-46]패스워드 최소 길이 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-46]패스워드 최소 길이 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [46-START] >> $RESULT_FILE 2>&1
if [ -f /etc/login.defs ]; then
    pass_min_len=$(awk '/^PASS_MIN_LEN/ {print $2}' /etc/login.defs)
    if [[ "$pass_min_len" -ge 8 ]]; then
        echo "패스워드 최소 길이를 준수하고 있음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/login.defs | grep -v '^ *#' | grep "PASS_MIN_LEN" >> $RESULT_FILE 2>&1
		echo [46-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-46]Result : GOOD >> $RESULT_FILE 2>&1
    else
        echo "패스워드 최소 길이를 준수하고 있지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/login.defs | grep -v '^ *#' | grep "PASS_MIN_LEN" >> $RESULT_FILE 2>&1
		echo [46-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-46]Result : VULNERABLE >> $RESULT_FILE 2>&1
    fi
else
    echo "/etc/login.defs 파일을 찾을 수 없음."
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-47]패스워드 최대 사용기간 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-47]패스워드 최대 사용기간 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [47-START] >> $RESULT_FILE 2>&1
MAX_PASSWORD_AGE=90
MAX_PASSWORD_AGE_CONFIG=$(cat /etc/login.defs | grep -v '^ *#' | grep "PASS_MAX_DAYS" | awk '{print $2}')
if [ -z "$MAX_PASSWORD_AGE_CONFIG" ]
	then
		echo "패스워드 최대 사용기간 설정이 되어 있지 않음"
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/login.defs | grep "PASS_MAX_DAYS" >> $RESULT_FILE 2>&1
		echo [47-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-47]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
if [ "$MAX_PASSWORD_AGE_CONFIG" -le "$MAX_PASSWORD_AGE" ]
	then
    	echo "패스워드 최대 사용기간을 준수하고 있음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/login.defs | grep "PASS_MAX_DAYS" >> $RESULT_FILE 2>&1
		echo [47-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-47]Result : GOOD >> $RESULT_FILE 2>&1
else
		echo "패스워드 최대 사용기간을 준수하고 있지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/login.defs | grep "PASS_MAX_DAYS" >> $RESULT_FILE 2>&1
		echo [47-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-47]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-48]패스워드 최소 사용기간 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-48]패스워드 최소 사용기간 설정 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [48-START] >> $RESULT_FILE 2>&1
if [ -f /etc/login.defs ]
	then
		if [ `grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 최소 사용 기간 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo [48-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-48]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				if [ `grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" | awk '{print $2}'` -eq 1 ]
					then
						echo "★ 패스워드 최소 사용 기간 설정이 정책에 맞게 적용되어 있음" >> $RESULT_FILE 2>&1				
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo [48-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1	
						echo [U-48]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 패스워드 최소 사용 기간 설정이 적용되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo [48-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-48]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
	else
		echo "★ /etc/login.defs 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [48-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-48]Result : MANUAL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-49]불필요한 계정 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-49]불필요한 계정 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [49-START] >> $RESULT_FILE 2>&1
touch check_49_3.txt
cat /etc/passwd | egrep -v 'false|nologin|null|halt|sync|shutdown|rpm|new' > check_49_1.txt
cat check_49_1.txt | awk -F: '{print $1}' > check_49_2.txt
for i in `cat check_49_2.txt`; do 
lastlog -u $i | grep $i >> check_49_3.txt; done
if [ `awk -F ":" '$3 >= 500 {print $0}' /etc/passwd | egrep -v "nfsnobody|false|nologin" | wc -l` -eq 0 ]
	then
		echo "★ UID 500 이상 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "1. 계정별 최근 접속기록" >> $RESULT_FILE 2>&1
		cat check_49_3.txt >> $RESULT_FILE 2>&1
		echo [49-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-49]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ UID 500 이상 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F ":" '$3 >= 500 {print $0}' /etc/passwd | egrep -v "nfsnobody|false|nologin" >> $RESULT_FILE 2>&1
		echo "1. 계정별 최근 접속기록" >> $RESULT_FILE 2>&1
		cat check_49_3.txt >> $RESULT_FILE 2>&1
		echo [49-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-49]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm check_49_1.txt
rm check_49_2.txt
rm check_49_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-50]관리자 그룹에 최소한의 계정 포함
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-50]관리자 그룹에 최소한의 계정 포함 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [50-START] >> $RESULT_FILE 2>&1
grep "^root" /etc/group | awk -F ":" '{print $4}' | sed s/,/\\n/g | grep -v "^root$" | wc -w > check_50.txt
if [ `cat check_50.txt` -eq 0 ]
	then
		echo "★ 관리자 그룹에 root 이외의 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep "^root" /etc/group >> $RESULT_FILE 2>&1
		echo [50-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-50]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 관리자 그룹에 root 이외의 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep "^root" /etc/group >> $RESULT_FILE 2>&1
		echo [50-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-50]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm -rf check_50.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-51]계정이 존재하지 않는 GID 금지 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-51]계정이 존재하지 않는 GID 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [51-START] >> $RESULT_FILE 2>&1
	awk -F : '$4 == null {print $0}' /etc/group | awk -F : '$3 >= 500 {print $0}' > check_group.txt
	awk -F : '{print $4}' /etc/passwd > check_passwd.txt
	for TGID in `cat check_passwd.txt`
	do
		grep -v ":$TGID:" check_group.txt > check_51.txt
		cat check_51.txt > check_group.txt
	done
	if [ `cat check_group.txt | wc -w` -eq 0 ]
	then
		echo "★ 계정이 존재하지 않는 500 이상 GID가 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [51-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-51]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 계정이 존재하지 않는 500 이상 GID가 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1 
		cat check_group.txt >> $RESULT_FILE 2>&1 
		echo [51-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-51]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
	rm -rf check_group.txt
	rm -rf check_passwd.txt
	rm -rf check_51.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-52]동일한 UID 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-52]동일한 UID 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [52-START] >> $RESULT_FILE 2>&1
awk -F : '{print $3}' /etc/passwd > U_passwd.txt
	if [ `cat U_passwd.txt | sort | uniq -d | wc -l` -eq 0 ]
		then
			echo "★ 중복된 UID가 존재하지 않음" >> $RESULT_FILE 2>&1
			echo [52-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-52]Result : GOOD >> $RESULT_FILE 2>&1
		else
			echo "★ 중복된 UID가 존재함" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1 
			DUID=`cat U_passwd.txt | sort | uniq -d`
			grep "x:$DUID:" /etc/passwd >> $RESULT_FILE 2>&1
			echo [52-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-52]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
	rm -rf U_passwd.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-53]사용자 shell 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-53]사용자 shell 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [53-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" |  awk -F: '{print $7}'| egrep -v 'false|nologin|null|halt|sync|shutdown' | wc -l` -eq 0 ]
	then
		echo "★ 점검 대상 시스템 계정에 쉘이 부여되지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" >> $RESULT_FILE 2>&1
		echo [53-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-53]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 점검 대상 시스템 계정에 쉘이 부여됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" >> $RESULT_FILE 2>&1
		echo [53-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-53]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-54] 세션 타임아웃 설정
echo "============================================================" >> "$RESULT_FILE" 2>&1
echo [U-54] 세션 타임아웃 설정  >> "$RESULT_FILE" 2>&1
echo "============================================================" >> "$RESULT_FILE" 2>&1
echo "[54-START]" >> "$RESULT_FILE" 2>&1
PROFILE_FILE="/etc/profile"
CSH_FILE="/etc/csh.cshrc"
# 세션 타임아웃 값 추출 함수
get_timeout_value() {
    local file="$1"
    local pattern="$2"
    local timeout_value=$(grep -E "$pattern" "$file" | awk -F'=' '{print $2}')
    echo "$timeout_value"
}
# /etc/profile 파일의 타임아웃 값 확인
profile_tmout=$(get_timeout_value "$PROFILE_FILE" "^\s*export TMOUT=[0-9]{1,3}$")
# /etc/csh.cshrc 파일의 타임아웃 값 확인
if [ -f "$CSH_FILE" ]; then
    csh_tmout=$(get_timeout_value "$CSH_FILE" "^\s*set autologout=[0-9]{1,3}$")
else
    csh_tmout=""
fi
# 설정된 타임아웃 값이 600초 이하인지 확인하여 결과 출력
if [[ -n "$profile_tmout" && "$profile_tmout" -le 600 ]] || [[ -n "$csh_tmout" && "$csh_tmout" -le 600 ]]; then
    echo "세션 타임아웃 옵션이 600초 이하로 올바르게 설정되었습니다." >> "$RESULT_FILE" 2>&1
    echo "[54-END]" >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-54] Result: GOOD" >> "$RESULT_FILE" 2>&1
else
    echo "세션 타임아웃 옵션이 올바르게 설정되지 않았습니다." >> "$RESULT_FILE" 2>&1
    echo "[54-END]" >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-54] Result: VULNERABLE" >> "$RESULT_FILE" 2>&1
fi
echo >> "$RESULT_FILE" 2>&1
echo >> "$RESULT_FILE" 2>&1


echo [U-55]hosts.lpd 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-55]hosts.lpd 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [55-START] >> $RESULT_FILE 2>&1
if [ -e /etc/hosts.lpd ]
	then
		if [ "$(stat -c %a /etc/hosts.lpd)" = "600" ] && [ "$(stat -c %U /etc/hosts.lpd)" = "root" ]
			then
				echo "hosts.lpd 파일의 소유자 및 퍼미션(600)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo [55-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-55]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "hosts.lpd 파일의 소유자 및 퍼미션(600)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/hosts.lpd >> $RESULT_FILE 2>&1
				echo [9-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-9]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
			else
				echo "/etc/hosts.lpd file missing" >> "$RESULT_FILE" 2>&1
				echo "[55-END]" >> "$RESULT_FILE" 2>&1
				echo >> "$RESULT_FILE" 2>&1
				echo "[U-55]Result : GOOD" >> "$RESULT_FILE" 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-56]UMASK 설정 관리
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-56]UMASK 설정 관리  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [56-START] >> $RESULT_FILE 2>&1
if [ `umask` -eq 0022 ]
	then
		echo "★ UMASK 값이 적절하게 설정됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1		
		echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
		echo [56-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-56]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `umask` -eq 0027 ]
			then
				echo "★ UMASK 값이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1		
				echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
				echo [56-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-56]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ UMASK 값이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1		
				echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
				echo [56-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-56]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

### 홈 디렉터리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거되었다면 양호 
echo [U-57]홈디렉토리 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-57]홈디렉토리 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [57-START] >> $RESULT_FILE 2>&1
	ls -l /home/ | grep -v "+found" | sed -n '2,$p' > U_57_1.txt
	cat U_57_1.txt | grep -v "^........w." > U_57_2.txt
	if [ `cat U_57_1.txt | wc -l` -eq 0 ]
	then
		echo "★ 사용자 홈디렉토리가 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [57-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-57]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `diff U_57_1.txt U_57_2.txt | wc -l` -eq 0 ]
		then
			echo "★ 사용자 홈디렉토리의 퍼미션(o-w)이 적절하게 설정되어 있음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			cat U_57_1.txt >> $RESULT_FILE 2>&1
			echo [57-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-57]Result : GOOD >> $RESULT_FILE 2>&1
		else
			echo "★ 사용자 홈디렉토리의 퍼미션(o-w)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			cat U_57_1.txt | grep "^........w." >> $RESULT_FILE 2>&1
			echo [57-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-57]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	fi
	rm -rf U_57_1.txt
	rm -rf U_57_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "[U-58]홈디렉토리로 지정한 디렉토리의 존재 관리" >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo "[58-START]" >> $RESULT_FILE 2>&1
# /etc/passwd 파일에서 UID가 500 이상인 사용자 정보 추출하여 U_58_1.txt 파일에 저장
cat /etc/passwd | egrep -v 'false|nologin|sync' | awk -F: '$3>=500 {print $1 ":" $6}' > U_58_1.txt
# 홈 디렉토리의 존재 여부 확인하여 U_58_3.txt 파일에 저장
while IFS=: read -r user homedir; do
    if [ ! -d "$homedir" ]; then
        echo "$user:$homedir" >> U_58_3.txt
    fi
done < U_58_1.txt
# U_58_2.txt와 U_58_3.txt를 비교하여 존재하지 않는 홈 디렉토리를 확인
if [ -s U_58_3.txt ]; then
    echo "★ 홈디렉토리가 존재하지 않는 계정이 존재함" >> $RESULT_FILE 2>&1
    echo "[현황]" >> $RESULT_FILE 2>&1
    # 존재하지 않는 홈 디렉토리를 출력하고 해당 계정 리스트를 추가
    while IFS=: read -r user homedir; do
        echo "계정 $user의 홈 디렉토리 $homedir가 존재하지 않음" >> $RESULT_FILE 2>&1
    done < U_58_3.txt
    echo "[현황-END]" >> $RESULT_FILE 2>&1
    echo "[58-END]" >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo "[U-58]Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "★ 홈디렉토리가 존재하지 않는 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
    echo "[58-END]" >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo "[U-58]Result : GOOD" >> $RESULT_FILE 2>&1
fi
# 사용한 임시 파일 정리
rm -f U_58_1.txt U_58_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-59]숨겨진 파일 및 디렉토리 검색 및 제거 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [59-START] >> $RESULT_FILE 2>&1
# 검색 패턴 변수 지정
Var_59_1="font-unix|ICE-unix|ifstat|Test-unix|X11-unix|XIM-unix|esd-"
# /tmp 디렉토리에서 숨겨진 파일 검색
find /tmp -type f -name ".*" | grep -Ev "$Var_59_1" > U_59_1.txt
# 결과 확인
if [ $(wc -l < U_59_1.txt) -eq 0 ]; then
    echo "★ /tmp 디렉토리에 숨겨진 속성 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
    echo "[59-END]" >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo "[U-59]Result : GOOD" >> $RESULT_FILE 2>&1
else
    echo "★ /tmp 디렉토리에 숨겨진 속성 파일이 존재함" >> $RESULT_FILE 2>&1
    echo "[현황]" >> $RESULT_FILE 2>&1
    cat U_59_1.txt >> $RESULT_FILE 2>&1
    echo "[59-END]" >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo "[U-59]Result : MANUAL" >> $RESULT_FILE 2>&1
fi
# 임시 파일 정리
rm -rf U_59_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-60]ssh 원격접속 허용
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-60]ssh 원격접속 허용  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [60-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "sshd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SSH 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [60-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-60]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		echo "★ SSH 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "sshd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [60-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-60]Result : GOOD >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-61]ftp 서비스 확인
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-61]ftp 서비스 확인  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [61-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [61-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-61]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ FTP 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "ftpd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [61-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-61]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-62]ftp 계정 shell 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-62]ftp 계정 shell 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [62-START] >> $RESULT_FILE 2>&1
cat /etc/passwd | grep -w "^ftp" > U_62_1.txt
if [ `cat U_62_1.txt | wc -l` -eq 0 ]
	then
		echo "★ /etc/passwd 파일에 'ftp' 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [62-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-62]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat U_62_1.txt | awk -F: '{print $7}' | egrep -v "false|nologin|null|halt|sync|shutdown" | wc -l` -eq 0 ]
			then
				echo "★ 'ftp' 계정에 로그인 가능한 쉘이 부여되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat U_62_1.txt >> $RESULT_FILE 2>&1
				echo [62-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-62]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 'ftp' 계정에 로그인 가능한 쉘이 부여됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat U_62_1.txt >> $RESULT_FILE 2>&1
				echo [62-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-62]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf U_62_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-63]ftpusers 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-63]ftpusers 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [63-START] >> $RESULT_FILE 2>&1
if [ -e /etc/ftpusers ]
	then
		if [ "$(stat -c %a /etc/ftpusers)" = "640" ] && [ "$(stat -c %U /etc/ftpusers)" = "root" ]
			then
				echo "ftpusers 파일의 소유자 및 퍼미션(640)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo [63-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-63]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "ftpusers 파일의 소유자 및 퍼미션(640)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/ftpusers >> $RESULT_FILE 2>&1
				echo [63-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-63]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
			else
				echo "/etc/ftpusers file missing" >> "$RESULT_FILE" 2>&1
				echo "[63-END]" >> "$RESULT_FILE" 2>&1
				echo >> "$RESULT_FILE" 2>&1
				echo "[U-63]Result : GOOD" >> "$RESULT_FILE" 2>&1
	fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-64]ftpusers 파일 설정 FTP 서비스 root 계정 접근제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-64]ftpusers 파일 설정 FTP 서비스 root 계정 접근제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [64-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [64-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-64]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "ftpusers" -exec ls -l {} \; > U_64_1.txt
		if [ `cat U_64_1.txt | wc -l` -eq 0 ]
			then
				echo "★ ftpusers 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [64-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-64]Result : GOOD >> $RESULT_FILE 2>&1
			else
				find /etc -name "ftpusers" -exec cat {} \; > U_64_2.txt
				if [ `cat U_64_2.txt | grep "root" | grep -v "^ *#" | wc -l` -gt 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, ftpusers 파일에 root가 존재함" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat U_64_1.txt >> $RESULT_FILE 2>&1
						cat U_64_2.txt >> $RESULT_FILE 2>&1
						echo [64-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-64]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, ftpusers 파일에 root가 존재하지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat U_64_1.txt >> $RESULT_FILE 2>&1
						cat U_64_2.txt >> $RESULT_FILE 2>&1
						echo [64-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-64]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi	
fi		
rm -rf U_64_1.txt
rm -rf U_64_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


### 점검 방법 “/etc/at.allow”, “/etc/at.deny” 파일의 소유자 및 권한 확인
### 위에 제시한 파일의 소유자가 root가 아니거나 파일의 권한이  이하가 아닌 경우 취약
echo [U-65]at 서비스 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-65]at 서비스 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ -e /etc/at.allow ] && [-e /etc/at.deny]
	then
		if [ "$(stat -c %a /etc/at.allow)" >= "750" ] && ["$(stat -c %a /etc/at.deny)" >= "750" ] && [ "$(stat -c %U /etc/at.allow)" = "root"] && [ "$(stat -c %U /etc/at.allow)" = "root" ]
			then
				echo "at.allow 파일과 at.deny 파일의 소유자 및 퍼미션(750)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo [65-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-65]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "at.allow 파일 또는 at.deny 소유자 및 퍼미션(750)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/at.allow >> $RESULT_FILE 2>&1
				ls -alL /etc/deny.allow >> $RESULT_FILE 2>&1
				echo [65-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-65]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
			else
				echo "/etc/at.allow 파일 또는 at.deny 파일이 없습니다." >> $RESULT_FILE 2>&1
				echo "[65-END]" >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-65]Result : GOOD >> $RESULT_FILE 2>&1
	fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-66]SNMP 서비스 구동 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-66]SNMP 서비스 구동 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "snmp" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SNMP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [66-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-66]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ SNMP 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "snmp" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [66-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-66]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-67]SNMP 서비스 Community String의 복잡성 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-67]SNMP 서비스 Community String의 복잡성 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "snmpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SNMP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [67-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-67]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "snmpd.conf" -exec cat {} \; > U_67_1.txt
		if [ `cat U_67_1.txt | wc -l` -gt 0 ]
			then
				if [ `cat U_67_1.txt | grep "public" | grep -v "^ *#" | wc -l` -eq 0 ]
					then
						echo "★ SNMP Community String이 임의의 값으로 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat U_67_1.txt | grep -v "^ *#" >> $RESULT_FILE 2>&1
						echo [67-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-67]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ SNMP Community String이 기본값으로 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat U_67_1.txt | grep -v "^ *#" >> $RESULT_FILE 2>&1
						echo [67-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-67]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				echo "★ SNMP 서비스가 실행중이나 설정파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [67-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-67]Result : MANUAL >> $RESULT_FILE 2>&1
		fi						
fi
rm -rf U_67_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


# 로그인 시 출력되는 메시지는 /etc/update-motd.d 경로에서 10-help-text 스크립트를 통해서 출력됨
echo [U-68]로그온 시 경고 메시지 제공
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-68]로그온 시 경고 메시지 제공  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
files_to_check=("/etc/motd" "/etc/issue.net" "/etc/vsftpd/vsftpd.conf" "/etc/mail/sendmail.cf" "/etc/named.conf")
# Loop through the files and check if they exist
for file in "${files_to_check[@]}"; do
    if [ -e "$file" ]; then
		echo "$file 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat $file >> $RESULT_FILE 2>&1
		echo [U-68]Result : MANUAL >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
    else
        echo "$file 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [U-68]Result : N/A >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
    fi
done


echo [U-69]NFS 설정파일 접근권한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-69]NFS 설정파일 접근권한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
file="/etc/exports"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 644 ]; then
		echo "★ /etc/exports 파일의 퍼미션(644)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ls -l /etc/exports >> $RESULT_FILE 2>&1
		echo [69-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-69]Result : GOOD >> $RESULT_FILE 2>&1
    else
		echo "★ /etc/exports 파일의 퍼미션(644)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ls -l /etc/exports >> $RESULT_FILE 2>&1
		echo [69-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-69]Result : VULNERABLE >> $RESULT_FILE 2>&1
    fi
else
    echo "The /etc/exports 파일을 찾을 수 없음." >> "$RESULT_FILE" 2>&1
    echo [69-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-69]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-70]expn, vrfy 명령어 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-70]expn, vrfy 명령어 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [70-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-70]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [70-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-70]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > U_70.txt \;			
				cat U_70.txt | grep -i "O PrivacyOptions" > U_70_1.txt
				if [ `cat U_70_1.txt | grep -v "^ *#" | grep "noexpn" | grep "novrfy" | wc -l` -eq 0 ]
					then
						echo "★ Sendmail 서비스가 실행중이며 sendmail.cf 파일에 noexpn, novrfy 옵션이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat U_70_1.txt >> $RESULT_FILE 2>&1
						echo [70-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-70]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ Sendmail 서비스가 실행중이며 sendmail.cf 파일에 noexpn, novrfy 옵션이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat U_70_1.txt >> $RESULT_FILE 2>&1
						echo [70-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-70]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf U_70.txt
rm -rf U_70_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


### /etc/apache2/apache2.conf 경로에서 ServerTokents Prod 옵션과 ServerSignature off 옵션 설정이 되어 있는지 확인 필요
echo [U-71]Apache 웹 서비스 정보 숨김
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-71]Apache 웹 서비스 정보 숨김  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
### 변수 선언
APACHE_CONF_FILE="/etc/apache2/apache2.conf"

if [ -e "$APACHE_CONF_FILE" ]
	then
    # Check if ServerTokens and ServerSignature options are set
    	if grep -qE "^\s*ServerTokens\s+Prod" "$APACHE_CONF_FILE" && grep -qE "^\s*ServerSignature\s+Off" "$APACHE_CONF_FILE"
		then
        echo "apache2.conf 파일에 올바르게 설정되어 있습니다." >> $RESULT_FILE 2>&1
		echo [71-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-71]Result : GOOD >> $RESULT_FILE 2>&1
else
        echo "apache2.conf 파일에 올바르지 않게 설정되어 있습니다." >> $RESULT_FILE 2>&1
		echo [71-END] >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep "ServerTokens Prod" /etc/apache2/apache2.conf | grep -v "#" >> $RESULT_FILE 2>&1
		grep "ServerSignature Off" /etc/apache2/apache2.conf | grep -v "#" >> $RESULT_FILE 2>&1
		echo "공란이라면 ServerTonkens / ServerSignature 설정이 없는 것입니다." >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-71]Result : VULNERABLE >> $RESULT_FILE 2>&1
   	 	fi
else
	echo "apache2.conf 파일이 없습니다." >> $RESULT_FILE 2>&1
	echo [71-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
	echo [U-71]Result : N/A >> $RESULT_FILE 2>&1
    
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-72]정책에 따른 시스템 로깅 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-72]정책에 따른 시스템 로깅 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ -f /etc/syslog.conf ]
	then
		cat /etc/syslog.conf | grep -v "#" | awk '$0 != null {print $0}' > U_72_1.txt
	else
		if [ -f /etc/rsyslog.conf ]
			then
				cat /etc/rsyslog.conf | grep -v "#" | awk '$0 != null {print $0}' > U_72_1.txt
				cat /etc/rsyslog.d/50-default.conf | egrep -v ^[[:space:]]*$ | grep -v '#' >  U_72_1.txt
			else
				echo "★ (r)syslog.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [72-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-72]Result : MANUAL >> $RESULT_FILE 2>&1
		fi
fi
#if [ `cat U_72_1.txt | egrep -w "cron.\*|authpriv.\*|\*.info" | wc -l` -eq 3 ]
if [ `cat U_72_1.txt |  egrep "cron.\*|authpriv.\*|\*.info|mail.\*|\*.alert|\*.emerg|\/var\/log\/message|kern.\*" | grep -v '#' | wc -l` -gt 5 ]
	then
		echo "★ (r)syslog.conf 설정이 적절하게 설정됨 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat U_72_1.txt >> $RESULT_FILE 2>&1
		echo [72-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-72]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 아래 현황을 기반으로 수동분석 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat U_72_1.txt |  egrep "cron.\*|authpriv.\*|\*.info|mail.\*|\*.alert|\*.emerg|\/var\/log\/message|kern.\*" | grep -v '#' >> $RESULT_FILE 2>&1
		echo [72-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-72]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm -rf U_72_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "주통 기반 72개 항목 OS에 대한 점검이 완료되었습니다." >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Version ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
uname -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/issue >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ ping test ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ping -c 3 www.google.com >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Interface ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ifconfig -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ cat /etc/passwd ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/passwd  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ cat /etc/shadow ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/shadow  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Socket ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo -e "netstat -lntp" >> $RESULT_FILE 2>&1
netstat -anp | head -200 >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo -e "ss -lntp" >> $RESULT_FILE 2>&1
ss -lntp >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Daemon ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "ps -ef" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ps -ef >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ TCP Wrapper]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "1) /etc/hosts.deny" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/hosts.deny >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "2) /etc/hosts.allow" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/hosts.allow >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "외부 패키지 라이브러리 사용 현황 조사 시작합니다." >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo "1) APT 패키지 검사" >> $RESULT_FILE 2>&1
if dpkg-query -W -f='${Package} ${Version}\n' >> $RESULT_FILE 2>&1; then
    if [ -s $RESULT_FILE ]; then
        true  # 빈 블록 방지
    else
        echo "APT 패키지 데이터가 없습니다." >> $RESULT_FILE 2>&1
    fi
else
    echo "APT 패키지가 설치되지 않았습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo "2) Snap 패키지 검사" >> $RESULT_FILE 2>&1
if snap list | awk 'NR>1 {print $1, $2}' >> $RESULT_FILE 2>&1; then
    if [ -s $RESULT_FILE ]; then
        true  # 빈 블록 방지
    else
        echo "Snap 패키지 데이터가 없습니다." >> $RESULT_FILE 2>&1
    fi
else
    echo "Snap 패키지가 설치되지 않았습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo "3) pip 패키지 검사" >> $RESULT_FILE 2>&1
# python pip 검사
echo "3-1 python 검사 결과" >> $RESULT_FILE 2>&1
if command -v pip &> /dev/null; then
    pip list --format=columns | awk 'NR>2 {print $1, $2}' >> $RESULT_FILE 2>&1
    if [ ! -s $RESULT_FILE ]; then
        echo "python pip 패키지 데이터가 없습니다." >> $RESULT_FILE 2>&1
    fi
else
    echo "python pip 패키지가 설치되지 않았습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

# python3 pip 검사
echo "3-2) python3 검사 결과" >> $RESULT_FILE 2>&1
if command -v pip3 &> /dev/null; then
    pip3 list --format=columns | awk 'NR>2 {print $1, $2}' >> $RESULT_FILE 2>&1
    if [ ! -s $RESULT_FILE ]; then
        echo "python3 pip 패키지 데이터가 없습니다." >> $RESULT_FILE 2>&1
    fi
else
    echo "python3 pip 패키지가 설치되지 않았습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "4) npm 패키지 검사" >> $RESULT_FILE 2>&1
# npm 설치 여부 확인
if ! command -v npm &> /dev/null
then
    echo "npm 설치되어 있지 않습니다." >> $RESULT_FILE 2>&1
else
    # jq 설치 여부 확인
    if ! command -v jq &> /dev/null
    then
        echo "jq 설치되어 있지 않습니다. npm 패키지 목록을 제대로 출력할 수 없습니다." >> $RESULT_FILE 2>&1
    else
        # npm 패키지가 하나도 없을 경우 데이터가 없다고 출력
        npm_list=$(npm list -g --depth=0 --json)
        if [ "$(echo "$npm_list" | jq '.dependencies' | length)" -eq 0 ]; then
            echo "npm 패키지 데이터가 없습니다." >> $RESULT_FILE 2>&1
        else
            echo "$npm_list" | jq -r '.dependencies | to_entries[] | "\(.key) \(.value.version)"' >> $RESULT_FILE 2>&1
        fi
    fi
fi
echo "============================================================" >> $RESULT_FILE 2>&1
echo "외부 패키지 라이브러리 사용 현황 조사 완료되었습니다." >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "Nginx/Tomcat 취약점 진단 수행합니다." >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

### 서비스가 설치되었는지 확인하는 함수
check_nginx_installed() {
    if systemctl list-units --type=service --all | grep -q "nginx"; then
        echo "nginx 서비스가 설치되어 있습니다." >> $RESULT_FILE
        return 0  # nginx가 설치되어 있으면 0 반환
    else
        echo "nginx 서비스가 설치되지 않았습니다." >> $RESULT_FILE
        return 1  # nginx가 설치되지 않으면 1 반환
    fi
}

check_tomcat_installed() {
    # tomcat7, tomcat8, tomcat9, tomcat10 중 하나라도 서비스에 존재하는지 확인
    if systemctl list-units --type=service --all | grep -q "tomcat"; then
        echo "Tomcat 서비스가 설치되어 있습니다." >> $RESULT_FILE
        return 0  # Tomcat이 설치되었으면 0 반환
    else
        echo "Tomcat 서비스가 설치되지 않았습니다." >> $RESULT_FILE
        return 1  # Tomcat이 설치되지 않으면 1 반환
    fi
}

### 서비스가 실행 중인지 확인하는 함수
check_nginx_running() {
    if systemctl is-active --quiet "nginx"; then
        echo "nginx 서비스 실행 중입니다." >> $RESULT_FILE
        return 0  # nginx가 실행 중이면 0 반환
    else
        echo "nginx 서비스 실행 중이 아닙니다." >> $RESULT_FILE
        return 1  # nginx가 실행 중이 아니면 1 반환
    fi
}

check_tomcat_running() {
    # tomcat7, tomcat8, tomcat9, tomcat10 중 실행 중인 서비스를 확인
    if systemctl is-active --quiet tomcat7 || systemctl is-active --quiet tomcat8 || systemctl is-active --quiet tomcat9 || systemctl is-active --quiet tomcat10; then
        echo "Tomcat 서비스 실행 중." >> $RESULT_FILE
        return 0  # Tomcat 서비스가 실행 중이면 0 반환
    else
        echo "Tomcat 서비스 실행 중이 아닙니다." >> $RESULT_FILE
        return 1  # Tomcat 서비스가 실행 중이 아니면 1 반환
    fi
}

### Tomcat 설치 경로 자동 탐색 함수
find_tomcat_home() {
    CANDIDATE_PATHS=(
        "/var/lib/tomcat9"
        "/var/lib/tomcat8"
        "/var/lib/tomcat10"
        "/opt/tomcat"
        "/opt/tomcat8"
        "/opt/tomcat9"
        "/opt/tomcat10"
        "/usr/share/tomcat"
        "/usr/share/tomcat8"
        "/usr/share/tomcat9"
        "/usr/share/tomcat10"
        "/usr/local/tomcat"
        "/usr/local/tomcat8"
        "/usr/local/tomcat9"
        "/usr/local/tomcat10"
        "/etc/tomcat"
        "/etc/tomcat8"
        "/etc/tomcat9"
        "/etc/tomcat10"
        "/home/tomcat"
        "/var/tomcat"
        "/var/lib/tomcat11"
        "/opt/tomcat11"
        "/usr/share/tomcat11"
        "/usr/local/tomcat11"
        "/etc/tomcat11"
    )
	# 설치 디렉토리 찾기
    for path in "${CANDIDATE_PATHS[@]}"; do
        if [[ -d "$path" && -f "$path/bin/catalina.sh" ]]; then
            echo "$path"
            return 0
        fi
    done

    TOMCAT_PATH=$(find / -name "catalina.sh" 2>/dev/null | head -n 1)
    if [[ -n "$TOMCAT_PATH" ]]; then
        echo "$(dirname "$(dirname "$TOMCAT_PATH")")"
        return 0
    fi

    echo "Tomcat 설치 경로를 찾을 수 없습니다."
    return 1
}
# Tomcat 취약점 진단 수행 함수
check_tomcat_vulnerability() {
    TOMCAT_HOME=$(find_tomcat_home)
    if [[ "$TOMCAT_HOME" == "Tomcat 설치 경로를 찾을 수 없습니다." ]]; then
        echo "Tomcat이 설치되지 않았습니다. 점검을 중단합니다." >> $RESULT_FILE 2>&1
        return 1
    fi

    TOMCAT_USERS_FILE="$TOMCAT_HOME/conf/tomcat-users.xml"
    TOMCAT_WEBAPPS="$TOMCAT_HOME/webapps"
    TOMCAT_CONF_FILE="$TOMCAT_HOME/conf/server.xml"
    LOG_FILE="$TOMCAT_HOME/logs/catalina.out"
    BACKUP_DIR="/var/backups/tomcat"
    OS_TYPE=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

    USERS_FILE_PERMISSION=$(stat -c "%a" "$TOMCAT_USERS_FILE")
    CONF_FILE_PERMISSION=$(stat -c "%a" "$TOMCAT_CONF_FILE")
    LOG_PERMISSION=$(stat -c "%a" "$LOG_FILE")
    DIR_PERMISSION=$(stat -c "%a" "$TOMCAT_WEBAPPS")

    echo "[TO-01] Default 관리자 계정명 변경" >> $RESULT_FILE 2>&1
    if grep -iq "tomcat" "$TOMCAT_USERS_FILE"; then
        echo "★ 기본 관리자 계정 사용 중" >> $RESULT_FILE 2>&1
        echo "[TO-01] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    else
        echo "★ 기본 관리자 계정 변경됨" >> $RESULT_FILE 2>&1
        echo "[TO-01] Result : GOOD" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-02] 취약한 패스워드 사용 제한" >> $RESULT_FILE 2>&1
    if grep -iq "password" "$TOMCAT_USERS_FILE"; then
        echo "★ 취약한 패스워드 사용 감지" >> $RESULT_FILE 2>&1
        echo "[TO-02] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    else
        echo "★ 취약한 패스워드 사용 없음" >> $RESULT_FILE 2>&1
        echo "[TO-02] Result : GOOD" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-03] 패스워드 파일 권한 관리" >> $RESULT_FILE 2>&1
    if [[ "$USERS_FILE_PERMISSION" -eq 644 ]]; then
        echo "★ 패스워드 파일 권한 취약 (644)" >> $RESULT_FILE 2>&1
        echo "[TO-03] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    else
        echo "★ 패스워드 파일 권한 안전" >> $RESULT_FILE 2>&1
        echo "[TO-03] Result : GOOD" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-04] 홈디렉토리 쓰기 권한 관리" >> $RESULT_FILE 2>&1
    if [[ "$DIR_PERMISSION" -ge 755 ]]; then
        echo "★ Document Root 권한 안전" >> $RESULT_FILE 2>&1
        echo "[TO-04] Result : GOOD" >> $RESULT_FILE 2>&1
    else
        echo "★ Document Root 권한 취약" >> $RESULT_FILE 2>&1
        echo "[TO-04] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-05] 환경설정 파일 권한 관리" >> $RESULT_FILE 2>&1
    if [[ "$CONF_FILE_PERMISSION" -ge 644 ]]; then
        echo "★ 환경설정 파일 권한 안전" >> $RESULT_FILE 2>&1
        echo "[TO-05] Result : GOOD" >> $RESULT_FILE 2>&1
    else
        echo "★ 환경설정 파일 권한 취약" >> $RESULT_FILE 2>&1
        echo "[TO-05] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-06] 에러 메시지 관리" >> $RESULT_FILE 2>&1
    if grep -iq "<error-page>" "$TOMCAT_CONF_FILE"; then
        echo "★ 에러 메시지가 적절히 관리됨" >> $RESULT_FILE 2>&1
        echo "[TO-06] Result : GOOD" >> $RESULT_FILE 2>&1
    else
        echo "★ 에러 메시지 관리 필요" >> $RESULT_FILE 2>&1
        echo "[TO-06] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-07] 로그 파일 주기적 백업" >> $RESULT_FILE 2>&1
    if [[ -f "$LOG_FILE" && -d "$BACKUP_DIR" && $(ls -A "$BACKUP_DIR" | grep "catalina") ]]; then
        echo "★ 로그 파일이 주기적으로 백업됨" >> $RESULT_FILE 2>&1
        echo "[TO-07] Result : GOOD" >> $RESULT_FILE 2>&1
    else
        echo "★ 로그 파일 백업 필요" >> $RESULT_FILE 2>&1
        echo "[TO-07] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-08] 로그 파일 권한 설정" >> $RESULT_FILE 2>&1
    if [[ "$LOG_PERMISSION" -le 640 ]]; then
        echo "★ 로그 파일 권한 적절" >> $RESULT_FILE 2>&1
        echo "[TO-08] Result : GOOD" >> $RESULT_FILE 2>&1
    else
        echo "★ 로그 파일 권한 과다 허용 (현재: $LOG_PERMISSION)" >> $RESULT_FILE 2>&1
        echo "[TO-08] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

	echo "[TO-09] 최신 패치 적용" >> $RESULT_FILE 2>&1
	# Tomcat 경로 목록
	TOMCAT_PATHS=(
		"/opt/tomcat/bin/version.sh"
		"/usr/share/tomcat8/bin/version.sh"
		"/usr/share/tomcat9/bin/version.sh"
		"/usr/share/tomcat10/bin/version.sh"
		"/usr/share/tomcat11/bin/version.sh"
		"/usr/local/tomcat/bin/version.sh"
		"/etc/tomcat8/bin/version.sh"
		"/etc/tomcat9/bin/version.sh"
		"/etc/tomcat10/bin/version.sh"
		"/etc/tomcat11/bin/version.sh"
		"/var/lib/tomcat8/bin/version.sh"
		"/var/lib/tomcat9/bin/version.sh"
		"/var/lib/tomcat10/bin/version.sh"
		"/var/lib/tomcat11/bin/version.sh"
		"/home/tomcat/bin/version.sh"
		"/home/user/tomcat/bin/version.sh"
		"/opt/tomcat8/bin/version.sh"
		"/opt/tomcat9/bin/version.sh"
		"/opt/tomcat10/bin/version.sh"
		"/opt/tomcat11/bin/version.sh"
		"/usr/local/tomcat8/bin/version.sh"
		"/usr/local/tomcat9/bin/version.sh"
		"/usr/local/tomcat10/bin/version.sh"
		"/usr/local/tomcat11/bin/version.sh"
		"/var/tomcat8/bin/version.sh"
		"/var/tomcat9/bin/version.sh"
		"/var/tomcat10/bin/version.sh"
		"/var/tomcat11/bin/version.sh"
	)

	# 현재 설치된 Tomcat 버전 확인
	INSTALLED_TOMCAT_VERSION="Tomcat 버전 파일을 찾을 수 없음"
	for TOMCAT_PATH in "${TOMCAT_PATHS[@]}"; do
		if [ -f "$TOMCAT_PATH" ]; then
			# version.sh 파일 실행하여 출력에서 "Server version" 부분을 추출
			INSTALLED_TOMCAT_VERSION=$(bash "$TOMCAT_PATH" | grep -i "Server version" | awk '{print $3"/"$4}')
			break
		fi
	done

	# Tomcat의 최신 버전 확인 (Tomcat 공식 사이트에서 최신 버전 확인)
	LATEST_TOMCAT_VERSION=$(curl -s https://tomcat.apache.org/ | grep -oP 'Tomcat \d+\.\d+\.\d+' | head -n 1 | awk '{print $2}')

	# 버전 비교 및 출력
	if [ "$INSTALLED_TOMCAT_VERSION" != "$LATEST_TOMCAT_VERSION" ]; then
		echo "★ Tomcat 버전이 최신 버전이 아닙니다. 최신 버전으로 업데이트 필요." >> $RESULT_FILE 2>&1
		echo "★ 현재 설치된 Tomcat 버전: $INSTALLED_TOMCAT_VERSION" >> $RESULT_FILE 2>&1
		echo "★ 최신 Tomcat 버전: $LATEST_TOMCAT_VERSION" >> $RESULT_FILE 2>&1
		echo "[TO-09] Result : VULNERABLE" >> $RESULT_FILE 2>&1
	else
		echo "★ Tomcat이 최신 버전으로 업데이트 되어 있습니다." >> $RESULT_FILE 2>&1
		echo "★ 현재 설치된 Tomcat 버전: $INSTALLED_TOMCAT_VERSION" >> $RESULT_FILE 2>&1
		echo "★ 최신 Tomcat 버전: $LATEST_TOMCAT_VERSION" >> $RESULT_FILE 2>&1
		echo "[TO-09] Result : GOOD" >> $RESULT_FILE 2>&1
	fi

	echo >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
}

# Nginx 취약점 진단 수행 함수
check_nginx_vulnerability() {
echo "[NG-01] 웹 서비스 영역의 분리" >> $RESULT_FILE 2>&1
NGINX_ROOT=$(grep -i 'root' /etc/nginx/nginx.conf)

if [[ $NGINX_ROOT =~ "/var/www/html" ]]; then
    echo "★ 웹 서비스 root 디렉토리 변경 필요: /var/www/html -> 다른 디렉토리로 변경 권장" >> $RESULT_FILE 2>&1
    echo "[NG-01] Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "★ 웹 서비스 root 디렉토리 변경이 완료되었습니다." >> $RESULT_FILE 2>&1
    echo "[NG-01] Result : GOOD" >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "[NG-02] 불필요한 파일 제거" >> $RESULT_FILE 2>&1
if [ -d "/usr/share/nginx/html" ]; then
    echo "★ 불필요한 Sample/Manual 디렉토리가 존재합니다." >> $RESULT_FILE 2>&1
    echo "디렉토리 현황:" >> $RESULT_FILE 2>&1
    ls -l /usr/share/nginx/html >> $RESULT_FILE 2>&1  # 디렉토리 내 파일 목록을 결과에 기록
    echo "[NG-02] Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "★ Sample/Manual 디렉토리가 존재하지 않습니다." >> $RESULT_FILE 2>&1
    echo "[NG-02] Result : GOOD" >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "[NG-03] 링크 사용금지" >> $RESULT_FILE
SYMLINKS=$(find /etc /home /var -type l -ls 2>/dev/null | grep -E '->')

if [ -n "$SYMLINKS" ]; then
    echo "★ 심볼릭 링크가 존재합니다." >> $RESULT_FILE
    echo "$SYMLINKS" >> $RESULT_FILE
    echo "[NG-03] Result : VULNERABLE" >> $RESULT_FILE
else
    echo "★ 심볼릭 링크가 존재하지 않습니다." >> $RESULT_FILE
    echo "[NG-03] Result : GOOD" >> $RESULT_FILE
fi
echo "" >> $RESULT_FILE
echo "" >> $RESULT_FILE

echo "[NG-04] 파일 업로드 및 다운로드 제한" >> $RESULT_FILE 2>&1
UPLOAD_LIMIT=$(grep -i 'client_max_body_size' /etc/nginx/nginx.conf)
if [ -z "$UPLOAD_LIMIT" ]; then
    echo "★ 파일 업로드 크기 제한 설정이 되어 있지 않습니다. 기본 크기 제한 추가 필요." >> $RESULT_FILE 2>&1
    echo "[NG-04] Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "★ 파일 업로드 크기 제한이 설정되어 있습니다: $UPLOAD_LIMIT" >> $RESULT_FILE 2>&1
    echo "[NG-04] Result : GOOD" >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "[NG-05] 디렉토리 리스팅 제거" >> $RESULT_FILE 2>&1
DIR_LISTING=$(grep -i 'autoindex' /etc/nginx/nginx.conf)

if [[ $DIR_LISTING =~ "on" ]]; then
    echo "★ 디렉토리 리스팅이 활성화되어 있습니다. autoindex를 off로 설정 필요." >> $RESULT_FILE 2>&1
    echo "[NG-05] Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "★ 디렉토리 리스팅 비활성화 상태입니다." >> $RESULT_FILE 2>&1
    echo "[NG-05] Result : GOOD" >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "[NG-06] 웹 프로세스 권한 제한" >> $RESULT_FILE 2>&1
PROCESS_USER=$(ps aux | grep nginx | grep -v grep | awk '{print $1}')

if [ "$PROCESS_USER" == "root" ]; then
    echo "★ 웹 서버가 root 권한으로 실행 중입니다. 권한 제한이 필요합니다." >> $RESULT_FILE 2>&1
    echo "[NG-06] Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "★ 웹 서버는 이미 non-root 사용자로 실행 중입니다." >> $RESULT_FILE 2>&1
    echo "[NG-06] Result : GOOD" >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "[NG-07] 안정화 버전 및 패치 적용" >> $RESULT_FILE 2>&1
# 현재 Nginx 버전 확인
CURRENT_VERSION=$(nginx -v 2>&1 | awk -F/ '{print $2}')

# 최신 버전 확인 (우분투에서 apt-cache 사용)
LATEST_VERSION=$(apt-cache policy nginx | grep -i "Candidate" | awk '{print $2}')

# 버전 비교 및 출력
if [ "$CURRENT_VERSION" != "$LATEST_VERSION" ]; then
    echo "Nginx 버전이 최신 버전이 아닙니다. 최신 버전으로 업데이트 필요." >> $RESULT_FILE 2>&1
    echo "현재 설치된 Nginx 버전: $CURRENT_VERSION" >> $RESULT_FILE 2>&1
    echo "최신 Nginx 버전: $LATEST_VERSION" >> $RESULT_FILE 2>&1
    echo "[NG-07] Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "Nginx가 최신 버전으로 업데이트 되어 있습니다." >> $RESULT_FILE 2>&1
    echo "현재 설치된 Nginx 버전: $CURRENT_VERSION" >> $RESULT_FILE 2>&1
    echo "최신 Nginx 버전: $LATEST_VERSION" >> $RESULT_FILE 2>&1
    echo "[NG-07] Result : GOOD" >> $RESULT_FILE 2>&1
fi

echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
}

### 실행 중인 서비스 진단 수행
# nginx 서비스가 설치되었는지 확인
if check_nginx_installed; then
    # nginx 서비스가 실행 중인지 확인
    if check_nginx_running; then
        check_nginx_vulnerability 
    else
        echo "nginx 서비스가 실행 중이 아닙니다." >> $RESULT_FILE
    fi
else
    echo "nginx 서비스가 설치되지 않았습니다." >> $RESULT_FILE
fi

# Tomcat 서비스가 설치되었는지 확인
if check_tomcat_installed; then
    # Tomcat 서비스가 실행 중인지 확인
    if check_tomcat_running; then
        check_tomcat_vulnerability
    else
        echo "Tomcat 서비스가 실행 중이 아닙니다." >> $RESULT_FILE
    fi
else
    echo "Tomcat 서비스가 설치되지 않았습니다." >> $RESULT_FILE
fi

### 최종 종료
echo "============================================================" >> $RESULT_FILE 2>&1
echo "Nginx/Tomcat 취약점 진단 완료되었습니다." >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
}

check_rocky() {
ssh_ver='OpenSSH_9.8p1'
ssl_ver='OpenSSL_1.1.1t / OpenSSL_3.0.8'
dir=./audit_temp
mkdir -p $dir

echo ""
echo "Rocky 운영 체제 보안 취약점 진단 스크립트를 실행합니다."
echo ""
echo "==============================  START  ==============================" 
echo ""

IP=$(ip addr show | grep 'inet ' | head -1 | awk '{print $2}' | cut -d'/' -f1)
RESULT_FILE=./RockyOO$(hostname)OO$IP.txt

echo [U-1]root 계정 원격 접속 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-1]root 계정 원격 접속 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [1-START] >> $RESULT_FILE 2>&1
SSHCONFIG='/etc/ssh/sshd_config'
if [ `ls $SSHCONFIG | wc -l` -eq 0 ]; then
		echo "★ sshd_config 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo -e "[1-END]\n" >> $RESULT_FILE 2>&1
		echo [U-1]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		if [ `grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "#" | grep -i "no" | wc -l` -eq 0 ]; then
				echo "★ root 계정 원격 접속이 제한되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "without" >> $RESULT_FILE 2>&1
				echo [1-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-1]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ root 계정 원격 접속이 제한됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "without" >> $RESULT_FILE 2>&1
				echo [1-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-1]Result : GOOD >> $RESULT_FILE 2>&1
		fi  
fi

echo >> $RESULT_FILE 2>&1

echo [U-2]패스워드 복잡성 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-2]패스워드 복잡성 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [2-START] >> $RESULT_FILE 2>&1

PWQUALITY='/etc/security/pwquality.conf'
if [ `ls $PWQUALITY | wc -l` -eq 0 ]
	then
		echo "★ pwquality.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [2-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-02]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		if [ `grep -i "credit" $PWQUALITY | grep "=" | grep -v "#" | wc -l` -ge 3 ]
			then
				echo "★ 패스워드 복잡성 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "credit" $PWQUALITY | grep "=" | grep -v '#' >> $RESULT_FILE 2>&1
				echo [2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-2]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 패스워드 복잡성 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "credit" $PWQUALITY | grep "=" | grep -v '#' >> $RESULT_FILE 2>&1
				echo [2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-2]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1


echo [U-3]계정 잠금 임계값 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-3]계정 잠금 임계값 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [3-START] >> $RESULT_FILE 2>&1

SYSAUTHAC='/etc/pam.d/system-auth'

if [ `ls $SYSAUTHAC | wc -l` -eq 0 ]
	then
		echo "★ system-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [3-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-3]Result : MANUAL >> $RESULT_FILE 2>&1
	else
        if [ `cat $SYSAUTHAC | grep 'faillock.so' | grep 'deny' | grep -v '#' | wc -l ` -eq 0 ]; then
					echo "★ 계정 잠금 임계값 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
					echo "[현황]" >> $RESULT_FILE 2>&1
					grep -i "^auth" $SYSAUTHAC >> $RESULT_FILE 2>&1
					echo [3-END] >> $RESULT_FILE 2>&1
					echo >> $RESULT_FILE 2>&1
					echo [U-3]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
					echo "★ 계정 잠금 임계값 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
					echo "[현황]" >> $RESULT_FILE 2>&1
					grep -i "^auth" $SYSAUTHAC >> $RESULT_FILE 2>&1
					echo [3-END] >> $RESULT_FILE 2>&1
					echo >> $RESULT_FILE 2>&1
					echo [U-3]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi

echo >> $RESULT_FILE 2>&1

echo [U-4]패스워드 파일 보호
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-4]패스워드 파일 보호  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [4-START] >> $RESULT_FILE 2>&1
if [ -f /etc/shadow ]; then
    echo "/etc/shadow 파일이 존재함" >> $RESULT_FILE 2>&1
    echo [4-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1			
	echo [U-4]Result : GOOD >> $RESULT_FILE 2>&1
else
    passwd_field=$(head -1 /etc/passwd | cut -d: -f2)    
    if [ "$passwd_field" == "x" ]; then
	    echo "★ 패스워드 /etc/passwd 파일에 저장하지 않고 별도의 파일에 저장함" >> $RESULT_FILE 2>&1
		echo [4-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1			
		echo [U-4]Result : GOOD >> $RESULT_FILE 2>&1
    else
		echo "★ 패스워드 /etc/passwd 파일에 저장함" >> $RESULT_FILE 2>&1
        echo [4-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-4]Result : VULNERABLE >> $RESULT_FILE 2>&1
    fi
fi
echo >> $RESULT_FILE 2>&1

echo [U-5]root 홈, 패스 디렉터리 권한 및 패스 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-5]root 홈, 패스 디렉터리 권한 및 패스 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [5-START] >> $RESULT_FILE 2>&1
if [ `echo $PATH | egrep '^:|:$|::|^.:|:.:|:.$' | wc -l` -eq 0 ]; then
		echo "★ PATH 환경변수에 '.'이 맨 앞 또는 중간에 위치하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $PATH >> $RESULT_FILE 2>&1
		echo [5-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-5]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ PATH 환경변수에 '.'이 맨 앞 또는 중간에 위치함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $PATH >> $RESULT_FILE 2>&1
		echo [5-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-5]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-6]파일 및 디렉터리 소유자 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-6]파일 및 디렉터리 소유자 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
file=`find / \( -nouser -o -nogroup \)  2>/dev/null >> $dir/tmp_6_1.txt`
#	ls -l /home | awk '{print $3}' | grep "^[0-9]" > tmp_6_1.txt
#	for i in `cat tmp_6_1.txt`; do ls -l /home | grep -w $i >> tmp_6_2.txt; done
if [ `cat $dir/tmp_6_1.txt | wc -l` -gt 0 ]; then
		echo "★ 소유자가 존재하지 않는 파일이 존재함" >> $RESULT_FILE 2>&1
		echo -e "[현황] \n`cat $dir/tmp_6_1.txt`" >> $RESULT_FILE 2>&1
		echo -e "총 갯수 : `cat $dir/tmp_6_1.txt | wc -l`" >> $RESULT_FILE 2>&1
		echo [6-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-6]Result : VULNERABLE >> $RESULT_FILE 2>&1		
	else
		echo "★ 소유자가 존재하지 않는 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [6-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-6]Result : GOOD >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-7]/etc/passwd 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-7]/etc/passwd 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [7-START] >> $RESULT_FILE 2>&1
file="/etc/passwd"
owner="$(stat -c %U "$file")"
permissions="$(stat -c %a "$file")"

if [ -f "$file" ]; then
    if [ "$owner" = "root" ] && [ "$permissions" -le 644 ]; then
	echo "★ /etc/passwd 파일의 소유자 및 퍼미션(644)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [7-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-7]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
	echo "★ /etc/passwd 파일의 소유자 및 퍼미션(644)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [7-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-7]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/passwd 파일을 찾을 수 없음" >> "$RESULT_FILE" 2>&1
    echo [7-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-7]Result : N/A" >> "$RESULT_FILE" 2>&1
fi
echo >> $RESULT_FILE 2>&1


echo [U-8]/etc/shadow 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-8]/etc/shadow 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [8-START] >> $RESULT_FILE 2>&1
file="/etc/shadow"
owner="$(stat -c %U "$file")"
permissions="$(stat -c %a "$file")"
if [ -f "$file" ]; then
    if [ "$owner" = "root" ] && [ "$permissions" -le 400 ]; then
		echo "★ /etc/shadow 파일의 소유자 및 퍼미션(400)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [8-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-8]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
		echo "★ /etc/shadow 파일의 소유자 및 퍼미션(400)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [8-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-8]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/shadow file not found" >> "$RESULT_FILE" 2>&1
    echo [8-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-8]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1


echo [U-9]/etc/hosts 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-9]/etc/hosts 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [9-START] >> $RESULT_FILE 2>&1
file="/etc/hosts"
owner="$(stat -c %U "$file")"
permissions="$(stat -c %a "$file")"
if [ -f "$file" ]; then
    if [ "$owner" = "root" ] && [ "$permissions" -le 600 ]; then
        echo "★ /etc/hosts 파일의 소유자 및 퍼미션(600)이하로 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [9-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-9]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
        echo "★ /etc/hosts 파일의 소유자 및 퍼미션(600)이하로 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [9-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-9]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/hosts 파일을 찾을 수 없음" >> "$RESULT_FILE" 2>&1
    echo [9-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-9]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1

echo [U-10]/etc/xinetd.conf 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-10]/etc/xinetd.conf 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [10-START] >> $RESULT_FILE 2>&1
file1="/etc/xinetd.conf"
file2="/etc/inetd.conf"
if [ -f "$file1" ]
	then
		owner="$(stat -c %U "$file1")"
		permissions="$(stat -c %a "$file1")"
		if [ "$owner" = "root" ] && [ "$permissions" -eq 600 ]
			then
				echo "★ /etc/xinetd.conf 파일의 소유자 및 퍼미션(600)으로 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
				echo "[현황]" >> "$RESULT_FILE" 2>&1
				ls -alL "$file1" >> "$RESULT_FILE" 2>&1
				echo [10-END] >> "$RESULT_FILE" 2>&1
				echo >> "$RESULT_FILE" 2>&1
				echo "[U-10]Result : GOOD" >> "$RESULT_FILE" 2>&1
			else
				echo "★ /etc/xinetd.conf 파일의 소유자 및 퍼미션(600)으로 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
				echo "[현황]" >> "$RESULT_FILE" 2>&1
				ls -alL "$file1" >> "$RESULT_FILE" 2>&1
				echo [10-END] >> "$RESULT_FILE" 2>&1
				echo >> "$RESULT_FILE" 2>&1
				echo "[U-10]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
		fi
	else
		if [ -f "$file2" ]
			then
				owner="$(stat -c %U "$file2")"
				permissions="$(stat -c %a "$file2")"
				if [ "$owner" = "root" ] && [ "$permissions" -eq 600 ]
					then
						echo "★ /etc/inetd.conf 파일의 소유자 및 퍼미션(600)으로 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
						echo "[현황]" >> "$RESULT_FILE" 2>&1
						ls -alL "$file2" >> "$RESULT_FILE" 2>&1
						echo [10-END] >> "$RESULT_FILE" 2>&1
						echo >> "$RESULT_FILE" 2>&1
						echo "[U-10]Result : GOOD" >> "$RESULT_FILE" 2>&1
					else
						echo "★ /etc/inetd.conf 파일의 소유자 및 퍼미션(600)으로 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
						echo "[현황]" >> "$RESULT_FILE" 2>&1
						ls -alL "$file2" >> "$RESULT_FILE" 2>&1
						echo [10-END] >> "$RESULT_FILE" 2>&1
						echo >> "$RESULT_FILE" 2>&1
						echo "[U-10]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
				fi			
					else
						echo "★ /etc/inetd.conf 파일 또는 /etc/inetd.d 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
						echo [10-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-10]Result : N/A >> $RESULT_FILE 2>&1 
		fi
fi
echo >> $RESULT_FILE 2>&1

echo [U-11]/etc/rsyslog.conf 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-11]/etc/rsyslog.conf 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [11-START] >> $RESULT_FILE 2>&1
file="/etc/rsyslog.conf"
owner="$(stat -c %U "$file")"
permissions="$(stat -c %a "$file")"
if [ -f "$file" ]; then
    if [ "$owner" = "root" ] && [ "$permissions" -le 640 ]; then
		echo "★ /etc/rsyslog.conf 파일의 소유자 및 퍼미션(640)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [11-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-11]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
		echo "★ /etc/rsyslog.conf 파일의 소유자 및 퍼미션(640)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [11-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-11]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/rsyslog.conf file not found." >> "$RESULT_FILE" 2>&1
    echo [11-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-11]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1

echo [U-12]/etc/services 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-12]/etc/services 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [12-START] >> $RESULT_FILE 2>&1
file="/etc/services"
owner="$(stat -c %U "$file")"
permissions="$(stat -c %a "$file")"
if [ -f "$file" ]; then
    if [ "$owner" = "root" ] && [ "$permissions" -le 644 ]; then
		echo "★ /etc/services 파일의 소유자 및 퍼미션(644)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [12-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-12]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
		echo "★ /etc/services 파일의 소유자 및 퍼미션(644)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [12-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-12]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "The /etc/services file is missing." >> "$RESULT_FILE" 2>&1
    echo [12-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-12]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1


echo [U-13]SUID, SGID, 설정 파일점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-13]SUID, SGID, 설정 파일점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [13-START] >> $RESULT_FILE 2>&1

file=`find / -user root -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null >> $dir/tmp_13.txt`
if [ `cat $dir/tmp_13.txt | wc -l` -gt 0 ]; then
                echo "★ 주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있음" >> $RESULT_FILE 2>&1
                echo -e "[현황] \n`cat $dir/tmp_13.txt`" >> $RESULT_FILE 2>&1
                echo -e "총 갯수 : `cat $dir/tmp_13.txt | wc -l`" >> $RESULT_FILE 2>&1
                echo -e "[13-END]\n" >> $RESULT_FILE 2>&1
                echo [EN-13]Result : VULNERABLE >> $RESULT_FILE 2>&1
        else
                echo "★ 주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않음" >> $RESULT_FILE 2>&1
                echo -e "[13-END]\n" >> $RESULT_FILE 2>&1
                echo >> $RESULT_FILE 2>&1
                echo [U-13]Result : GOOD >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-14]사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-14]사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [14-START] >> $RESULT_FILE 2>&1
file="/etc/profile"
owner="$(stat -c %U "$file")"
permissions="$(stat -c %a "$file")"
if [ -f "$file" ]; then
    if [ "$owner" = "root" ] && [ "$permissions" -le 644 ]
		then
			echo "★ /etc/profile 파일의 소유자 및 퍼미션(g-w,o-w)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
			echo "[현황]" >> "$RESULT_FILE" 2>&1
			ls -al /etc/profile >> "$RESULT_FILE" 2>&1
			echo [14-END] >> "$RESULT_FILE" 2>&1
			echo >> "$RESULT_FILE" 2>&1
			echo [U-14]Result : GOOD >> "$RESULT_FILE" 2>&1
		else
			echo "★ /etc/profile 파일의 소유자 및 퍼미션(g-w,o-w)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> "$RESULT_FILE" 2>&1
			ls -al /etc/profile >> "$RESULT_FILE" 2>&1
			echo [14-END] >> "$RESULT_FILE" 2>&1
			echo >> "$RESULT_FILE" 2>&1
			echo [U-14]Result : VULNERABLE >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/profile file missing" >> "$RESULT_FILE" 2>&1
    echo [14-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo [U-14]Result : N/A >> "$RESULT_FILE" 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-15]world writable 파일 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-15]world writable 파일 점검 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [15-START] >> $RESULT_FILE 2>&1
file=`find / ! \( \( -type d -path '/proc' -o -path '/sys/fs' \) -prune \) -perm -2 -type f 2>/dev/null >> $dir/tmp_15.txt`

if [ `cat $dir/tmp_15.txt | wc -l` -gt 0 ]; then
                echo "★ 불필요한 World Writable 파일이 존재함" >> $RESULT_FILE 2>&1
                echo -e "[현황] \n`cat $dir/tmp_15.txt`" >> $RESULT_FILE 2>&1
                echo -e "총 갯수 : `cat $dir/tmp_15.txt | wc -l`" >> $RESULT_FILE 2>&1
                echo -e "[15-END]\n" >> $RESULT_FILE 2>&1
                echo [EN-15]Result : VULNERABLE >> $RESULT_FILE 2>&1
        else
                echo "★ 불필요한 World Writable 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
                echo -e "[15-END]\n" >> $RESULT_FILE 2>&1
                echo >> $RESULT_FILE 2>&1
                echo [U-15]Result : GOOD >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-16]dev에 존재하지 않는 device 파일 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-16]dev에 존재하지 않는 device 파일 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [16-START] >> $RESULT_FILE 2>&1
file=`find /dev -type f 2>/dev/null >> $dir/tmp_16.txt`

if [ `cat $dir/tmp_16.txt | wc -l` -gt 0 ]; then
                echo "★ /dev 디렉토리에 major, minor nubmer를 가지지 않는 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
                echo -e "[현황] \n`cat $dir/tmp_16.txt`" >> $RESULT_FILE 2>&1
                echo -e "총 갯수 : `cat $dir/tmp_16.txt | wc -l`" >> $RESULT_FILE 2>&1
                echo -e "[16-END]\n" >> $RESULT_FILE 2>&1
                echo [EN-16]Result : VULNERABLE >> $RESULT_FILE 2>&1
        else
                echo "★ /dev 디렉토리에 major, minor nubmer를 가지지 않는 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
                echo -e "[16-END]\n" >> $RESULT_FILE 2>&1
                echo >> $RESULT_FILE 2>&1
                echo [U-16]Result : GOOD >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-17]$HOME/.rhosts, hosts.equiv 사용 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-17]$HOME/.rhosts, hosts.equiv 사용 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [17-START] >> $RESULT_FILE 2>&1
	ls -l /home/ | grep -v "+found" | sed -n '2,$p' | awk '{print $9}' > $dir/tmp_17_1.txt
	for i in `cat $dir/tmp_17_1.txt`; do ls -al /home/$i/.rhosts; done 2>/dev/null > $dir/tmp_17_2.txt
	if [ -f /etc/hosts.equiv ]; then ls -l /etc/hosts.equiv >> $dir/tmp_17_2.txt; else true; fi 
	if [ `cat $dir/tmp_17_2.txt | wc -l` -eq 0 ]
	then
		echo "★ .rhosts, hosts.equiv 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [17-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-17]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat $dir/tmp_17_2.txt | wc -l` -eq `cat $dir/tmp_17_2.txt | grep "^....------" | wc -l` ]
		then
			for i in `cat $dir/tmp_17_2.txt | awk '{print $9}'`; do cat $i; done >> $dir/tmp_17_3.txt
			if [ `cat $dir/tmp_17_3.txt | grep "\+" | wc -l` -eq 0 ] 
			then
				echo "★ .rhosts, hosts.equiv 파일의 퍼미션 및 설정이 적절하게 적용됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				for i in `cat $dir/tmp_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
				echo [17-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-17]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ .rhosts, hosts.equiv 파일의 설정이 적절하지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				for i in `cat $dir/tmp_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
				echo [17-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-17]Result : VULNERABLE >> $RESULT_FILE 2>&1
			fi
		else
			echo "★ .rhosts, hosts.equiv 파일의 퍼미션이 적절하지 않음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			for i in `cat $dir/tmp_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
			echo [17-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [SU-17]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	fi

echo >> $RESULT_FILE 2>&1
echo [U-18]접속 IP 및 포트 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-18]접속 IP 및 포트 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [18-START] >> $RESULT_FILE 2>&1
file_a='/etc/hosts.allow'
file_d='/etc/hosts.deny'
cnt=0

if [ -e $file_a ]; then
        if [ `cat $file_a | grep -v "^#" | grep ALL | wc -l` -eq 0 ]; then
                echo "* hosts.allow ALL 설정이 존재 하지 않음" >> $RESULT_FILE 2>&1
                echo >> $RESULT_FILE 2>&1
        else
                echo -e "* $file_a 파일 점검 필요" >> $RESULT_FILE 2>&1
                echo -e "[$file_a 현황]" >> $RESULT_FILE 2>&1
                cat $file_a | grep -v "^#" | grep ALL >> $RESULT_FILE 2>&1
                cnt=$((cnt+1))
        fi
else
        echo -e "* $file_a 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
fi

if [ -e $file_d ]; then
        if [ `cat $file_d | grep -v "^#" | wc -l` -gt 1  ]; then
                echo "* hosts.deny 내 설정이 존재함" >> $RESULT_FILE 2>&1
                echo -e "[$file_d 현황]" >> $RESULT_FILE 2>&1
                cat $file_d | grep -v "^#" >> $RESULT_FILE 2>&1
                echo >> $RESULT_FILE 2>&1
         else
                echo -e "* $file_d 파일 내용 미존재로 점검 필요" >> $RESULT_FILE 2>&1
                cnt=$((cnt+1))
        fi
else
        echo -e "$file_d 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
fi
echo -e "\n[18-END]\n" >> $RESULT_FILE 2>&1
if [ $cnt -ge 1 ]; then
        echo "[U-18]Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
        echo [U-18]Result : GOOD >> $RESULT_FILE 2>&1

fi

echo >> $RESULT_FILE 2>&1

echo [U-19]Finger 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-19]Finger 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [19-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "finger" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Finger 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [19-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-19]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ Finger 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep -i "finger" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [19-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-19]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1


echo [U-20]Anonymous FTP 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-20]Anonymous FTP 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [20-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [20-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find / -name "vsftpd.conf" -exec cp -a {} $dir/vsftpd.conf \;
		if [ `cat $dir/vsftpd.conf 2>/dev/null | wc -l` -eq 0 ]
			then
				if [ `cat /etc/passwd | egrep -w "ftp|anonymous" | wc -l` -eq 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, ftp 또는 anonymous 계정이 존재하지 않음 " >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, ftp 또는 anonymous 계정이 존재함 " >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat /etc/passwd | egrep -w "ftp|anonymous" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				if [ `cat $dir/vsftpd.conf | grep "anonymous_enable" | grep -v "#" | grep -i -v "no$" | wc -l` -eq 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, Anonymous 접속이 차단됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat $dir/vsftpd.conf | grep "anonymous_enable" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, Anonymous 접속이 허용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat $dir/vsftpd.conf | grep "anonymous_enable" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi	
fi
echo >> $RESULT_FILE 2>&1

echo [U-21]r 계열 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-21]r 계열 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [21-START] >> $RESULT_FILE 2>&1
find / -name "rsh" -o -name "rexec" -o -name "rlogin" >> $dir/tmp_21_1.txt
#systemctl -t service list-unit-files | egrep 'rsh|rexec|rlogin' >> $dir/tmp_21_2.txt
if [ ! -s "$dir/tmp_21_1.txt" ]
        then
                echo "★ r 계열 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
                echo [21-END] >> $RESULT_FILE 2>&1
                echo >> $RESULT_FILE 2>&1
                echo [U-21]Result : GOOD >> $RESULT_FILE 2>&1
        else
                if [ ! `ps -ef | egrep 'rsh|rexec|rlogin' | grep -v 'grep' | wc -l` -eq 0 ]; then
                        echo "★ r 계열 서비스가 실행중임" >> $RESULT_FILE 2>&1
                        echo "[현황]" >> $RESULT_FILE 2>&1
                        ps -ef | egrep 'rsh|rexec|rlogin' | grep -v 'grep' >> $RESULT_FILE 2>&1
                        echo [21-END] >> $RESULT_FILE 2>&1
                        echo >> $RESULT_FILE 2>&1
                        echo [U-21]Result : VULNERABLE >> $RESULT_FILE 2>&1
#               elif [ ! `cat $dir/tmp_21_2.txt |wc -l` -eq 0 ]; then
                else
                        echo "★ r 계열 서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
                        echo "[현황]" >> $RESULT_FILE 2>&1
                        cat $dir/tmp_21_1.txt >> $RESULT_FILE 2>&1
                        echo [21-END] >> $RESULT_FILE 2>&1
                        echo >> $RESULT_FILE 2>&1
                        echo [U-21]Result : GOOD >> $RESULT_FILE 2>&1
                fi
        fi

echo >> $RESULT_FILE 2>&1

echo [U-22]crond 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-22]crond 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [22-START] >> $RESULT_FILE 2>&1
echo "[현황]" >> "$RESULT_FILE" 2>&1
cnt=0
lists=(
    "/etc/crontab 640 root"
    "/etc/cron.hourly 640 root"
    "/etc/cron.daily 640 root"
    "/etc/cron.weekly 640 root"
    "/etc/cron.monthly 640 root"
    "/etc/cron.allow 640 root"
    "/etc/cron.deny 640 root"
    "/etc/cron.d 640 root"
	"/usr/bin/crontab 750 root"
)

for list in "${lists[@]}"; do
    path=$(echo "$list" | awk '{ print $1 }')
    perm=$(echo "$list" | awk '{ print $2 }')
    owner=$(echo "$list" | awk '{ print $3 }')

    if [ ! -d "$path" ]; then
        if [ -e "$path" ]; then
            list_perm=$(stat -c "%a" "$path")
            file_owner=$(stat -c "%U" "$path")
            if [ "$perm" -lt "$list_perm" ] || [ "$owner" != "$file_owner" ]; then
                echo -e "$path 파일의 소유자($owner) 또는 퍼미션($perm)이 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
                echo -e "  $(ls -al $path)" >> "$RESULT_FILE" 2>&1
                cnt=$((cnt+1))
            else
                echo -e "$path 파일의 소유자 및 퍼미션이 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
            fi
        fi
    elif [ -d "$path" ]; then
        for file in "$path"/*; do
            if [ -e "$file" ]; then
                list_perm=$(stat -c "%a" "$file")
                file_owner=$(stat -c "%U" "$file")
                if [ "$perm" -lt "$list_perm" ] || [ "$owner" != "$file_owner" ]; then
                    echo -e "$file 파일의 소유자($owner) 또는 퍼미션($perm)이 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
                    echo -e "  $(ls -al $file)" >> "$RESULT_FILE" 2>&1
                    cnt=$((cnt+1))
                else
                    echo -e "$file 파일의 소유자 및 퍼미션이 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
                fi
            fi
        done
    fi
done

echo -e "[22-END]\n" >> $RESULT_FILE 2>&1

if [ $cnt -ge 1 ]; then
        echo -e "[U-22]Result : VULNERABLE\n" >> $RESULT_FILE 2>&1
else
        echo -e "[U-22]Result : GOOD\n" >> $RESULT_FILE 2>&1

fi

echo [U-23]DoS 공격에 취약한 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-23]DoS 공격에 취약한 서비스 비활성화 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [23-START] >> $RESULT_FILE 2>&1
# 서비스 실행 여부 저장
echo echo.service status >> $dir/tmp_23_1.txt 2>&1
systemctl is-active echo.service >> $dir/tmp_23_1.txt 2>&1
echo discard.service status >> $dir/tmp_23_1.txt 2>&1
systemctl is-active discard.service >> $dir/tmp_23_1.txt 2>&1
echo daytime.service status >> $dir/tmp_23_1.txt 2>&1
systemctl is-active daytime.service >> $dir/tmp_23_1.txt 2>&1
echo chargen.service status >> $dir/tmp_23_1.txt 2>&1
systemctl is-active chargen.service >> $dir/tmp_23_1.txt 2>&1


if [ `find /etc/systemd/system -name "echo" -o -name "discard" -o -name "daytime" -o -name "chargen" | wc -l` -eq 0 ]
	then
		echo "★ DoS 공격에 취약한 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [23-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-23]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat $dir/tmp_23_1.txt | grep "active" | wc -l` -eq 0 ]
			then
				echo "★ DoS 공격에 취약한 서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat $dir/tmp_23_1.txt >> $RESULT_FILE 2>&1
				echo [40-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-40]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ DoS 공격에 취약한 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat $dir/tmp_23_1.txt | grep "active" >> $RESULT_FILE 2>&1
				echo [40-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-40]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi

echo >> $RESULT_FILE 2>&1

echo [U-24]NFS 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-24]NFS 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [24-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "NFS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [24-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-24]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "NFS 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [24-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-24]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-25]NFS 접근 통제
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-25]NFS 접근 통제  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [25-START] >> $RESULT_FILE 2>&1
	if [ `ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "NFS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [25-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-25]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ -f /etc/exports ]
		then
			if [ `cat /etc/exports | grep -i "everyone" | grep -v "^ *#" | wc -l` -eq 0 ]
			then
				echo "NFS 서비스가 실행중이나 everyone 공유가 존재하지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" >> $RESULT_FILE 2>&1
				cat /etc/exports >> $RESULT_FILE 2>&1
				echo [25-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-25]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "NFS 서비스가 실행중이고 everyone 공유가 존재함" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" >> $RESULT_FILE 2>&1
				cat /etc/exports >> $RESULT_FILE 2>&1
				echo [25-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-25]Result : VULNERABLE >> $RESULT_FILE 2>&1
			fi
		else
			echo "NFS 서비스가 실행중이나 /etc/exports 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" >> $RESULT_FILE 2>&1
			echo [25-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-25]Result : MANUAL >> $RESULT_FILE 2>&1
		fi
	fi
echo >> $RESULT_FILE 2>&1

echo [U-26]automountd 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-26]automountd 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [26-START] >> $RESULT_FILE 2>&1

if [ `ps -ef | egrep "autofs|automount" | grep -v "grep" | grep -v 'node_exporter' | wc -l` -eq 0 ]
	then
		echo "autofs, automount 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [26-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-26]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "autofs, automount 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | egrep "autofs|automount" | grep -v "grep" | grep -v 'node_exporter' >> $RESULT_FILE 2>&1
		echo [26-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-26]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-27]RPC 서비스 확인
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-27]RPC 서비스 확인  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [27-START] >> $RESULT_FILE 2>&1
find /etc/systemd/system -name "rpc.cmsd" -o -name "rpc.ttdbserverd" -o -name "sadmind" -o -name "rusersd" -o -name "walld" -o -name "sprayd" -o -name "rstatd" -o -name "rpc.nisd" -o -name "rpc.pcnfsd" -o -name "rpc.statd" -o -name "rpc.ypupdated" -o -name "rpc.rquotad" -o -name "kcms_server" -o -name "cachefsd"  -o -name "rexd" >> $dir/tmp_27_1.txt 2>&1
ps -ef | grep "rpcbind" | grep -v "grep" >> $dir/tmp_27_1.txt 2>&1
if [ `cat $dir/tmp_27_1.txt | wc -l` -eq 0 ]
	then
		echo "★ RPC 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [27-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-27]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat $dir/tmp_27_1.txt | egrep "active|rpcbind" | wc -l` -eq 0 ]
			then
				echo "RPC서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat $dir/tmp_27_1.txt >> $RESULT_FILE 2>&1
				echo [27-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-27]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ RPC 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat $dir/tmp_27_1.txt | egrep "active|rpcbind" >> $RESULT_FILE 2>&1
				echo [27-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-27]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1

echo [U-28]NIS, NIS+ 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-28]NIS, NIS+ 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [28-START] >> $RESULT_FILE 2>&1
SERVICE_NIS="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nisd"
	if [ `ps -ef | egrep $SERVICE_NIS | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ NIS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [28-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-28]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ NIS 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | egrep $SERVICE_NIS | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [28-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-28]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
echo >> $RESULT_FILE 2>&1

echo [U-29]tftp, talk 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-29]tftp, talk 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [29-START] >> $RESULT_FILE 2>&1
		if [ `find /etc -type f \( -name 'tftp' -o -name 'talk' -o -name 'ntalk' \) | wc -l` -eq 0 ]
			then
				echo "★ tftp, talk 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo [29-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-29]Result : GOOD >> $RESULT_FILE 2>&1		
			else
				echo "★ tftp, talk 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				find /etc -type f \( -name 'tftp' -o -name 'talk' -o -name 'ntalk' \) >> $RESULT_FILE 2>&1
				echo [29-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-29]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
echo >> $RESULT_FILE 2>&1

echo [U-30]Sendmail 버전 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-30]Sendmail 버전 점검 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [30-START] >> $RESULT_FILE 2>&1
find /etc -name "sendmail.cf" -exec cp -a {} $dir/sendmailcheck.txt 2>/dev/null \;

if [ `ps -ef | egrep 'sendmail|postfix' | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [30-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-30]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat $dir/sendmailcheck.txt | wc -l` -eq 0 ]
			then
				echo "Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [30-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-30]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				if [ `cat $dir/sendmailcheck.txt | grep -v '^ *#' | grep DZ | egrep "8.15" | wc -l` -eq 0 ]
					then
						echo "취약한 버전의 Sendmail 서비스가 실행중임" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						echo "Sendmail 버전 : `cat $dir/sendmailcheck.txt | grep -v '^ *#' | grep DZ`" >> $RESULT_FILE 2>&1
						echo [30-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-30]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ 취약하지 않은 버전의 Sendmail 서비스가 실행중임" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						echo "Sendmail 버전 : `cat $dir/sendmailcheck.txt | grep -v '^ *#' | grep DZ`" >> $RESULT_FILE 2>&1
						echo [30-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-30]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
echo >> $RESULT_FILE 2>&1

echo [U-31]스팸 메일 릴레이 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-31]스팸 메일 릴레이 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [31-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | egrep 'sendmail|postfix' | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [31-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-31]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat $dir/sendmailcheck.txt | wc -l` -eq 0 ]
			then
				echo "Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [31-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-31]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				if [ `cat $dir/sendmailcheck.txt | grep -v "^ *#" | grep "R$\*" | grep -i "Relaying denied" | wc -l ` -gt 0 ]
					then
						echo "스팸 메일 릴레이 제한 설정이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat $dir/sendmailcheck.txt | grep -v "^ *#" | grep "R$\*" | grep -i "Relaying denied" >> $RESULT_FILE 2>&1
						echo [31-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-31]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "스팸 메일 릴레이 제한 설정이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat $dir/sendmailckeck.txt | grep "R$\*" | grep -i "Relaying denied" >> $RESULT_FILE 2>&1
						echo [31-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-31]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
fi
echo >> $RESULT_FILE 2>&1

echo [U-32]일반사용자의 Sendmail 실행 방지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-32]일반사용자의 Sendmail 실행 방지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [32-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | egrep 'sendmail|postfix' | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [32-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-32]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat $dir/sendmailcheck.txt | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [32-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-32]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				if [ `cat $dir/sendmailcheck.txt | grep -i "O PrivacyOptions" | grep -i "restrictqrun" | grep -v "#" | wc -l` -gt 0 ]
					then
						echo "★ 일반사용자의 Sendmail 실행 방지 설정이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat $dir/sendmailcheck.txt | grep -i "O PrivacyOptions" | grep -i "restrictqrun" >> $RESULT_FILE 2>&1
						echo [32-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-32]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 일반사용자의 Sendmail 실행 방지 설정이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat $dir/sendmailcheck.txt | grep -i "O PrivacyOptions" >> $RESULT_FILE 2>&1
						echo [32-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-32]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
fi
echo >> $RESULT_FILE 2>&1

echo [U-33]DNS 보안 버전 패치
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-33]DNS 보안 버전 패치  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [33-START] >> $RESULT_FILE 2>&1

if [ "$(ss -lntp | awk '$4 ~ /:53$/ {print}' | wc -l)" -eq 0 ]; then
    echo "★ DNS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
    echo [33-END] >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo [U-33]Result : GOOD >> $RESULT_FILE 2>&1
else
    if command -v named &>/dev/null; then
        echo "★ DNS 서비스가 실행중이며 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
        echo "[현황]" >> $RESULT_FILE 2>&1
        named -v >> $RESULT_FILE 2>&1
        echo [33-END] >> $RESULT_FILE 2>&1
        echo >> $RESULT_FILE 2>&1
        echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
    elif [ -f /usr/sbin/named ]; then
        echo "★ DNS 서비스가 실행중임 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
        echo "[현황]" >> $RESULT_FILE 2>&1
        /usr/sbin/named -v >> $RESULT_FILE 2>&1
        echo [33-END] >> $RESULT_FILE 2>&1
        echo >> $RESULT_FILE 2>&1
        echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
    elif [ -f /usr/sbin/named9 ]; then
        echo "★ DNS 서비스가 실행중임 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
        echo "[현황]" >> $RESULT_FILE 2>&1
        /usr/sbin/named9 -v >> $RESULT_FILE 2>&1
        echo [33-END] >> $RESULT_FILE 2>&1
        echo >> $RESULT_FILE 2>&1
        echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
    else
        echo "★ DNS 서비스가 실행중이나 실행 데몬을 찾을 수 없음" >> $RESULT_FILE 2>&1
        echo [33-END] >> $RESULT_FILE 2>&1
        echo >> $RESULT_FILE 2>&1
        echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
    fi
fi

echo >> $RESULT_FILE 2>&1

echo [U-34] DNS Zone Transfer 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-34] DNS Zone Transfer 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [34-START] >> $RESULT_FILE 2>&1

if [ "$(ss -lntp | awk '$4 ~ /:53$/ {print}' | wc -l)" -eq 0 ]; then
    echo "★ DNS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
    echo [34-END] >> $RESULT_FILE 2>&1
    echo >> $RESULT_FILE 2>&1
    echo [U-34]Result : GOOD >> $RESULT_FILE 2>&1
else
    cat /etc/named.conf /etc/named.rfc1912.zones /etc/named.boot >> $dir/dnstranstercheck.txt 2> /dev/null
    if [ "$(wc -l < $dir/dnstranstercheck.txt)" -eq 0 ]; then
        echo "★ DNS 서비스가 실행중이나 설정파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> $RESULT_FILE 2>&1
        ss -lntp | awk '$4 ~ /:53$/ {print}' >> $RESULT_FILE 2>&1
        echo [34-END] >> $RESULT_FILE 2>&1
        echo >> $RESULT_FILE 2>&1
        echo [U-34]Result : MANUAL >> $RESULT_FILE 2>&1
    else
        if ! grep -q "allow-transfer" "$dir/dnstranstercheck.txt" | grep -v "#"; then
            echo "★ DNS 서비스가 실행중이며 DNS ZoneTransfer 설정이 적용되지 않음" >> $RESULT_FILE 2>&1
            echo "[현황]" >> $RESULT_FILE 2>&1
            ss -lntp | awk '$4 ~ /:53$/ {print}' >> $RESULT_FILE 2>&1
            echo [34-END] >> $RESULT_FILE 2>&1
            echo >> $RESULT_FILE 2>&1
            echo [U-34]Result : VULNERABLE >> $RESULT_FILE 2>&1
        else
            echo "★ DNS 서비스가 실행중이며 DNS ZoneTransfer 설정이 적용됨" >> $RESULT_FILE 2>&1
            echo "[현황]" >> $RESULT_FILE 2>&1
            ss -lntp | awk '$4 ~ /:53$/ {print}' >> $RESULT_FILE 2>&1
            grep "allow-transfer" "$dir/dnstranstercheck.txt" | grep -v "#" >> $RESULT_FILE 2>&1
            echo [34-END] >> $RESULT_FILE 2>&1
            echo >> $RESULT_FILE 2>&1
            echo [U-34]Result : GOOD >> $RESULT_FILE 2>&1
        fi
    fi
fi

echo >> $RESULT_FILE 2>&1

echo [U-35]웹서비스 디렉토리 리스팅 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-35]웹서비스 디렉토리 리스팅 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [35-START] >> $RESULT_FILE 2>&1
find / -name 'httpd.conf' -exec cp -a {} httpd.conf \; 2>/dev/null
echo -e 'U-35 ~ U-41 영역은 추후 검토 필요'>> $RESULT_FILE 2>&1
echo [35-END] >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [U-35]Result : MANUAL >> $RESULT_FILE 2>&1

echo [U-42]최신 보안패치 및 벤더 권고사항 적용
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-42]최신 보안패치 및 벤더 권고사항 적용   >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [42-START] >> $RESULT_FILE 2>&1
		echo "★ 아래 현황을 기반으로 수동분석" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo "1. openssl version" >> $RESULT_FILE 2>&1
		openssl version >> $RESULT_FILE 2>&1
		echo "2. bash shell version" >> $RESULT_FILE 2>&1
		bash --version | grep "bash" >> $RESULT_FILE 2>&1
		rpm -qa | grep bash >> $RESULT_FILE 2>&1
		echo "2.1 bash 취약점 테스트(벤더사 제공)" >> $RESULT_FILE 2>&1
		env x='() { :;}; echo vulnerable' bash -c "echo this is a test" >> $RESULT_FILE 2>&1
		echo "3. ssh version"  >> $RESULT_FILE 2>&1
		ssh -V >> $RESULT_FILE 2>&1
		echo -e "** 최신 OpenSSH 버전은 $ssh_ver 입니다. **" >> $RESULT_FILE 2>&1
		echo -e "** 최신 OpenSSL 버전은 $ssl_ver 입니다. **" >> $RESULT_FILE 2>&1		
		echo "4. OS Version" >> $RESULT_FILE 2>&1
		uname -a >> $RESULT_FILE 2>&1
		cat /etc/redhat-release >> $RESULT_FILE 2>&1
		echo "5. env" >> $RESULT_FILE 2>&1
		env >> $RESULT_FILE 2>&1
		echo [42-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-42]RESULT : MANUAL >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

### utmp, wtmp ,btmp 등의 로그를 확인하여 마지막 로그인 시간, 접속 IP, 실패한 이력 등을 확인하여 계정 탈취 공격 및 시스템 해킹 여부를 검토
### sulog를 확인하여 허용된 계정 외에 su 명령어를 통해 권한상승을 시도하였는지 검토
### xferlog를 확인하여 비인가자의 ftp 접근 여부를 검토
### 로그 분석에 대한 결과 보고서 작성 및 분석 결과보고서 체계 수립 되어 있습니까?
echo [U-43]로그의 정기적 검토 및 보고
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-43]로그의 정기적 검토 및 보고  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [43-START] >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo "★ 인터뷰 점검 항목" >> $RESULT_FILE 2>&1
echo [43-END] >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [U-43]Result : MANUAL >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-44]root 이외의 UID가 ‘0’ 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-44]root 이외의 UID가 ‘0’ 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [44-START] >> $RESULT_FILE 2>&1
if [ `awk -F: '$3==0 {print $0}' /etc/passwd | grep -v 'root' | wc -l` -eq 0 ]
	then
		echo "★ root 이외의 UID가 '0'인 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F: '$3==0 {print $0}' /etc/passwd >> $RESULT_FILE 2>&1
		echo [44-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-44]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ root 이외의 UID가 '0'인 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F: '$3==0 {print $0}' /etc/passwd >> $RESULT_FILE 2>&1
		echo [44-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-44]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-45]root 계정 su 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-45]root 계정 su 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [45-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/group | grep 'wheel' | awk -F ':' '$4!=null { print $0 }' | wc -l` -eq 0 ]
	then
		echo "wheel 그룹 내 추가된 사용자가 없습니다." >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [45-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-45]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		echo "wheel 그룹이 존재합니다. 추가된 사용자에 대한 검토 메뉴얼 필요." >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/group | grep wheel  >> $RESULT_FILE 2>&1
		echo [45-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-45]Result : MANUAL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-46]패스워드 최소 길이 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-46]패스워드 최소 길이 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [46-START] >> $RESULT_FILE 2>&1
if [ -f /etc/security/pwquality.conf ]; then
	pass_min_len=$(awk -F'=' '/^minlen/ { print $2 }' /etc/security/pwquality.conf)
        if [[ $pass_min_len -ge 8 ]]; then
		echo "패스워드 최소 길이를 준수하고 있음" >> $RESULT_FILE 2>&1
                echo "[현황]" >> $RESULT_FILE 2>&1
                $pass_min_len >> $RESULT_FILE 2>&1		
		echo [46-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-46]Result : GOOD >> $RESULT_FILE 2>&1
    else
	    echo "패스워드 최소 길이를 준수하고 있지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/security/pwquality.conf  | grep "minlen" >> $RESULT_FILE 2>&1
		echo [46-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-46]Result : VULNERABLE >> $RESULT_FILE 2>&1
    fi
else
    echo "/etc/security/pwquality.conf 파일을 찾을 수 없음."
fi
echo >> $RESULT_FILE 2>&1

echo [U-47]패스워드 최대 사용기간 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-47]패스워드 최대 사용기간 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [47-START] >> $RESULT_FILE 2>&1
MAX_PASSWORD_AGE=90
MAX_PASSWORD_AGE_CONFIG=$(cat /etc/login.defs | grep -v '^ *#' | grep "PASS_MAX_DAYS" | awk '{print $2}')
if [ -z "$MAX_PASSWORD_AGE_CONFIG" ]
	then
		echo "패스워드 최대 사용기간 설정이 되어 있지 않음"
		echo [47-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-47]Result : VULNERABLE >> $RESULT_FILE 2>&1
		exit 1
fi
if [ "$MAX_PASSWORD_AGE_CONFIG" -le "$MAX_PASSWORD_AGE" ]
	then
    	echo "패스워드 최대 사용기간을 준수하고 있음" >> $RESULT_FILE 2>&1
		echo [47-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-47]Result : GOOD >> $RESULT_FILE 2>&1
else
		echo "패스워드 최대 사용기간을 준수하고 있지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/login.defs |grep -v '^ *#' |  grep "PASS_MAX_DAYS" >> $RESULT_FILE 2>&1
		echo [47-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-47]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-48]패스워드 최소 사용기간 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-48]패스워드 최소 사용기간 설정 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [48-START] >> $RESULT_FILE 2>&1
if [ -f /etc/login.defs ]
	then
		if [ `grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 최소 사용 기간 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo [9-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-9]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				if [ `grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" | awk '{print $2}'` -eq 1 ]
					then
						echo "★ 패스워드 최소 사용 기간 설정이 정책에 맞게 적용되어 있음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo [9-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-9]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 패스워드 최소 사용 기간 설정이 적용되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo [9-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-9]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
	else
		echo "★ /etc/login.defs 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [9-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-9]Result : MANUAL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-49]불필요한 계정 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-49]불필요한 계정 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [49-START] >> $RESULT_FILE 2>&1
touch $dir/check_49_3.txt
cat /etc/passwd | egrep -v 'false|nologin|null|halt|sync|shutdown|rpm|new' > $dir/check_49_1.txt
cat $dir/check_49_1.txt | awk -F: '{print $1}' > $dir/check_49_2.txt
for i in `cat $dir/check_49_2.txt`; do 
lastlog -u $i | grep $i >> $dir/check_49_3.txt; done
if [ `awk -F ":" '$3 >= 500 {print $0}' /etc/passwd | grep -v "nfsnobody" | wc -l` -eq 0 ]
	then
		echo "★ UID 500 이상 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "1. 계정별 최근 접속기록" >> $RESULT_FILE 2>&1
		cat $dir/check_49_3.txt >> $RESULT_FILE 2>&1
		echo [49-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-49]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ UID 500 이상 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F ":" '$3 >= 500 {print $0}' /etc/passwd | grep -v "nfsnobody" >> $RESULT_FILE 2>&1
		echo "1. 계정별 최근 접속기록" >> $RESULT_FILE 2>&1
		cat $dir/check_49_3.txt >> $RESULT_FILE 2>&1
		echo [49-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-49]Result : MANUAL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-50]관리자 그룹에 최소한의 계정 포함
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-50]관리자 그룹에 최소한의 계정 포함 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [50-START] >> $RESULT_FILE 2>&1
grep "^root" /etc/group | awk -F ":" '{print $4}' | sed s/,/\\n/g | grep -v "^root$" | wc -w > check_50.txt
if [ `cat check_50.txt` -eq 0 ]
	then
		echo "★ 관리자 그룹에 root 이외의 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep "^root" /etc/group >> $RESULT_FILE 2>&1
		echo [50-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-50]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 관리자 그룹에 root 이외의 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep "^root" /etc/group >> $RESULT_FILE 2>&1
		echo [50-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-50]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm -rf check_50.txt
echo >> $RESULT_FILE 2>&1

echo [U-51]계정이 존재하지 않는 GID 금지 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-51]계정이 존재하지 않는 GID 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [51-START] >> $RESULT_FILE 2>&1
	awk -F : '$4 == null {print $0}' /etc/group | awk -F : '$3 >= 500 {print $0}' > $dir/check_group.txt
	awk -F : '{print $4}' /etc/passwd > $dir/check_passwd.txt
	for TGID in `cat $dir/check_passwd.txt`
	do
		grep -v ":$TGID:" $dir/check_group.txt > $dir/check_51.txt
		cat $dir/check_51.txt > $dir/check_group.txt
	done
	if [ `cat $dir/check_group.txt | wc -w` -eq 0 ]
	then
		echo "★ 계정이 존재하지 않는 500 이상 GID가 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [51-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-51]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 계정이 존재하지 않는 500 이상 GID가 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1 
		cat $dir/check_group.txt >> $RESULT_FILE 2>&1 
		echo [51-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-51]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
echo >> $RESULT_FILE 2>&1

echo [U-52]동일한 UID 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-52]동일한 UID 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [52-START] >> $RESULT_FILE 2>&1
awk -F : '{print $3}' /etc/passwd > $dir/tmp_passwd.txt
	if [ `cat $dir/tmp_passwd.txt | sort | uniq -d | wc -l` -eq 0 ]
		then
			echo "★ 중복된 UID가 존재하지 않음" >> $RESULT_FILE 2>&1
			echo [52-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-52]Result : GOOD >> $RESULT_FILE 2>&1
		else
			echo "★ 중복된 UID가 존재함" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1 
			DUID=`cat $dir/tmp_passwd.txt | sort | uniq -d`
			grep "x:$DUID:" /etc/passwd >> $RESULT_FILE 2>&1
			echo [52-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-52]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
echo >> $RESULT_FILE 2>&1

echo [U-53]사용자 shell 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-53]사용자 shell 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [53-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" |  awk -F: '{print $7}'| egrep -v 'false|nologin|null|halt|sync|shutdown' | wc -l` -eq 0 ]
	then
		echo "★ 점검 대상 시스템 계정에 쉘이 부여되지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" >> $RESULT_FILE 2>&1
		echo [53-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-53]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 점검 대상 시스템 계정에 쉘이 부여됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" >> $RESULT_FILE 2>&1
		echo [53-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-53]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-54]Session Timeout 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-54]Session Timeout 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [54-START] >> $RESULT_FILE 2>&1
	if [ `echo $TMOUT | wc -w` -eq 0 ]
	then
		echo "★ 세션 타임아웃이 설정되지 않음" >> $RESULT_FILE 2>&1
		echo [54-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-54]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		if [ `echo $TMOUT` -gt 600 ]
		then
			echo "★ 세션 타임아웃이 설정되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			echo "TMOUT : `echo $TMOUT`" >> $RESULT_FILE 2>&1
			echo [54-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-54]Result : VULNERABLE >> $RESULT_FILE 2>&1
		else
			echo "★ 세션 타임아웃이 정책에 맞게 설정됨" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			echo "TMOUT : `echo $TMOUT`" >> $RESULT_FILE 2>&1
			echo [54-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-54]Result : GOOD >> $RESULT_FILE 2>&1
		fi
	fi
	echo >> $RESULT_FILE 2>&1

echo [U-55]hosts.lpd 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-55]hosts.lpd 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [55-START] >> $RESULT_FILE 2>&1
if [ -e /etc/hosts.lpd ]
	then
		if [ "$(stat -c %a /etc/hosts.lpd)" = "600" ] && [ "$(stat -c %U /etc/hosts.lpd)" = "root" ]
			then
				echo "hosts.lpd 파일의 소유자 및 퍼미션(600)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo [55-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-55]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "hosts.lpd 파일의 소유자 및 퍼미션(600)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/hosts.lpd >> $RESULT_FILE 2>&1
				echo [9-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-9]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
			else
				echo "/etc/hosts.lpd 파일이 존재하지 않음" >> "$RESULT_FILE" 2>&1
				echo "[55-END]" >> "$RESULT_FILE" 2>&1
				echo >> "$RESULT_FILE" 2>&1
				echo "[U-54]Result : GOOD" >> "$RESULT_FILE" 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-56]UMASK 설정 관리
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-56]UMASK 설정 관리  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [56-START] >> $RESULT_FILE 2>&1
if [ `umask` -eq 0022 ]
	then
		echo "★ UMASK 값이 적절하게 설정됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1		
		echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
		echo [56-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-56]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `umask` -eq 0027 ]
			then
				echo "★ UMASK 값이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1		
				echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
				echo [56-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-56]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ UMASK 값이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1		
				echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
				echo [56-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-56]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1

echo [U-57]홈디렉토리 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-57]홈디렉토리 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [57-START] >> $RESULT_FILE 2>&1
	ls -l /home/ | grep -v "+found" | sed -n '2,$p' > $dir/tmp_57_1.txt
	cat $dir/tmp_57_1.txt | grep -v "^........w." > $dir/tmp_57_2.txt
	if [ `cat $dir/tmp_57_1.txt | wc -l` -eq 0 ]
	then
		echo "★ 사용자 홈디렉토리가 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [57-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-57]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `diff $dir/tmp_57_1.txt $dir/tmp_57_2.txt | wc -l` -eq 0 ]
		then
			echo "★ 사용자 홈디렉토리의 퍼미션(o-w)이 적절하게 설정되어 있음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			cat $dir/tmp_57_1.txt >> $RESULT_FILE 2>&1
			echo [57-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-57]Result : GOOD >> $RESULT_FILE 2>&1
		else
			echo "★ 사용자 홈디렉토리의 퍼미션(o-w)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			cat $dir/tmp_57_1.txt | grep "^........w." >> $RESULT_FILE 2>&1
			echo [57-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-57]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	fi
echo >> $RESULT_FILE 2>&1

echo [U-58]홈디렉토리로 지정한 디렉토리의 존재 관리
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-58]홈디렉토리로 지정한 디렉토리의 존재 관리  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [58-START] >> $RESULT_FILE 2>&1
		cat /etc/passwd | awk -F: '$3>=1000 {print $0}' > $dir/tmp_58_1.txt
		cat $dir/tmp_58_1.txt | awk -F: '{print $6}' > $dir/tmp_58_2.txt
		touch $dir/tmp_58_3.txt
		for i in `cat $dir/tmp_58_2.txt`
			do
				if [ -d $i ]; then echo $i >> $dir/tmp_58_3.txt; else true; fi
		done
		if [ `diff $dir/tmp_58_2.txt $dir/tmp_58_3.txt | wc -l` -eq 0 ]
			then
				echo "★ 홈디렉토리가 존재하지 않는 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
				echo [58-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-58]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 홈디렉토리가 존재하지 않는 계정이 존재함" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				diff $dir/tmp_58_2.txt $dir/tmp_58_3.txt | grep "<" | awk '{print $2}' > $dir/tmp_58_4.txt
				for i in `cat $dir/tmp_58_4.txt`
					do
						cat /etc/passwd | grep $i | awk -F: '{print "계정  "$1"  의 홈디렉토리  "$6"  가 존재하지 않음"}' >> $RESULT_FILE 2>&1
				done
				echo [58-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-58]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
echo >> $RESULT_FILE 2>&1

echo [U-59]숨겨진 파일 및 디렉토리 검색 및 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-59]숨겨진 파일 및 디렉토리 검색 및 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [59-START] >> $RESULT_FILE 2>&1
	file=`find / ! \( \( -path '/var/lib/rpm' -o -path '/.autorelabel' -o -path '/etc/skel' -o -path '/sys' -o -path '/run' -o -path '/boot' -o -path '/usr/lib*' -o -path '/home/*/.bash*' -o -path '/root/.bash*' -o -path '/usr/src/kernels' -o -path '/opt/SE' \) -prune \) -name ".*" 2>/dev/null >> $dir/tmp_59_1.txt`
	if [ `cat $dir/tmp_59_1.txt | wc -l` -gt 0 ]; then
                echo "★ 숨겨진 파일 및 디렉토리가 존재함" >> $RESULT_FILE 2>&1
                echo -e "[현황] \n`cat $dir/tmp_59_1.txt`" >> $RESULT_FILE 2>&1
                echo -e "총 갯수 : `cat $dir/tmp_59_1.txt | wc -l`" >> $RESULT_FILE 2>&1
                echo [59-END] >> $RESULT_FILE 2>&1
                echo >> $RESULT_FILE 2>&1
                echo [U-59]Result : VULNERABLE >> $RESULT_FILE 2>&1
        else
                echo "★ 숨겨진 파일 및 디렉토리가 존재하지 않음" >> $RESULT_FILE 2>&1
                echo [59-END] >> $RESULT_FILE 2>&1
                echo >> $RESULT_FILE 2>&1
                echo [U-59]Result : GOOD >> $RESULT_FILE 2>&1
fi

echo >> $RESULT_FILE 2>&1

echo [U-60]ssh 원격접속 허용
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-60]ssh 원격접속 허용  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [60-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "sshd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SSH 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [60-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-60]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		echo "★ SSH 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "sshd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [60-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-60]Result : GOOD >> $RESULT_FILE 2>&1
fi

if [ `ps -ef | grep 'telnet' | grep -v 'grep' | wc -l` -gt 0 ]; then
		echo -e "★ TELNET 서비스가 실행중이므로 점검 필요\n" >> $RESULT_FILE 2>&1
fi

echo >> $RESULT_FILE 2>&1

echo [U-61]ftp 서비스 확인
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-61]ftp 서비스 확인  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [61-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [61-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-61]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ FTP 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "ftpd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [61-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-61]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-62]ftp 계정 shell 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-62]ftp 계정 shell 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [62-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/passwd | egrep "^ftp" | wc -l` -eq 0 ]
	then
		echo "★ /etc/passwd 파일에 'ftp' 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [62-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-62]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat /etc/passwd | egrep "^ftp" | awk -F: '{print $7}' | egrep -v "false" | wc -l` -eq 0 ]
			then
				echo "★ 'ftp' 계정에 로그인 가능한 쉘이 부여됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat /etc/passwd | egrep "^ftp"  >> $RESULT_FILE 2>&1
				echo [62-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-62]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 'ftp' 계정에 로그인 가능한 쉘이 부여되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat /etc/passwd | egrep "^ftp" >> $RESULT_FILE 2>&1
				echo [62-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-62]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1

echo [U-63]ftpusers 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-63]ftpusers 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [63-START] >> $RESULT_FILE 2>&1
if [ -e /etc/ftpusers ]
	then
		if [ "$(stat -c %a /etc/ftpusers)" = "640" ] && [ "$(stat -c %U /etc/ftpusers)" = "root" ]
			then
				echo "ftpusers 파일의 소유자 및 퍼미션(640)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo [63-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-63]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "ftpusers 파일의 소유자 및 퍼미션(640)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/ftpusers >> $RESULT_FILE 2>&1
				echo [63-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-63]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
			else
				echo "/etc/ftpusers 파일 존재하지 않음" >> "$RESULT_FILE" 2>&1
				echo "[63-END]" >> "$RESULT_FILE" 2>&1
				echo >> "$RESULT_FILE" 2>&1
				echo "[U-63]Result : GOOD" >> "$RESULT_FILE" 2>&1
	fi
echo >> $RESULT_FILE 2>&1

echo [U-64]ftpusers 파일 설정 FTP 서비스 root 계정 접근제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-64]ftpusers 파일 설정 FTP 서비스 root 계정 접근제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [64-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [64-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-64]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "ftpusers" -exec cp -a {} $dir/ftpusers \;
		if [ `cat $dir/ftpusers | wc -l` -eq 0 ]
			then
				echo "★ ftpusers 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [64-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-64]Result : GOOD >> $RESULT_FILE 2>&1
			else
				if [ `cat $dir/ftpusers | grep "root" | grep -v "^ *#" | wc -l` -gt 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, ftpusers 파일에 root가 존재함" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat $dir/ftpusers | grep "root" | grep -v "^ *#"  >> $RESULT_FILE 2>&1
						echo [64-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [SU-64]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, ftpusers 파일에 root가 존재하지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat $dir/ftpusers | grep "root" | grep -v "^ *#"  >> $RESULT_FILE 2>&1
						echo [64-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [SU-64]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi	
fi
echo >> $RESULT_FILE 2>&1

echo [U-65]at 서비스 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-65]at 서비스 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
file_a=/etc/at.allow
file_d=/etc/at.deny
own_a=$(stat -c %U "$file_a" 2>/dev/null)
own_d=$(stat -c %U "$file_d" 2>/dev/null)
perm_a=$(stat -c %a "$file_a" 2>/dev/null)
perm_d=$(stat -c %a "$file_d" 2>/dev/null)
cnt=0

echo "[현황]" >> $RESULT_FILE 2>&1

if [ -e $file_a ]; then
        if [[ "$own_a" != "root" ]] || [[ "$perm_a" -gt "640" ]]; then
                echo -e "$file_a 파일의 소유자 및 퍼미션(640)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
                echo "[현황]" >> $RESULT_FILE 2>&1
                ls -alL $file_a 2>/dev/null >> $RESULT_FILE 2>&1        
                cnt=$((cnt+1))
        else 
                echo -e "$file_a 파일의 소유자 및 퍼미션(640)이 적절하게 설정됨/n" >> $RESULT_FILE 2>&1

        fi
else
        echo -e "$file_a 파일이 존재하지 않습니다." >> $RESULT_FILE 2>&1
        
fi
if [ -e $file_d ]; then
        if [[ "$own_d" != "root" ]] || [[ "$perm_d" -gt "640" ]]; then
                echo -e "$file_d 파일의 소유자 및 퍼미션(640)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
                echo "[현황]" >> $RESULT_FILE 2>&1
                ls -alL $file_d 2>/dev/null >> $RESULT_FILE 2>&1
                cnt=$((cnt+1))
        else    
                echo -e "$file_d 파일의 소유자 및 퍼미션(640)이 적절하게 설정됨\n" >> $RESULT_FILE 2>&1
        fi    
else
        echo -e "$file_d 파일이 존재하지 않습니다." >> $RESULT_FILE 2>&1
fi

if [ $cnt -ge 1 ]; then
        echo "[U-65]Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
        echo [U-65]Result : GOOD >> $RESULT_FILE 2>&1

fi

echo >> $RESULT_FILE 2>&1

echo [U-66]SNMP 서비스 구동 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-66]SNMP 서비스 구동 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "snmp" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SNMP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [66-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-66]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ SNMP 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "snmp" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [66-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-66]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-67]SNMP 서비스 Community String의 복잡성 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-67]SNMP 서비스 Community String의 복잡성 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "snmpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SNMP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [67-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-67]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "snmpd.conf" -exec cp -a {} $dir/tmp_67_1.txt \;
		if [ `cat $dir/tmp_67_1.txt | wc -l` -gt 0 ]
			then
				if [ `cat $dir/tmp_67_1.txt | grep "public" | grep -v "^ *#" | wc -l` -eq 0 ]
					then
						echo "★ SNMP Community String이 임의의 값으로 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat $dir/tmp_67_1.txt | grep -v "^ *#" >> $RESULT_FILE 2>&1
						echo [67-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-67]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ SNMP Community String이 기본값으로 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat $dir/tmp_67_1.txt | grep -v "^ *#" >> $RESULT_FILE 2>&1
						echo [67-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-67]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				echo "★ SNMP 서비스가 실행중이나 설정파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [67-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-67]Result : MANUAL >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1

echo [U-68]로그온 시 경고 메시지 제공
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-68]로그온 시 경고 메시지 제공  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ `cat /etc/issue.net | wc -l` -gt 2 ]
	then
		if [ `cat /etc/motd | wc -l` -gt 0 ]
			then
				echo "★ /etc/issue.net, /etc/motd 파일에 경고 메시지가 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				echo "1) /etc/issue.net 파일 내용" >> $RESULT_FILE 2>&1
				cat /etc/issue.net >> $RESULT_FILE 2>&1
				echo "2) /etc/motd 파일 내용" >> $RESULT_FILE 2>&1
				cat /etc/motd >> $RESULT_FILE 2>&1
				echo [68-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-68]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/motd 파일에 경고 메시지가 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [68-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-68]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		if [ `cat /etc/motd | wc -l` -gt 0 ]
			then
				echo "★ /etc/issue.net 파일에 경고 메시지가 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [68-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-68]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/issue.net, /etc/motd 파일에 경고 메시지가 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [68-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-68]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1

echo [U-69]NFS 설정파일 접근권한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-69]NFS 설정파일 접근권한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
file="/etc/exports"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 644 ]; then
		echo "★ /etc/exports 파일의 퍼미션(644)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ls -l /etc/exports >> $RESULT_FILE 2>&1
		echo [69-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-69]Result : GOOD >> $RESULT_FILE 2>&1
    else
		echo "★ /etc/exports 파일의 퍼미션(644)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ls -l /etc/exports >> $RESULT_FILE 2>&1
		echo [69-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-69]Result : VULNERABLE >> $RESULT_FILE 2>&1
    fi
else
    echo "The /etc/exports 파일을 찾을 수 없음." >> "$RESULT_FILE" 2>&1
    echo [69-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-69]Result : N/A" >> "$RESULT_FILE" 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo [U-70]expn, vrfy 명령어 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-70]expn, vrfy 명령어 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [70-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-70]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [70-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-70]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cp -a {} $dir/tmp_70.txt \;			
				cat $dir/tmp_70.txt | grep -i "O PrivacyOptions" > $dir/tmp_70_1.txt
				if [ `cat $dir/tmp_70_1.txt | grep -v "^ *#" | grep "noexpn" | grep "novrfy" | wc -l` -eq 0 ]
					then
						echo "★ Sendmail 서비스가 실행중이며 sendmail.cf 파일에 noexpn, novrfy 옵션이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat $dir/tmp_70_1.txt >> $RESULT_FILE 2>&1
						echo [70-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-70]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ Sendmail 서비스가 실행중이며 sendmail.cf 파일에 noexpn, novrfy 옵션이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat $dir/tmp_70_1.txt >> $RESULT_FILE 2>&1
						echo [70-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-70]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
echo >> $RESULT_FILE 2>&1

echo [U-71]Apache 웹 서비스 정보 숨김
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-71]Apache 웹 서비스 정보 숨김  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo -e 'U-71 영역은 추후 검토 필요'>> $RESULT_FILE 2>&1
echo [71-END] >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [U-71]Result : MANUAL >> $RESULT_FILE 2>&1

echo [U-72]정책에 따른 시스템 로깅 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-72]정책에 따른 시스템 로깅 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ -f /etc/syslog.conf ]
	then
		cat /etc/syslog.conf | grep -v "#" | awk '$0 != null {print $0}' >> $dir/tmp_72_1.txt
	else
		if [ -f /etc/rsyslog.conf ]
			then
				cat /etc/rsyslog.conf | grep -v "#" | awk '$0 != null {print $0}' >> $dir/tmp_72_1.txt
			else
				echo "★ (r)syslog.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [72-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-72]Result : N/A >> $RESULT_FILE 2>&1
		fi
fi
#if [ `cat $dir/tmp_72_1.txt | egrep -w "cron.\*|authpriv.\*|\*.info" | wc -l` -eq 3 ]
if [ `cat $dir/tmp_72_1.txt |   egrep "cron.\*|authpriv.\*|\*.info|mail.\*|\*.alert|\*.emerg|\/var\/log\/message|kern.\*" | grep -v '#' | wc -l` -gt 4 ]
	then
		echo "★ (r)syslog.conf 설정이 적절하게 설정됨 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat $dir/tmp_72_1.txt >> $RESULT_FILE 2>&1
		echo [72-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-72]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 아래 현황을 기반으로 수동분석 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat $dir/tmp_72_1.txt >> $RESULT_FILE 2>&1
		echo [72-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-72]Result : MANUAL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "주통 기반 72개 항목 리눅스(Rocky 8)에 대한 점검이 완료 되었습니다." >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

rm -rf $dir
rm -rf httpd.conf

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Version ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
uname -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/issue >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ ping test ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ping -c 3 www.google.com >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Interface ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ifconfig -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ cat /etc/passwd ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/passwd  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ cat /etc/shadow ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/shadow  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Socket ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
if command -v netstat &> /dev/null; then
    echo -e "netstat -lntp" >> $RESULT_FILE 2>&1
    netstat -anp | head -200 >> $RESULT_FILE 2>&1
else
    echo -e "netstat 명령어가 없어 ss 명령어를 사용합니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo -e "ss -lntp" >> $RESULT_FILE 2>&1
ss -lntp >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Daemon ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "ps -ef" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ps -ef >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ TCP Wrapper ]" >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

# /etc/hosts.deny 파일 확인
echo "1) /etc/hosts.deny" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
if [ -f /etc/hosts.deny ]; then
    cat /etc/hosts.deny >> $RESULT_FILE 2>&1
else
    echo "/etc/hosts.deny 파일이 존재하지 않습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

# /etc/hosts.allow 파일 확인
echo "2) /etc/hosts.allow" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
if [ -f /etc/hosts.allow ]; then
    cat /etc/hosts.allow >> $RESULT_FILE 2>&1
else
    echo "/etc/hosts.allow 파일이 존재하지 않습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

# 현재 실행 중인 네트워크 서비스 확인
echo "3) 현재 실행 중인 네트워크 서비스" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

# netstat이 존재하는지 확인 후 실행, 없으면 ss 사용
if command -v netstat &> /dev/null; then
    netstat -lntp >> $RESULT_FILE 2>&1
else
    ss -lntp >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ 패키지 검사 ]" >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

# 1) DNF(YUM) 패키지 검사
echo "1) DNF(YUM) 패키지 검사" >> $RESULT_FILE 2>&1
if command -v dnf &> /dev/null; then
    dnf list installed | awk 'NR>1 {print $1, $2}' >> $RESULT_FILE 2>&1
elif command -v yum &> /dev/null; then
    yum list installed | awk 'NR>1 {print $1, $2}' >> $RESULT_FILE 2>&1
else
    echo "DNF(YUM) 패키지가 설치되지 않았습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

# 2) Snap 패키지 검사 (Rocky에는 기본 없음)
echo "2) Snap 패키지 검사" >> $RESULT_FILE 2>&1
if command -v snap &> /dev/null; then
    snap list | awk 'NR>1 {print $1, $2}' >> $RESULT_FILE 2>&1
else
    echo "Snap 패키지가 설치되지 않았거나 지원되지 않습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

# 3) pip 패키지 검사
echo "3) pip 패키지 검사" >> $RESULT_FILE 2>&1
# python2 pip 검사
echo "3-1) Python pip 검사 결과" >> $RESULT_FILE 2>&1
if command -v pip &> /dev/null; then
    pip list --format=columns | awk 'NR>2 {print $1, $2}' >> $RESULT_FILE 2>&1
else
    echo "Python pip 패키지가 설치되지 않았습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

# python3 pip 검사
echo "3-2) Python3 pip 검사 결과" >> $RESULT_FILE 2>&1
if command -v pip3 &> /dev/null; then
    pip3 list --format=columns | awk 'NR>2 {print $1, $2}' >> $RESULT_FILE 2>&1
else
    echo "Python3 pip 패키지가 설치되지 않았습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

# 4) npm 패키지 검사
echo "4) npm 패키지 검사" >> $RESULT_FILE 2>&1
if command -v npm &> /dev/null; then
    npm list -g --depth=0 2>/dev/null | awk 'NR>1 {print $2}' | sed 's/@/ /' >> $RESULT_FILE 2>&1
else
    echo "npm이 설치되지 않았습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ 패키지 검사 완료 ]" >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "Nginx/Tomcat 취약점 진단 수행합니다." >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

### 서비스가 설치되었는지 확인하는 함수
check_nginx_installed() {
    if systemctl list-units --type=service --all | grep -q "nginx"; then
        echo "nginx 서비스가 설치되어 있습니다." >> $RESULT_FILE
        return 0  # nginx가 설치되어 있으면 0 반환
    else
        echo "nginx 서비스가 설치되지 않았습니다." >> $RESULT_FILE
        return 1  # nginx가 설치되지 않으면 1 반환
    fi
}

check_tomcat_installed() {
    # tomcat7, tomcat8, tomcat9, tomcat10 중 하나라도 서비스에 존재하는지 확인
    if systemctl list-units --type=service --all | grep -q "tomcat"; then
        echo "Tomcat 서비스가 설치되어 있습니다." >> $RESULT_FILE
        return 0  # Tomcat이 설치되었으면 0 반환
    else
        echo "Tomcat 서비스가 설치되지 않았습니다." >> $RESULT_FILE
        return 1  # Tomcat이 설치되지 않으면 1 반환
    fi
}

### 서비스가 실행 중인지 확인하는 함수
check_nginx_running() {
    if systemctl is-active --quiet "nginx"; then
        echo "nginx 서비스 실행 중입니다." >> $RESULT_FILE
        return 0  # nginx가 실행 중이면 0 반환
    else
        echo "nginx 서비스 실행 중이 아닙니다." >> $RESULT_FILE
        return 1  # nginx가 실행 중이 아니면 1 반환
    fi
}

check_tomcat_running() {
    # tomcat7, tomcat8, tomcat9, tomcat10 중 실행 중인 서비스를 확인
    if systemctl is-active --quiet tomcat7 || systemctl is-active --quiet tomcat8 || systemctl is-active --quiet tomcat9 || systemctl is-active --quiet tomcat10; then
        echo "Tomcat 서비스 실행 중." >> $RESULT_FILE
        return 0  # Tomcat 서비스가 실행 중이면 0 반환
    else
        echo "Tomcat 서비스 실행 중이 아닙니다." >> $RESULT_FILE
        return 1  # Tomcat 서비스가 실행 중이 아니면 1 반환
    fi
}

### Tomcat 설치 경로 자동 탐색 함수
find_tomcat_home() {
    CANDIDATE_PATHS=(
        "/usr/share/tomcat"
        "/usr/share/tomcat8"
        "/usr/share/tomcat9"
        "/usr/share/tomcat10"
        "/usr/share/tomcat11"
        "/usr/libexec/tomcat"
        "/usr/local/tomcat"
        "/usr/local/tomcat8"
        "/usr/local/tomcat9"
        "/usr/local/tomcat10"
        "/usr/local/tomcat11"
        "/etc/tomcat"
        "/etc/tomcat8"
        "/etc/tomcat9"
        "/etc/tomcat10"
        "/etc/tomcat11"
        "/opt/tomcat"
        "/opt/tomcat8"
        "/opt/tomcat9"
        "/opt/tomcat10"
        "/opt/tomcat11"
    )

    # 설치 디렉토리 찾기
    for path in "${CANDIDATE_PATHS[@]}"; do
        if [[ -d "$path" && -f "$path/bin/catalina.sh" ]]; then
            echo "$path"
            return 0
        fi
    done

    # find 명령어로 추가 검색 (Rocky Linux 최적화)
    TOMCAT_PATH=$(find /usr/share /usr/libexec /etc /opt -name "catalina.sh" 2>/dev/null | head -n 1)
    if [[ -n "$TOMCAT_PATH" ]]; then
        echo "$(dirname "$(dirname "$TOMCAT_PATH")")"
        return 0
    fi

    echo "Tomcat 설치 경로를 찾을 수 없습니다."
    return 1
}
# Tomcat 취약점 진단 수행 함수
check_tomcat_vulnerability() {
    TOMCAT_HOME=$(find_tomcat_home)
    if [[ "$TOMCAT_HOME" == "Tomcat 설치 경로를 찾을 수 없습니다." ]]; then
        echo "Tomcat이 설치되지 않았습니다. 점검을 중단합니다." >> $RESULT_FILE 2>&1
        return 1
    fi

    TOMCAT_USERS_FILE="$TOMCAT_HOME/conf/tomcat-users.xml"
    TOMCAT_WEBAPPS="$TOMCAT_HOME/webapps"
    TOMCAT_CONF_FILE="$TOMCAT_HOME/conf/server.xml"
    LOG_FILE="$TOMCAT_HOME/logs/catalina.out"
    BACKUP_DIR="/var/log/tomcat-backup"
    
    # Rocky Linux 기반 OS 확인
    OS_TYPE=$(awk -F= '/^ID_LIKE=/{print $2}' /etc/os-release | tr -d '"')
    [[ -z "$OS_TYPE" ]] && OS_TYPE=$(awk -F= '/^ID=/{print $2}' /etc/os-release | tr -d '"')

    USERS_FILE_PERMISSION=$(stat --format "%a" "$TOMCAT_USERS_FILE")
    CONF_FILE_PERMISSION=$(stat --format "%a" "$TOMCAT_CONF_FILE")
    LOG_PERMISSION=$(stat --format "%a" "$LOG_FILE")
    DIR_PERMISSION=$(stat --format "%a" "$TOMCAT_WEBAPPS")

    echo "[TO-01] Default 관리자 계정명 변경" >> $RESULT_FILE 2>&1
    if grep -iq "tomcat" "$TOMCAT_USERS_FILE"; then
        echo "★ 기본 관리자 계정 사용 중" >> $RESULT_FILE 2>&1
        echo "[TO-01] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    else
        echo "★ 기본 관리자 계정 변경됨" >> $RESULT_FILE 2>&1
        echo "[TO-01] Result : GOOD" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-02] 취약한 패스워드 사용 제한" >> $RESULT_FILE 2>&1
    if grep -iq "password" "$TOMCAT_USERS_FILE"; then
        echo "★ 취약한 패스워드 사용 감지" >> $RESULT_FILE 2>&1
        echo "[TO-02] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    else
        echo "★ 취약한 패스워드 사용 없음" >> $RESULT_FILE 2>&1
        echo "[TO-02] Result : GOOD" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-03] 패스워드 파일 권한 관리" >> $RESULT_FILE 2>&1
    if [[ "$USERS_FILE_PERMISSION" -eq 644 ]]; then
        echo "★ 패스워드 파일 권한 취약 (644)" >> $RESULT_FILE 2>&1
        echo "[TO-03] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    else
        echo "★ 패스워드 파일 권한 안전" >> $RESULT_FILE 2>&1
        echo "[TO-03] Result : GOOD" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-04] 홈디렉토리 쓰기 권한 관리" >> $RESULT_FILE 2>&1
    if [[ "$DIR_PERMISSION" -ge 755 ]]; then
        echo "★ Document Root 권한 안전" >> $RESULT_FILE 2>&1
        echo "[TO-04] Result : GOOD" >> $RESULT_FILE 2>&1
    else
        echo "★ Document Root 권한 취약" >> $RESULT_FILE 2>&1
        echo "[TO-04] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-05] 환경설정 파일 권한 관리" >> $RESULT_FILE 2>&1
    if [[ "$CONF_FILE_PERMISSION" -ge 644 ]]; then
        echo "★ 환경설정 파일 권한 안전" >> $RESULT_FILE 2>&1
        echo "[TO-05] Result : GOOD" >> $RESULT_FILE 2>&1
    else
        echo "★ 환경설정 파일 권한 취약" >> $RESULT_FILE 2>&1
        echo "[TO-05] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-06] 에러 메시지 관리" >> $RESULT_FILE 2>&1
    if grep -iq "<error-page>" "$TOMCAT_CONF_FILE"; then
        echo "★ 에러 메시지가 적절히 관리됨" >> $RESULT_FILE 2>&1
        echo "[TO-06] Result : GOOD" >> $RESULT_FILE 2>&1
    else
        echo "★ 에러 메시지 관리 필요" >> $RESULT_FILE 2>&1
        echo "[TO-06] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-07] 로그 파일 주기적 백업" >> $RESULT_FILE 2>&1
    if [[ -f "$LOG_FILE" && -d "$BACKUP_DIR" && $(ls -A "$BACKUP_DIR" | grep "catalina") ]]; then
        echo "★ 로그 파일이 주기적으로 백업됨" >> $RESULT_FILE 2>&1
        echo "[TO-07] Result : GOOD" >> $RESULT_FILE 2>&1
    else
        echo "★ 로그 파일 백업 필요" >> $RESULT_FILE 2>&1
        echo "[TO-07] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

    echo "[TO-08] 로그 파일 권한 설정" >> $RESULT_FILE 2>&1
    if [[ "$LOG_PERMISSION" -le 640 ]]; then
        echo "★ 로그 파일 권한 적절" >> $RESULT_FILE 2>&1
        echo "[TO-08] Result : GOOD" >> $RESULT_FILE 2>&1
    else
        echo "★ 로그 파일 권한 과다 허용 (현재: $LOG_PERMISSION)" >> $RESULT_FILE 2>&1
        echo "[TO-08] Result : VULNERABLE" >> $RESULT_FILE 2>&1
    fi
    echo >> $RESULT_FILE 2>&1

	echo "[TO-09] 최신 패치 적용" >> $RESULT_FILE 2>&1

	# Tomcat 경로 목록
	TOMCAT_PATHS=(
		"/opt/tomcat/bin/version.sh"
		"/usr/share/tomcat8/bin/version.sh"
		"/usr/share/tomcat9/bin/version.sh"
		"/usr/share/tomcat10/bin/version.sh"
		"/usr/share/tomcat11/bin/version.sh"
		"/usr/local/tomcat/bin/version.sh"
		"/etc/tomcat8/bin/version.sh"
		"/etc/tomcat9/bin/version.sh"
		"/etc/tomcat10/bin/version.sh"
		"/etc/tomcat11/bin/version.sh"
		"/var/lib/tomcat8/bin/version.sh"
		"/var/lib/tomcat9/bin/version.sh"
		"/var/lib/tomcat10/bin/version.sh"
		"/var/lib/tomcat11/bin/version.sh"
		"/home/tomcat/bin/version.sh"
		"/home/user/tomcat/bin/version.sh"
		"/opt/tomcat8/bin/version.sh"
		"/opt/tomcat9/bin/version.sh"
		"/opt/tomcat10/bin/version.sh"
		"/opt/tomcat11/bin/version.sh"
		"/usr/local/tomcat8/bin/version.sh"
		"/usr/local/tomcat9/bin/version.sh"
		"/usr/local/tomcat10/bin/version.sh"
		"/usr/local/tomcat11/bin/version.sh"
		"/var/tomcat8/bin/version.sh"
		"/var/tomcat9/bin/version.sh"
		"/var/tomcat10/bin/version.sh"
		"/var/tomcat11/bin/version.sh"
	)

	# 현재 설치된 Tomcat 버전 확인
	INSTALLED_TOMCAT_VERSION=""
	for TOMCAT_PATH in "${TOMCAT_PATHS[@]}"; do
		if [ -f "$TOMCAT_PATH" ]; then
			# version.sh 파일 실행하여 출력에서 "Server version" 부분을 추출
			INSTALLED_TOMCAT_VERSION=$(bash "$TOMCAT_PATH" 2>/dev/null | grep -i "Server version" | awk '{print $3"/"$4}')
			break
		fi
	done

	# Tomcat의 최신 버전 확인 (Tomcat 공식 사이트에서 최신 버전 확인)
	LATEST_TOMCAT_VERSION=""
	LATEST_TOMCAT_VERSION=$(curl -s https://tomcat.apache.org/ | grep -oP 'Tomcat \d+\.\d+\.\d+' | head -n 1 | awk '{print $2}')

	# URL 요청 실패 시 처리
	if [ -z "$LATEST_TOMCAT_VERSION" ]; then
		echo "★ 최신 Tomcat 버전을 가져오는 데 실패했습니다. 인터넷 연결 및 URL을 확인해주세요." >> $RESULT_FILE 2>&1
		echo "[TO-09] Result : VULNERABLE" >> $RESULT_FILE 2>&1
	else
		# 버전 비교 및 출력
		if [ "$INSTALLED_TOMCAT_VERSION" != "$LATEST_TOMCAT_VERSION" ]; then
			echo "★ Tomcat 버전이 최신 버전이 아닙니다. 최신 버전으로 업데이트 필요." >> $RESULT_FILE 2>&1
			echo "★ 현재 설치된 Tomcat 버전: $INSTALLED_TOMCAT_VERSION" >> $RESULT_FILE 2>&1
			echo "★ 최신 Tomcat 버전: $LATEST_TOMCAT_VERSION" >> $RESULT_FILE 2>&1
			echo "[TO-09] Result : VULNERABLE" >> $RESULT_FILE 2>&1
		else
			echo "★ Tomcat이 최신 버전으로 업데이트 되어 있습니다." >> $RESULT_FILE 2>&1
			echo "★ 현재 설치된 Tomcat 버전: $INSTALLED_TOMCAT_VERSION" >> $RESULT_FILE 2>&1
			echo "★ 최신 Tomcat 버전: $LATEST_TOMCAT_VERSION" >> $RESULT_FILE 2>&1
			echo "[TO-09] Result : GOOD" >> $RESULT_FILE 2>&1
		fi
	fi
	echo >> $RESULT_FILE 2>&1
}

# Nginx 취약점 진단 수행 함수
check_nginx_vulnerability() {
echo "[NG-01] 웹 서비스 영역의 분리" >> $RESULT_FILE 2>&1
NGINX_ROOT=$(grep -i 'root' /etc/nginx/nginx.conf)

if [[ $NGINX_ROOT =~ "/var/www/html" ]]; then
    echo "★ 웹 서비스 root 디렉토리 변경 필요: /var/www/html -> 다른 디렉토리로 변경 권장" >> $RESULT_FILE 2>&1
    echo "[NG-01] Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "★ 웹 서비스 root 디렉토리 변경이 완료되었습니다." >> $RESULT_FILE 2>&1
    echo "[NG-01] Result : GOOD" >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo "[NG-02] 불필요한 파일 제거" >> $RESULT_FILE 2>&1
if [ -d "/usr/share/nginx/html" ]; then
    echo "★ 불필요한 Sample/Manual 디렉토리가 존재합니다." >> $RESULT_FILE 2>&1
    echo "디렉토리 현황:" >> $RESULT_FILE 2>&1
    ls -l /usr/share/nginx/html >> $RESULT_FILE 2>&1  # 디렉토리 내 파일 목록을 결과에 기록
    echo "[NG-02] Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "★ Sample/Manual 디렉토리가 존재하지 않습니다." >> $RESULT_FILE 2>&1
    echo "[NG-02] Result : GOOD" >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo "[NG-03] 링크 사용금지" >> $RESULT_FILE
SYMLINKS=$(find /etc /home /var -type l -ls 2>/dev/null | grep -E '->')

if [ -n "$SYMLINKS" ]; then
    echo "★ 심볼릭 링크가 존재합니다." >> $RESULT_FILE
    echo "$SYMLINKS" >> $RESULT_FILE
    echo "[NG-03] Result : VULNERABLE" >> $RESULT_FILE
else
    echo "★ 심볼릭 링크가 존재하지 않습니다." >> $RESULT_FILE
    echo "[NG-03] Result : GOOD" >> $RESULT_FILE
fi
echo "" >> $RESULT_FILE

echo "[NG-04] 파일 업로드 및 다운로드 제한" >> $RESULT_FILE 2>&1
UPLOAD_LIMIT=$(grep -i 'client_max_body_size' /etc/nginx/nginx.conf)
if [ -z "$UPLOAD_LIMIT" ]; then
    echo "★ 파일 업로드 크기 제한 설정이 되어 있지 않습니다. 기본 크기 제한 추가 필요." >> $RESULT_FILE 2>&1
    echo "[NG-04] Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "★ 파일 업로드 크기 제한이 설정되어 있습니다: $UPLOAD_LIMIT" >> $RESULT_FILE 2>&1
    echo "[NG-04] Result : GOOD" >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo "[NG-05] 디렉토리 리스팅 제거" >> $RESULT_FILE 2>&1
DIR_LISTING=$(grep -i 'autoindex' /etc/nginx/nginx.conf)

if [[ $DIR_LISTING =~ "on" ]]; then
    echo "★ 디렉토리 리스팅이 활성화되어 있습니다. autoindex를 off로 설정 필요." >> $RESULT_FILE 2>&1
    echo "[NG-05] Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "★ 디렉토리 리스팅 비활성화 상태입니다." >> $RESULT_FILE 2>&1
    echo "[NG-05] Result : GOOD" >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo "[NG-06] 웹 프로세스 권한 제한" >> $RESULT_FILE 2>&1
PROCESS_USER=$(ps aux | grep nginx | grep -v grep | awk '{print $1}')

if [ "$PROCESS_USER" == "root" ]; then
    echo "★ 웹 서버가 root 권한으로 실행 중입니다. 권한 제한이 필요합니다." >> $RESULT_FILE 2>&1
    echo "[NG-06] Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "★ 웹 서버는 이미 non-root 사용자로 실행 중입니다." >> $RESULT_FILE 2>&1
    echo "[NG-06] Result : GOOD" >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo "[NG-07] 안정화 버전 및 패치 적용" >> $RESULT_FILE 2>&1
CURRENT_VERSION=$(nginx -v 2>&1 | awk -F/ '{print $2}')
LATEST_VERSION=$(dnf info nginx | grep -i "Version" | awk '{print $3}')

if [ "$CURRENT_VERSION" != "$LATEST_VERSION" ]; then
    echo "Nginx 버전이 최신 버전이 아닙니다. 최신 버전으로 업데이트 필요." >> $RESULT_FILE 2>&1
    echo "현재 설치된 Nginx 버전: $CURRENT_VERSION" >> $RESULT_FILE 2>&1
    echo "최신 Nginx 버전: $LATEST_VERSION" >> $RESULT_FILE 2>&1
    echo "[NG-07] Result : VULNERABLE" >> $RESULT_FILE 2>&1
else
    echo "Nginx가 최신 버전으로 업데이트 되어 있습니다." >> $RESULT_FILE 2>&1
    echo "현재 설치된 Nginx 버전: $CURRENT_VERSION" >> $RESULT_FILE 2>&1
    echo "최신 Nginx 버전: $LATEST_VERSION" >> $RESULT_FILE 2>&1
    echo "[NG-07] Result : GOOD" >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
}

### 실행 중인 서비스 진단 수행
# nginx 서비스가 설치되었는지 확인
if check_nginx_installed; then
    # nginx 서비스가 실행 중인지 확인
    if check_nginx_running; then
        check_nginx_vulnerability 
    else
        echo "nginx 서비스가 실행 중이 아닙니다." >> $RESULT_FILE
    fi
else
    echo "nginx 서비스가 설치되지 않았습니다." >> $RESULT_FILE
fi

# Tomcat 서비스가 설치되었는지 확인
if check_tomcat_installed; then
    # Tomcat 서비스가 실행 중인지 확인
    if check_tomcat_running; then
        check_tomcat_vulnerability
    else
        echo "Tomcat 서비스가 실행 중이 아닙니다." >> $RESULT_FILE
    fi
else
    echo "Tomcat 서비스가 설치되지 않았습니다." >> $RESULT_FILE
fi

### 최종 종료
echo "============================================================" >> $RESULT_FILE 2>&1
echo "Nginx/Tomcat 취약점 진단 완료되었습니다." >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
}
########### Cent OS 수정은 이곳에서 합니다. ###########
check_centos() {

eecho ""
echo "CentOS 운영 체제 보안 취약점 진단 스크립트를 실행합니다."
echo ""
echo "==============================  START  ==============================" 
echo ""

IP=`ifconfig -a | grep  "inet" | head -1 | awk '{print $2}'`
RESULT_FILE=./CentOS@@`hostname`@@$IP.txt

echo [U-1]root 계정 원격 접속 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-1]root 계정 원격 접속 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [1-START] >> $RESULT_FILE 2>&1
if [ `find /etc -type f -name "sshd_config" | wc -l` -eq 0 ]
	then
		echo "★ sshd_config 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [1-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-1]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SSHCONFIG=`find /etc -type f -name "sshd_config"`
		if [ `grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "#" | grep -i "no" | wc -l` -eq 0 ]
			then
				echo "★ root 계정 원격 접속이 제한되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "without" >> $RESULT_FILE 2>&1
				echo [1-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-1]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ root 계정 원격 접속이 제한됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "permitrootlogin" $SSHCONFIG | grep -v "setting" | grep -v "without" >> $RESULT_FILE 2>&1
				echo [1-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-1]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-2]패스워드 복잡성 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-2]패스워드 복잡성 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [2-START] >> $RESULT_FILE 2>&1
		if [ `find /etc -name "pwquality.conf" | wc -l` -eq 0 ]
		then
			echo "★ pwquality.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
			echo [2-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [SU-02]Result : MANUAL >> $RESULT_FILE 2>&1
		else
			PWQUALITY=`find /etc -name "pwquality.conf"`
			if [ `grep -i "credit" $PWQUALITY | grep "=" | grep -v "#" | wc -l` -ge 3 ]
			then
				echo "★ 패스워드 복잡성 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "credit" $PWQUALITY | grep "=" >> $RESULT_FILE 2>&1
				echo [2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-02]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 패스워드 복잡성 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "credit" $PWQUALITY | grep "=" >> $RESULT_FILE 2>&1
				echo [2-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-02]Result : VULNERABLE >> $RESULT_FILE 2>&1
			fi
		fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-3]계정 잠금 임계값 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-3]계정 잠금 임계값 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [3-START] >> $RESULT_FILE 2>&1
if [ `find /etc -name "system-auth" | wc -l` -eq 0 ]
	then
		echo "★ system-auth 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [3-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-3]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		SYSAUTHAC=`find /etc -name "system-auth"`
		if [ `grep -i "pam_tally2.so" $SYSAUTHAC | grep -i "deny" | wc -l` -eq 0 ]
			then
				echo "★ 계정 잠금 임계값 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "^auth" $SYSAUTHAC >> $RESULT_FILE 2>&1 
				echo [3-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-3]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ 계정 잠금 임계값 설정이 적용되어 있음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				grep -i "^auth" $SYSAUTHAC >> $RESULT_FILE 2>&1 
				echo [3-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1			
				echo [U-3]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-4]패스워드 파일 보호
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-4]패스워드 파일 보호  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [4-START] >> $RESULT_FILE 2>&1
if [ -f /etc/shadow ]; then
    echo "/etc/shadow 파일이 존재합니다." >> $RESULT_FILE 2>&1
    echo [4-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1			
	echo [U-4]Result : GOOD >> $RESULT_FILE 2>&1
else
    passwd_field=$(head -1 /etc/passwd | cut -d: -f2)    
    if [ "$passwd_field" == "x" ]; then
	    echo "★ 패스워드 /etc/passwd 파일에 저장하지 않고 별도의 파일에 저장함" >> $RESULT_FILE 2>&1
		echo [4-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1			
		echo [U-4]Result : GOOD >> $RESULT_FILE 2>&1
    else
		echo "★ 패스워드 /etc/passwd 파일에 저장함" >> $RESULT_FILE 2>&1
        echo [4-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-4]Result : VULNERABLE >> $RESULT_FILE 2>&1
    fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-5]root 홈, 패스 디렉터리 권한 및 패스 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-5]root 홈, 패스 디렉터리 권한 및 패스 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [5-START] >> $RESULT_FILE 2>&1
if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]
	then
		echo "★ PATH 환경변수에 '.'이 맨 앞 또는 중간에 위치하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $PATH >> $RESULT_FILE 2>&1
		echo [5-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-5]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ PATH 환경변수에 '.'이 맨 앞 또는 중간에 위치함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $PATH >> $RESULT_FILE 2>&1
		echo [5-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-5]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-6]파일 및 디렉터리 소유자 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-6]파일 및 디렉터리 소유자 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
	ls -l /home | awk '{print $3}' | grep "^[0-9]" > tmp_6_1.txt
	for i in `cat tmp_6_1.txt`; do ls -l /home | grep -w $i >> tmp_6_2.txt; done
	if [ -f tmp_6_2.txt ]
	then
		echo "★ /home 디렉토리에 소유자가 존재하지 않는 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_6_2.txt | tail -50 >> $RESULT_FILE 2>&1
		echo 총 갯수 : >> $RESULT_FILE 2>&1
		cat tmp_6_2.txt | wc -l >> $RESULT_FILE 2>&1
		echo [6-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-6]Result : VULNERABLE >> $RESULT_FILE 2>&1		
	else
		echo "★ /home 디렉토리에 소유자가 존재하지 않는 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [6-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-6]Result : GOOD >> $RESULT_FILE 2>&1
	fi
	rm -rf tmp_6_1.txt
	rm -rf tmp_6_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-7]/etc/passwd 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-7]/etc/passwd 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [7-START] >> $RESULT_FILE 2>&1
file="/etc/passwd"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 644 ]; then
		echo "★ /etc/passwd 파일의 소유자 및 퍼미션(644)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [7-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-7]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
		echo "★ /etc/passwd 파일의 소유자 및 퍼미션(644)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [7-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-7]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/passwd 파일을 찾을 수 없음" >> "$RESULT_FILE" 2>&1
    echo [7-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-7]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo [U-8]/etc/shadow 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-8]/etc/shadow 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [8-START] >> $RESULT_FILE 2>&1
file="/etc/shadow"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 400 ]; then
		echo "★ /etc/shadow 파일의 소유자 및 퍼미션(400)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [8-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-8]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
		echo "★ /etc/shadow 파일의 소유자 및 퍼미션(400)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [8-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-8]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/shadow file not found" >> "$RESULT_FILE" 2>&1
    echo [8-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-8]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-9]/etc/hosts 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-9]/etc/hosts 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [9-START] >> $RESULT_FILE 2>&1
file="/etc/hosts"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 600 ]; then
        echo "★ /etc/hosts 파일의 소유자 및 퍼미션(600)이하로 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [9-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-9]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
        echo "★ /etc/hosts 파일의 소유자 및 퍼미션(600)이하로 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [9-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-9]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/hosts 파일을 찾을 수 없음" >> "$RESULT_FILE" 2>&1
    echo [9-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-9]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

### 보통 centos 7에서는 /etc/systemd/system 파일에서 해당 기능을 수행한다고함 -> 우선 항목에 대한 검토만 진행함
echo [U-10]/etc/xinetd.conf 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-10]/etc/xinetd.conf 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [10-START] >> $RESULT_FILE 2>&1
file1="/etc/xinetd.conf"
file2="/etc/inetd.conf"
# file3="/etc/systemd/system"
if [ -f "$file1" ]
	then
		owner="$(stat -c %U "$file1")"
		permissions="$(stat -c %a "$file1")"
		if [ "$owner" = "root" ] && [ "$permissions" -eq 600 ]
			then
				echo "★ /etc/xinetd.conf 파일의 소유자 및 퍼미션(600)으로 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
				echo "[현황]" >> "$RESULT_FILE" 2>&1
				ls -alL "$file1" >> "$RESULT_FILE" 2>&1
				echo [10-END] >> "$RESULT_FILE" 2>&1
				echo >> "$RESULT_FILE" 2>&1
				echo "[U-10]Result : GOOD" >> "$RESULT_FILE" 2>&1
			else
				echo "★ /etc/xinetd.conf 파일의 소유자 및 퍼미션(600)으로 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
				echo "[현황]" >> "$RESULT_FILE" 2>&1
				ls -alL "$file1" >> "$RESULT_FILE" 2>&1
				echo [10-END] >> "$RESULT_FILE" 2>&1
				echo >> "$RESULT_FILE" 2>&1
				echo "[U-10]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
		fi
	else
		if [ -f "$file2" ]
			then
				owner="$(stat -c %U "$file2")"
				permissions="$(stat -c %a "$file2")"
				if [ "$owner" = "root" ] && [ "$permissions" -eq 600 ]
					then
						echo "★ /etc/inetd.conf 파일의 소유자 및 퍼미션(600)으로 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
						echo "[현황]" >> "$RESULT_FILE" 2>&1
						ls -alL "$file2" >> "$RESULT_FILE" 2>&1
						echo [10-END] >> "$RESULT_FILE" 2>&1
						echo >> "$RESULT_FILE" 2>&1
						echo "[U-10]Result : GOOD" >> "$RESULT_FILE" 2>&1
					else
						echo "★ /etc/inetd.conf 파일의 소유자 및 퍼미션(600)으로 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
						echo "[현황]" >> "$RESULT_FILE" 2>&1
						ls -alL "$file2" >> "$RESULT_FILE" 2>&1
						echo [10-END] >> "$RESULT_FILE" 2>&1
						echo >> "$RESULT_FILE" 2>&1
						echo "[U-10]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
				fi			
					else
						echo "★ /etc/inetd.conf 파일 또는 /etc/inetd.d 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
						echo [10-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-10]Result : N/A >> $RESULT_FILE 2>&1 
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-11]/etc/rsyslog.conf 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-11]/etc/rsyslog.conf 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [11-START] >> $RESULT_FILE 2>&1
file="/etc/rsyslog.conf"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 640 ]; then
		echo "★ /etc/rsyslog.conf 파일의 소유자 및 퍼미션(640)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [11-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-11]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
		echo "★ /etc/rsyslog.conf 파일의 소유자 및 퍼미션(640)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [11-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-11]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/rsyslog.conf file not found." >> "$RESULT_FILE" 2>&1
    echo [11-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-11]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-12]/etc/services 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-12]/etc/services 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [12-START] >> $RESULT_FILE 2>&1
file="/etc/services"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 644 ]; then
		echo "★ /etc/services 파일의 소유자 및 퍼미션(644)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [12-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-12]Result : GOOD" >> "$RESULT_FILE" 2>&1
    else
		echo "★ /etc/services 파일의 소유자 및 퍼미션(644)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
        echo "[현황]" >> "$RESULT_FILE" 2>&1
        ls -alL "$file" >> "$RESULT_FILE" 2>&1
        echo [12-END] >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo "[U-12]Result : VULNERABLE" >> "$RESULT_FILE" 2>&1
    fi
else
    echo "The /etc/services file is missing." >> "$RESULT_FILE" 2>&1
    echo [12-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-12]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-13]SUID, SGID, 설정 파일점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-13]SUID, SGID, 설정 파일점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [13-START] >> $RESULT_FILE 2>&1
CheckSuidSgid1=$(find / -user root -type f \( -perm -04000 -o -perm -02000 \) -exec ls -l {} \ >> CheckSuidSgid.txt 2>&1)
for i in /sbin/dump /sbin/restore /sbin/unix_chkpwd /usr/bin/at /usr/bin/lpq /usr/bin/lpq-lpd /usr/bin/lpr /usr/bin/lpr-lpd /usr/bin/lprm /usr/bin/lprm-lqp /usr/bin/newgrp /usr/sbin/lpc /usr/sbin/lpc-lpd /usr/sbin/traceroute
do
	cat CheckSuidSgid.txt | grep $i >> ResultSuidSgid.txt
done
CheckSuidSgid2=$(cat ResultSuidSgid.txt | wc -l )
if [ $CheckSuidSgid2 = 0 ]
	then
		echo "주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [13-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-13]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1 
		cat CheckSuidSgid.txt  >> $RESULT_FILE 2>&1 
		echo [13-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-13]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf CheckSuidSgid.txt
rm -rf ResultSuidSgid.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


# ### 추후 보완 필요, for 문에서 .profile / .bashrc 파일 점검 결과 각각 수행되어서, 결과 값이 2개로 나옴
echo [U-14]사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-14]사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [14-START] >> $RESULT_FILE 2>&1
if [ -f /etc/profile ]; then
    if [ $(stat -c %U /etc/profile) = "root" ] && [ $(stat -c %A /etc/profile) = "r--r-----" ]
		then
			echo "★ /etc/profile 파일의 소유자 및 퍼미션(g-w,o-w)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
			echo "[현황]" >> "$RESULT_FILE" 2>&1
			ls -al /etc/profile >> "$RESULT_FILE" 2>&1
			echo [14-END] >> "$RESULT_FILE" 2>&1
			echo >> "$RESULT_FILE" 2>&1
			echo [U-14]Result : GOOD >> "$RESULT_FILE" 2>&1
		else
			echo "★ /etc/profile 파일의 소유자 및 퍼미션(g-w,o-w)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> "$RESULT_FILE" 2>&1
			ls -al /etc/profile >> "$RESULT_FILE" 2>&1
			echo [14-END] >> "$RESULT_FILE" 2>&1
			echo >> "$RESULT_FILE" 2>&1
			echo [U-14]Result : VULNERABLE >> "$RESULT_FILE" 2>&1
    fi
else
    echo "★ /etc/profile file missing" >> "$RESULT_FILE" 2>&1
    echo [14-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo [U-14]Result : N/A >> "$RESULT_FILE" 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-15]world writable 파일 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-15]world writable 파일 점검 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [15-START] >> $RESULT_FILE 2>&1
	wwcheck=./U-15@@`hostname`@@$IP.txt
	echo >> $RESULT_FILE 2>&1
	echo "world write check.txt 파일을 점검해주세요" >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
	### 파일 소유자 외 쓰기 권한이 있는 파일 리스트 전체 출력합니다.
	echo "파일 소유자 외 쓰기 권한이 있는 파일 리스트 전체를 출력합니다." >> $wwcheck 2>&1
	find / -type f -perm -2 -exec ls -l {} \; >> $wwcheck 2>&1
	echo [15-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
	echo [U-15]Result : MANUAL >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-16]dev에 존재하지 않는 device 파일 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-16]dev에 존재하지 않는 device 파일 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [16-START] >> $RESULT_FILE 2>&1
find /dev -type f -exec ls -l {} \; > tmp_16.txt
if [ `cat tmp_16.txt | wc -l` -eq 0 ]
	then
		echo "★ /dev 디렉토리에 major, minor nubmer를 가지지 않는 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [16-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-16]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ /dev 디렉토리에 major, minor nubmer를 가지지 않는 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_16.txt | tail -50 >> $RESULT_FILE 2>&1
		echo 총 갯수 : >> $RESULT_FILE 2>&1
		cat tmp_16.txt >> wc -l $RESULT_FILE 2>&1
		echo [16-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-16]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
rm -rf tmp_16.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-17]$HOME/.rhosts, hosts.equiv 사용 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-17]$HOME/.rhosts, hosts.equiv 사용 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [17-START] >> $RESULT_FILE 2>&1
	ls -l /home/ | grep -v "+found" | sed -n '2,$p' | awk '{print $9}' > tmp_17_1.txt
	for i in `cat tmp_17_1.txt`; do ls -al /home/$i/.rhosts; done 2>/dev/null > tmp_17_2.txt
	if [ -f /etc/hosts.equiv ]; then ls -l /etc/hosts.equiv >> tmp_17_2.txt; else true; fi 
	if [ `cat tmp_17_2.txt | wc -l` -eq 0 ]
	then
		echo "★ .rhosts, hosts.equiv 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [17-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-17]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_17_2.txt | wc -l` -eq `cat tmp_17_2.txt | grep "^....------" | wc -l` ]
		then
			for i in `cat tmp_17_2.txt | awk '{print $9}'`; do cat $i; done >> tmp_17_3.txt
			if [ `cat tmp_17_3.txt | grep "\+" | wc -l` -eq 0 ] 
			then
				echo "★ .rhosts, hosts.equiv 파일의 퍼미션 및 설정이 적절하게 적용됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				for i in `cat tmp_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
				echo [17-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-17]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ .rhosts, hosts.equiv 파일의 설정이 적절하지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				for i in `cat tmp_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
				echo [17-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-17]Result : VULNERABLE >> $RESULT_FILE 2>&1
			fi
		else
			echo "★ .rhosts, hosts.equiv 파일의 퍼미션이 적절하지 않음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			for i in `cat tmp_17_2.txt | awk '{print $9}'`; do ls -l $i >> $RESULT_FILE 2>&1 && cat $i >> $RESULT_FILE 2>&1; done
			echo [17-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [SU-17]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	fi
	rm -rf tmp_17_1.txt
	rm -rf tmp_17_2.txt				
	rm -rf tmp_17_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-18]접속 IP 및 포트 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-18]접속 IP 및 포트 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [18-START] >> $RESULT_FILE 2>&1
### /etc/hosts.allow 파일에 ALL 설정이 되어 있지 않은지, .deny 파일에 설정이 추가 되어 있는지 확인
if [ `cat /etc/hosts.allow | grep -v "^#" | grep ALL | wc -l` -eq 0 ] && [`cat /etc/hosts.deny | grep -v "^#" | wc -l` -eq 1]
  then
	echo "hosts.allow ALL 설정이 존재 하지 않고 hosts.deny 옵션이 적용되어 있음" >> $RESULT_FILE 2>&1
	echo [18-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
    echo [U-18]Result : GOOD >> $RESULT_FILE 2>&1
 else
	echo "hosts.allow 또는 hosts.deny 파일 점검 필요" >> $RESULT_FILE 2>&1
	echo "[현황]" >> $RESULT_FILE 2>&1
	echo "etc/hosts.allow" >> $RESULT_FILE 2>&1
	cat /etc/hosts.allow | grep -v "^#" >> $RESULT_FILE 2>&1
	echo "etc/hosts.deny" >> $RESULT_FILE 2>&1
	cat /etc/hosts.deny | grep -v "^#" >> $RESULT_FILE 2>&1
	echo [18-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
    echo [U-18]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-19]Finger 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-19]Finger 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [19-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "finger" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Finger 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [19-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-19]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ Finger 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep -i "finger" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [19-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-19]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-20]Anonymous FTP 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-20]Anonymous FTP 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [20-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [20-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "vsftpd.conf" -exec cat {} \; > vsftpdcheck.txt
		if [ `cat vsftpdcheck.txt | wc -l` -eq 0 ]
			then
				if [ `cat /etc/passwd | egrep -w "ftp|anonymous" | wc -l` -eq 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, ftp 또는 anonymous 계정이 존재하지 않음 " >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, ftp 또는 anonymous 계정이 존재함 " >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat /etc/passwd | egrep -w "ftp|anonymous" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				if [ `cat vsftpdcheck.txt | grep "anonymous_enable" | grep -v "#" | grep -i -v "no$" | wc -l` -eq 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, Anonymous 접속이 차단됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat vsftpdcheck.txt | grep "anonymous_enable" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, Anonymous 접속이 허용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":21 " | grep -i "LISTEN" >> $RESULT_FILE 2>&1
						cat vsftpdcheck.txt | grep "anonymous_enable" >> $RESULT_FILE 2>&1
						echo [20-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-20]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi	
fi
rm -rf vsftpdcheck.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-21]r 계열 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-21]r 계열 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [21-START] >> $RESULT_FILE 2>&1
# 파일 생성
find / -name "rsh" -o -name "rexec" -o -name "rlogin" > tmp_21_1.txt
service --status-all > tmp_21_2.txt
if [ ! -s "tmp_21_1.txt" ]
	then
		echo "★ r 계열 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [21-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-21]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if grep -q "[ + ] rsh" tmp_21_2.txt || grep -q "[ + ] rlogin" tmp_21_2.txt || grep -q "[ + ] rexec" tmp_21_2.txt
			then
				echo "★ r 계열 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_21_2.txt >> $RESULT_FILE 2>&1
				echo [21-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-21]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ r 계열 서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_21_1.txt >> $RESULT_FILE 2>&1
				echo [21-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-21]Result : GOOD >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_21_1.txt
rm -rf tmp_21_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-22]crond 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-22]crond 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [22-START] >> $RESULT_FILE 2>&1
# find /etc/cron* -type d 명령어 결과 값을 변수에 저장하면 어떨까?
cron_dirs=(
	"etc/crontab"
    "/etc/cron.d"
    "/etc/cron.hourly"
	"/etc/cron.daily"
    "/etc/cron.weekly"
	"/etc/cron.monthly"
	"/etc/cron.allow"
	"/etc/cron.deny"
)
for cron_dir in "${cron_dirs[@]}"; do
    if [ -d "$cron_dir" ]; then
        owner=$(stat -c %U "$cron_dir")
        permissions=$(stat -c %a "$cron_dir")

        if [ "$owner" = "root" ] && [ "$permissions" -le 640 ]; then
            echo "파일의 소유자 및 퍼미션(640)이하로 적절하게 설정됨" >> "$RESULT_FILE" 2>&1
			echo [22-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-22]Result : GOOD >> $RESULT_FILE 2>&1
        else
            echo "파일의 소유자 또는 퍼미션(640) 이하로의 설정이 $cron_dir 적절하게 설정되지 않음" >> "$RESULT_FILE" 2>&1
            echo "[현황]" >> "$RESULT_FILE" 2>&1
            ls -ld "$cron_dir" >> "$RESULT_FILE" 2>&1
            echo >> "$RESULT_FILE" 2>&1
           	echo [22-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-22]Result : VULNERABLE >> $RESULT_FILE 2>&1
        fi
    else
        echo "$cron_dir not found." >> "$RESULT_FILE" 2>&1
        echo >> "$RESULT_FILE" 2>&1
        echo [23-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-23]Result : N/A >> $RESULT_FILE 2>&1
    fi
done
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-23]DoS 공격에 취약한 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-23]DoS 공격에 취약한 서비스 비활성화 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [23-START] >> $RESULT_FILE 2>&1
# 서비스 실행 여부 저장
echo echo.service status >> tmp_23_1.txt 2>&1
systemctl is-active echo.service >> tmp_23_1.txt 2>&1
echo discard.service status >> tmp_23_1.txt 2>&1
systemctl is-active discard.service >> tmp_23_1.txt 2>&1
echo daytime.service status >> tmp_23_1.txt 2>&1
systemctl is-active daytime.service >> tmp_23_1.txt 2>&1
echo chargen.service status >> tmp_23_1.txt 2>&1
systemctl is-active chargen.service >> tmp_23_1.txt 2>&1


if [ `find /etc/systemd/system -name "echo" -o -name "discard" -o -name "daytime" -o -name "chargen" | wc -l` -eq 0 ]
	then
		echo "★ DoS 공격에 취약한 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [23-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-23]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_23_1.txt | grep "active" | wc -l` -eq 0 ]
			then
				echo "★ DoS 공격에 취약한 서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_23_1.txt >> $RESULT_FILE 2>&1
				echo [40-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-40]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ DoS 공격에 취약한 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_23_1.txt | grep "active" >> $RESULT_FILE 2>&1
				echo [40-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-40]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_23_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-24]NFS 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-24]NFS 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [24-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "NFS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [24-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-24]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "NFS 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [24-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-24]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-25]NFS 접근 통제
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-25]NFS 접근 통제  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [25-START] >> $RESULT_FILE 2>&1
	if [ `ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "NFS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [25-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-25]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ -f /etc/exports ]
		then
			if [ `cat /etc/exports | grep -i "everyone" | grep -v "^ *#" | wc -l` -eq 0 ]
			then
				echo "NFS 서비스가 실행중이나 everyone 공유가 존재하지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" >> $RESULT_FILE 2>&1
				cat /etc/exports >> $RESULT_FILE 2>&1 
				echo [25-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-25]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "NFS 서비스가 실행중이고 everyone 공유가 존재함" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" >> $RESULT_FILE 2>&1
				cat /etc/exports >> $RESULT_FILE 2>&1 
				echo [25-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-25]Result : VULNERABLE >> $RESULT_FILE 2>&1
			fi
		else
			echo "NFS 서비스가 실행중이나 /etc/exports 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			ps -ef | egrep "nfsd|statd|mountd" | grep -v "grep" >> $RESULT_FILE 2>&1
			echo [25-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-25]Result : MANUAL >> $RESULT_FILE 2>&1
		fi
	fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-26]automountd 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-26]automountd 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [26-START] >> $RESULT_FILE 2>&1

if [ `ps -ef | egrep "autofs" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "autofs 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [26-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-26]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "autofs 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep -i "autofs" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [26-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-26]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-27]RPC 서비스 확인
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-27]RPC 서비스 확인  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [27-START] >> $RESULT_FILE 2>&1
find /etc/systemd/system -name "rpc.cmsd" -o -name "rpc.ttdbserverd" -o -name "sadmind" -o -name "rusersd" -o -name "walld" -o -name "sprayd" -o -name "rstatd" -o -name "rpc.nisd" -o -name "rpc.pcnfsd" -o -name "rpc.statd" -o -name "rpc.ypupdated" -o -name "rpc.rquotad" -o -name "kcms_server" -o -name "cachefsd"  -o -name "rexd" >> tmp_27_1.txt 2>&1
if [ `cat tmp_27_1.txt | wc -l` -eq 0 ]
	then
		echo "★ DoS 공격에 취약한 서비스가 설치되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [27-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-27]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_27_1.txt | grep "active" | wc -l` -eq 0 ]
			then
				echo "RPC서비스가 설치되어 있으나 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_27_1.txt >> $RESULT_FILE 2>&1
				echo [27-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-27]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ DoS 공격에 취약한 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_27_1.txt | grep "active" >> $RESULT_FILE 2>&1
				echo [27-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-27]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_27_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-28]NIS, NIS+ 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-28]NIS, NIS+ 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [28-START] >> $RESULT_FILE 2>&1
SERVICE_NIS="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nisd"
	if [ `ps -ef | egrep $SERVICE_NIS | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ NIS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [28-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-28]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ NIS 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | egrep $SERVICE_NIS | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [28-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-28]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-29]tftp, talk 서비스 비활성화
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-29]tftp, talk 서비스 비활성화  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [29-START] >> $RESULT_FILE 2>&1
		if [ `systemctl -t service -a --state running | egrep "tftp|talk" | egrep "3:on|:.on|3:활성" | wc -l` -eq 0 ]
			then
				echo "★ tftp, talk 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
				echo [29-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-29]Result : GOOD >> $RESULT_FILE 2>&1		
			else
				echo "★ tftp, talk 서비스가 실행중임" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				systemctl -t service -a --state running | egrep "tftp|talk" >> $RESULT_FILE 2>&1
				echo [29-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-29]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-30]Sendmail 버전 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-30]Sendmail 버전 점검 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [30-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [30-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-30]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [30-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-30]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > sendmailcheck.txt \;			
				if [ `cat sendmailcheck | grep -v '^ *#' | grep DZ | egrep "8.15" | wc -l` -eq 0 ]
					then
						echo "취약한 버전의 Sendmail 서비스가 실행중임" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						echo "Sendmail 버전 : `cat sendmailcheck.txt | grep -v '^ *#' | grep DZ`" >> $RESULT_FILE 2>&1
						echo [30-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-30]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ 취약하지 않은 버전의 Sendmail 서비스가 실행중임" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						echo "Sendmail 버전 : `cat sendmailcheck.txt | grep -v '^ *#' | grep DZ`" >> $RESULT_FILE 2>&1
						echo [30-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-30]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf sendmailcheck.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-31]스팸 메일 릴레이 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-31]스팸 메일 릴레이 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [31-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [31-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-31]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [31-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-31]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > sendmailRckeck.txt \;
				if [ `cat sendmailRckeck.txt | grep -v "^ *#" | grep "R$\*" | grep -i "Relaying denied" | wc -l ` -gt 0 ]
					then
						echo "스팸 메일 릴레이 제한 설정이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat sendmailRckeck.txt | grep -v "^ *#" | grep "R$\*" | grep -i "Relaying denied" >> $RESULT_FILE 2>&1
						echo [31-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-31]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "스팸 메일 릴레이 제한 설정이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat sendmailRckeck.txt | grep "R$\*" | grep -i "Relaying denied" >> $RESULT_FILE 2>&1
						echo [31-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-31]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf sendmailRckeck.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-32]일반사용자의 Sendmail 실행 방지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-32]일반사용자의 Sendmail 실행 방지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [32-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [32-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-32]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
				echo [32-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-32]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > sendmailNcheck.txt \;
				if [ `cat sendmailNcheck.txt | grep -i "O PrivacyOptions" | grep -i "restrictqrun" | grep -v "#" | wc -l` -gt 0 ]
					then
						echo "★ 일반사용자의 Sendmail 실행 방지 설정이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat sendmailNcheck.txt | grep -i "O PrivacyOptions" | grep -i "restrictqrun" >> $RESULT_FILE 2>&1
						echo [32-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-32]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 일반사용자의 Sendmail 실행 방지 설정이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						ps -ef | grep sendmail | grep -v "grep" >> $RESULT_FILE 2>&1
						cat sendmailNcheck.txt | grep -i "O PrivacyOptions" >> $RESULT_FILE 2>&1
						echo [32-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-32]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf sendmailNcheck.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


### 운영체제별 BIND DNS 서버 바이너리 실행 파일 경로가 다르기에 확인 필요함
echo [U-33]DNS 보안 버전 패치
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-33]DNS 보안 버전 패치  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [33-START] >> $RESULT_FILE 2>&1
if [ `netstat -anp | awk '{print $4}' | grep ":53$" | wc -l` -eq 0 ]
	then
		echo "★ DNS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [33-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-33]Result : GOOD >> $RESULT_FILE 2>&1
	else
		named -v > /dev/null
		if [ $? -eq 0 ]
			then
				echo "★ DNS 서비스가 실행중이며 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				named -v >> $RESULT_FILE 2>&1
				echo [33-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				if [ -f /usr/sbin/named ]
					then
						echo "★ DNS 서비스가 실행중임 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						/usr/sbin/named -v >> $RESULT_FILE 2>&1
						echo [33-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
					else
						if [ -f /usr/sbin/named9 ]
							then
								echo "★ DNS 서비스가 실행중임 버전을 확인하여 결과 분석" >> $RESULT_FILE 2>&1
								echo "[현황]" >> $RESULT_FILE 2>&1
								/usr/sbin/named9 -v >> $RESULT_FILE 2>&1
								echo [33-END] >> $RESULT_FILE 2>&1
								echo >> $RESULT_FILE 2>&1
								echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
							else
								echo "★ DNS 서비스가 실행중이나 실행 데몬을 찾을 수 없음" >> $RESULT_FILE 2>&1
								echo [33-END] >> $RESULT_FILE 2>&1
								echo >> $RESULT_FILE 2>&1
								echo [U-33]Result : MANUAL >> $RESULT_FILE 2>&1
						fi
				fi
		fi
fi	
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

### nmd
echo [U-34] DNS Zone Transfer 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-34] DNS Zone Transfer 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [34-START] >> $RESULT_FILE 2>&1
if [ `netstat -anp | awk '{print $4}' | grep ":53$" | wc -l` -eq 0 ]
	then
		echo "★ DNS 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [34-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-34]Result : GOOD >> $RESULT_FILE 2>&1
	else
		cat /etc/named.conf /etc/named.rfc1912.zones /etc/named.boot > dnstranstercheck.txt 2> /dev/null
		if [ `cat dnstranstercheck.txt | wc -l` -eq 0 ]
			then
				echo "★ DNS 서비스가 실행중이나 설정파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				netstat -anp | grep ":53 " >> $RESULT_FILE 2>&1
				echo [34-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-34]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				if [ `cat dnstranstercheck.txt | grep "allow-transfer" | grep -v "#" | wc -l` -eq 0 ]
					then
						echo "★ DNS 서비스가 실행중이며 DNS ZoneTransfer 설정이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":53 " >> $RESULT_FILE 2>&1						
						echo [34-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-34]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ DNS 서비스가 실행중이며 DNS ZoneTransfer 설정이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						netstat -anp | grep ":53 " >> $RESULT_FILE 2>&1
						cat dnstranstercheck.txt | grep "allow-transfer" | grep -v "#" >> $RESULT_FILE 2>&1
						echo [34-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-34]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf dnstranstercheck.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-35]웹서비스 디렉토리 리스팅 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-35]웹서비스 디렉토리 리스팅 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [35-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/httpd/conf/httpd.conf | grep -v '^ *#' | grep "Options Indexes FollowSymLinks" | wc -l` -eq 0 ]
	then
		echo "Indexs 옵션이 설정 되어 있지 않음" >> $RESULT_FILE 2>&1
		echo [35-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-35]Result : GOOD >> $RESULT_FILE 2>&1
	else

		echo "Index 옵션이 설정 되어 있음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/httpd/conf/httpd.conf | grep "Options Indexes FollowSymLinks" >> $RESULT_FILE 2>&1
		echo [35-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-35]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-36]웹서비스 웹 프로세스 권한 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-36]웹서비스 웹 프로세스 권한 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [36-START] >> $RESULT_FILE 2>&1
if [ -f /etc/httpd/conf/httpd.conf ]
	then
		if [ `cat /etc/httpd/conf/httpd.conf | grep -v '^ *#' | grep "User root" | wc -l` -gt 0 ] && [ `cat /etc/httpd/conf/httpd.conf | grep -v '^ *#' | grep "Group root" | wc -l` -gt 0 ]
			then
				echo "User & Group 부분에 root가 아닌 별도 계정으로 변경 되어 있지 않음" >> $RESULT_FILE 2>&1
				echo [36-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-36]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "User & Group 부분에 root가 아닌 별도 계정으로 변경됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat /etc/httpd/conf/httpd.conf | grep -v '^ *#' | grep "Options Indexes FollowSymLinks" >> $RESULT_FILE 2>&1
				echo [36-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-36]Result : VULNERABL >> $RESULT_FILE 2>&1
		fi
			else
				echo " /etc/httpd/conf/httpd.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [36-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-36]Result : N/A >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-37]웹서비스 상위 디렉토리 접근 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-37]웹서비스 상위 디렉토리 접근 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [37-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/httpd/conf/httpd.conf | grep -v '^ *#' | grep "AllowOverride *" | wc -l` -eq 0 ]
	then
		echo "상위 디렉터리에 이동제한을 설정함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/httpd/conf/httpd.conf | grep -v '^ *#' | grep "AllowOverride *" >> $RESULT_FILE 2>&1
		echo [37-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-37]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "상위 디렉터리에 이동제한을 설정하지 않음" >> $RESULT_FILE 2>&1
		echo [37-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-37]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-38]웹서비스 불필요한 파일 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-38]웹서비스 불필요한 파일 제거 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [38-START] >> $RESULT_FILE 2>&1
if [ `find /etc/httpd/conf/httpd.conf -type f -name "manual" | wc -l` -eq 0 ]
	then
		echo "불필요한 파일 및 디렉터리 존재 하지 않음" >> $RESULT_FILE 2>&1
		echo [38-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-38]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "불필요한 파일 및 디렉터리 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		find /etc/httpd/conf/httpd.conf -type f -name "manual"
		echo [38-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-38]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-39]웹서비스 링크 사용금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-39]웹서비스 링크 사용금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [39-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/httpd/conf/httpd.conf | grep -v '^ *#' | grep "Options Indexes FollowSymLinks" | wc -l` -gt 0 ]
	then
		echo "상위 디렉터리에 이동제한을 설정하지 않음" >> $RESULT_FILE 2>&1
		echo [38-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-38]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "상위 디렉터리에 이동제한을 설정함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/httpd/conf/httpd.conf | grep -v '^ *#' | grep "Options Indexes FollowSymLinks"
		echo [39-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-39]Result : VULNERABL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-40]웹서비스 파일 업로드 및 다운로드 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-40]웹서비스 파일 업로드 및 다운로드 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [40-START] >> $RESULT_FILE 2>&1
EXPECTED_LIMIT=5000000

if [ -f "$APACHE_CONF" ]; then
    limit_value=$(grep -E "^LimitRequestBody\s+" "$APACHE_CONF" | awk '{print $2}')
    if [ -n "$limit_value" ]; then
        if [ "$limit_value" -le "$MAX_LIMIT" ]; then
            echo "LimitRequestBody 적정 파일 사이즈 용량 설정됨 (5MB 이하)" >> $RESULT_FILE 2>&1
			echo [40-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-40]Result : GOOD >> $RESULT_FILE 2>&1
        else
            echo "LimitRequestBody 적정 파일 사이즈 용량 설정이 초과됨 (5MB 초과)" >> $RESULT_FILE 2>&1
			echo [40-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-40]Result : VULNERABLE >> $RESULT_FILE 2>&1
        fi
    else
        	echo "LimitRequestBody 용량 설정이 없습니다." >> $RESULT_FILE 2>&1
			echo [40-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-40]Result : VULNERABLE >> $RESULT_FILE 2>&1
    fi
else
    echo "사용중인 웹 서비스가 없습니다." >> $RESULT_FILE 2>&1
	echo [40-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
	echo [U-40]Result : N/A >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-41]웹서비스 영역의 분리
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-41]웹서비스 영역의 분리  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [41-START] >> $RESULT_FILE 2>&1
if [ `echo $HTTP_DOC_ROOT | egrep -w "/usr/local/apache/htdocs|/usr/local/apache2/htdocs|/var/www/html" | wc -l` -eq 0 ]
	then
		echo "★ DocumentRoot로 기본경로를 사용하지 않음" >> $RESULT_FILE 2>&1
		echo [41-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-41]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ DocumentRoot로 기본경로를 사용함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo $HTTP_DOC_ROOT >> $RESULT_FILE 2>&1
		echo [41-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-41]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-42]최신 보안패치 및 벤더 권고사항 적용
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-42]최신 보안패치 및 벤더 권고사항 적용   >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [42-START] >> $RESULT_FILE 2>&1
		echo "★ 아래 현황을 기반으로 수동분석" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		echo "1. openssl version" >> $RESULT_FILE 2>&1
		openssl version >> $RESULT_FILE 2>&1
		echo "2. bash shell version" >> $RESULT_FILE 2>&1
		bash --version | grep "bash" >> $RESULT_FILE 2>&1
		rpm -qa | grep bash >> $RESULT_FILE 2>&1
		echo "2.1 bash 취약점 테스트(벤더사 제공)" >> $RESULT_FILE 2>&1
		env x='() { :;}; echo vulnerable' bash -c "echo this is a test" >> $RESULT_FILE 2>&1
		echo [42-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-42]RESULT : MANUAL >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


### utmp, wtmp ,btmp 등의 로그를 확인하여 마지막 로그인 시간, 접속 IP, 실패한 이력 등을 확인하여 계정 탈취 공격 및 시스템 해킹 여부를 검토
### sulog를 확인하여 허용된 계정 외에 su 명령어를 통해 권한상승을 시도하였는지 검토
### xferlog를 확인하여 비인가자의 ftp 접근 여부를 검토
### 로그 분석에 대한 결과 보고서 작성 및 분석 결과보고서 체계 수립 되어 있습니까?
echo [U-43]로그의 정기적 검토 및 보고
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-43]로그의 정기적 검토 및 보고  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [43-START] >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo "★ 인터뷰 점검 항목" >> $RESULT_FILE 2>&1
echo [43-END] >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo [U-43]Result : MANUAL >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-44]root 이외의 UID가 ‘0’ 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-44]root 이외의 UID가 ‘0’ 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [44-START] >> $RESULT_FILE 2>&1
if [ `awk -F: '$3==0 {print $0}' /etc/passwd | grep -v 'root' | wc -l` -eq 0 ]
	then
		echo "★ root 이외의 UID가 '0'인 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F: '$3==0 {print $0}' /etc/passwd >> $RESULT_FILE 2>&1
		echo [44-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-44]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ root 이외의 UID가 '0'인 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F: '$3==0 {print $0}' /etc/passwd >> $RESULT_FILE 2>&1
		echo [44-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-44]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-45]root 계정 su 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-45]root 계정 su 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [45-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/group | grep wheel | wc -l` -eq 0 ]
	then
		echo "wheel 그룹이 없습니다." >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [45-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-45]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		echo "wheel 그룹이 존재합니다. 추가된 사용자에 대한 검토 메뉴얼 필요." >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/group | grep wheel  >> $RESULT_FILE 2>&1
		echo [45-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-45]Result : MANUAL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-46]패스워드 최소 길이 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-46]패스워드 최소 길이 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [46-START] >> $RESULT_FILE 2>&1
if [ -f /etc/login.defs ]; then
    pass_min_len=$(awk '/^PASS_MIN_LEN/ {print $2}' /etc/login.defs)
        if [ "$pass_min_len" -ge 8 ]; then
        echo "패스워드 최소 길이를 준수하고 있음" >> $RESULT_FILE 2>&1
		echo [46-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-46]Result : GOOD >> $RESULT_FILE 2>&1
    else
        echo "패스워드 최소 길이를 준수하고 있지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/login.defs | grep -v '^ *#' | grep "PASS_MIN_LEN" >> $RESULT_FILE 2>&1
		echo [46-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-46]Result : VULNERABLE >> $RESULT_FILE 2>&1
    fi
else
    echo "/etc/login.defs 파일을 찾을 수 없음."
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-47]패스워드 최대 사용기간 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-47]패스워드 최대 사용기간 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [47-START] >> $RESULT_FILE 2>&1
MAX_PASSWORD_AGE=90
MAX_PASSWORD_AGE_CONFIG=$(cat /etc/login.defs | grep -v '^ *#' | grep "PASS_MAX_DAYS" | awk '{print $2}')
if [ -z "$MAX_PASSWORD_AGE_CONFIG" ]
	then
		echo "패스워드 최대 사용기간 설정이 되어 있지 않음"
		echo [47-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-47]Result : VULNERABLE >> $RESULT_FILE 2>&1
		exit 1
fi
if [ "$MAX_PASSWORD_AGE_CONFIG" -le "$MAX_PASSWORD_AGE" ]
	then
    	echo "패스워드 최대 사용기간을 준수하고 있음" >> $RESULT_FILE 2>&1
		echo [47-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-47]Result : GOOD >> $RESULT_FILE 2>&1
else
		echo "패스워드 최대 사용기간을 준수하고 있지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/login.defs | grep "PASS_MAX_DAYS" >> $RESULT_FILE 2>&1
		echo [47-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-47]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-48]패스워드 최소 사용기간 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-48]패스워드 최소 사용기간 설정 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [48-START] >> $RESULT_FILE 2>&1
if [ -f /etc/login.defs ]
	then
		if [ `grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" | wc -l` -eq 0 ]
			then
				echo "★ 패스워드 최소 사용 기간 설정이 적용되어 있지 않음" >> $RESULT_FILE 2>&1
				echo [9-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-9]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				if [ `grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" | awk '{print $2}'` -eq 1 ]
					then
						echo "★ 패스워드 최소 사용 기간 설정이 정책에 맞게 적용되어 있음" >> $RESULT_FILE 2>&1				
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo [9-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1	
						echo [U-9]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ 패스워드 최소 사용 기간 설정이 적용되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						grep "PASS_MIN_DAYS" /etc/login.defs | grep -v "#" >> $RESULT_FILE 2>&1
						echo [9-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-9]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi
	else
		echo "★ /etc/login.defs 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
		echo [9-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-9]Result : MANUAL >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-49]불필요한 계정 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-49]불필요한 계정 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [49-START] >> $RESULT_FILE 2>&1
touch check_49_3.txt
cat /etc/passwd | egrep -v 'false|nologin|null|halt|sync|shutdown|rpm|new' > check_49_1.txt
cat check_49_1.txt | awk -F: '{print $1}' > check_49_2.txt
for i in `cat check_49_2.txt`; do 
lastlog -u $i | grep $i >> check_49_3.txt; done
if [ `awk -F ":" '$3 >= 500 {print $0}' /etc/passwd | grep -v "nfsnobody" | wc -l` -eq 0 ]
	then
		echo "★ UID 500 이상 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "1. 계정별 최근 접속기록" >> $RESULT_FILE 2>&1
		cat check_49_3.txt >> $RESULT_FILE 2>&1
		echo [49-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-49]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ UID 500 이상 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		awk -F ":" '$3 >= 500 {print $0}' /etc/passwd | grep -v "nfsnobody" >> $RESULT_FILE 2>&1
		echo "1. 계정별 최근 접속기록" >> $RESULT_FILE 2>&1
		cat check_49_3.txt >> $RESULT_FILE 2>&1
		echo [49-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-49]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm check_49_1.txt
rm check_49_2.txt
rm check_49_3.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-50]관리자 그룹에 최소한의 계정 포함
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-50]관리자 그룹에 최소한의 계정 포함 >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [50-START] >> $RESULT_FILE 2>&1
grep "^root" /etc/group | awk -F ":" '{print $4}' | sed s/,/\\n/g | grep -v "^root$" | wc -w > check_50.txt
if [ `cat check_50.txt` -eq 0 ]
	then
		echo "★ 관리자 그룹에 root 이외의 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep "^root" /etc/group >> $RESULT_FILE 2>&1
		echo [50-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-50]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 관리자 그룹에 root 이외의 계정이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep "^root" /etc/group >> $RESULT_FILE 2>&1
		echo [50-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-50]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm -rf check_50.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-51]계정이 존재하지 않는 GID 금지 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-51]계정이 존재하지 않는 GID 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [51-START] >> $RESULT_FILE 2>&1
	awk -F : '$4 == null {print $0}' /etc/group | awk -F : '$3 >= 500 {print $0}' > check_group.txt
	awk -F : '{print $4}' /etc/passwd > check_passwd.txt
	for TGID in `cat check_passwd.txt`
	do
		grep -v ":$TGID:" check_group.txt > check_51.txt
		cat check_51.txt > check_group.txt
	done
	if [ `cat check_group.txt | wc -w` -eq 0 ]
	then
		echo "★ 계정이 존재하지 않는 500 이상 GID가 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [51-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-51]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 계정이 존재하지 않는 500 이상 GID가 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1 
		cat check_group.txt >> $RESULT_FILE 2>&1 
		echo [51-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-51]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
	rm -rf check_group.txt
	rm -rf check_passwd.txt
	rm -rf check_51.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-52]동일한 UID 금지
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-52]동일한 UID 금지  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [52-START] >> $RESULT_FILE 2>&1
awk -F : '{print $3}' /etc/passwd > tmp_passwd.txt
	if [ `cat tmp_passwd.txt | sort | uniq -d | wc -l` -eq 0 ]
		then
			echo "★ 중복된 UID가 존재하지 않음" >> $RESULT_FILE 2>&1
			echo [52-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-52]Result : GOOD >> $RESULT_FILE 2>&1
		else
			echo "★ 중복된 UID가 존재함" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1 
			DUID=`cat tmp_passwd.txt | sort | uniq -d`
			grep "x:$DUID:" /etc/passwd >> $RESULT_FILE 2>&1
			echo [52-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-52]Result : VULNERABLE >> $RESULT_FILE 2>&1
	fi
	rm -rf tmp_passwd.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-53]사용자 shell 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-53]사용자 shell 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [53-START] >> $RESULT_FILE 2>&1
if [ `cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" |  awk -F: '{print $7}'| egrep -v 'false|nologin|null|halt|sync|shutdown' | wc -l` -eq 0 ]
	then
		echo "★ 점검 대상 시스템 계정에 쉘이 부여되지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" >> $RESULT_FILE 2>&1
		echo [53-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-53]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 점검 대상 시스템 계정에 쉘이 부여됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" >> $RESULT_FILE 2>&1
		echo [53-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-53]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-54] Session Timeout 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-54] Session Timeout 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [54-START] >> $RESULT_FILE 2>&1
	if [ `echo $TMOUT | wc -w` -eq 0 ]
	then
		echo "★ 세션 타임아웃이 설정되지 않음" >> $RESULT_FILE 2>&1
		echo [54-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-54]Result : VULNERABLE >> $RESULT_FILE 2>&1
	else
		if [ `echo $TMOUT` -gt 600 ]
		then
			echo "★ 세션 타임아웃이 설정되어 있으나 정책에 맞지 않음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			echo "TMOUT : `echo $TMOUT`" >> $RESULT_FILE 2>&1
			echo [54-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-54]Result : VULNERABLE >> $RESULT_FILE 2>&1
		else
			echo "★ 세션 타임아웃이 정책에 맞게 설정됨" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			echo "TMOUT : `echo $TMOUT`" >> $RESULT_FILE 2>&1
			echo [54-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-54]Result : GOOD >> $RESULT_FILE 2>&1
		fi
	fi
	echo >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1


echo [U-55]hosts.lpd 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-55]hosts.lpd 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [55-START] >> $RESULT_FILE 2>&1
if [ -e /etc/hosts.lpd ]
	then
		if [ "$(stat -c %a /etc/hosts.lpd)" = "600" ] && [ "$(stat -c %U /etc/hosts.lpd)" = "root" ]
			then
				echo "hosts.lpd 파일의 소유자 및 퍼미션(600)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo [55-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-55]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "hosts.lpd 파일의 소유자 및 퍼미션(600)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/hosts.lpd >> $RESULT_FILE 2>&1
				echo [9-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-9]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
			else
				echo "/etc/hosts.lpd file missing" >> "$RESULT_FILE" 2>&1
				echo "[55-END]" >> "$RESULT_FILE" 2>&1
				echo >> "$RESULT_FILE" 2>&1
				echo "[U-54]Result : GOOD" >> "$RESULT_FILE" 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-56]UMASK 설정 관리
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-56]UMASK 설정 관리  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [56-START] >> $RESULT_FILE 2>&1
if [ `umask` -eq 0022 ]
	then
		echo "★ UMASK 값이 적절하게 설정됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1		
		echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
		echo [56-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-56]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `umask` -eq 0027 ]
			then
				echo "★ UMASK 값이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1		
				echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
				echo [56-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-56]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ UMASK 값이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1		
				echo "UMASK : `umask`" >> $RESULT_FILE 2>&1
				echo [56-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-56]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

### 홈 디렉터리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거되었다면 양호 
echo [U-57]홈디렉토리 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-57]홈디렉토리 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [57-START] >> $RESULT_FILE 2>&1
	ls -l /home/ | grep -v "+found" | sed -n '2,$p' > tmp_57_1.txt
	cat tmp_57_1.txt | grep -v "^........w." > tmp_57_2.txt
	if [ `cat tmp_57_1.txt | wc -l` -eq 0 ]
	then
		echo "★ 사용자 홈디렉토리가 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [57-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-57]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `diff tmp_57_1.txt tmp_57_2.txt | wc -l` -eq 0 ]
		then
			echo "★ 사용자 홈디렉토리의 퍼미션(o-w)이 적절하게 설정되어 있음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			cat tmp_57_1.txt >> $RESULT_FILE 2>&1
			echo [57-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-57]Result : GOOD >> $RESULT_FILE 2>&1
		else
			echo "★ 사용자 홈디렉토리의 퍼미션(o-w)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
			echo "[현황]" >> $RESULT_FILE 2>&1
			cat tmp_57_1.txt | grep "^........w." >> $RESULT_FILE 2>&1
			echo [57-END] >> $RESULT_FILE 2>&1
			echo >> $RESULT_FILE 2>&1
			echo [U-57]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	fi
	rm -rf tmp_57_1.txt
	rm -rf tmp_57_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-58]홈디렉토리로 지정한 디렉토리의 존재 관리
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-58]홈디렉토리로 지정한 디렉토리의 존재 관리  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [58-START] >> $RESULT_FILE 2>&1
		cat /etc/passwd | awk -F: '$3>=1000 {print $0}' > tmp_58_1.txt
		cat tmp_58_1.txt | awk -F: '{print $6}' > tmp_58_2.txt
		touch tmp_58_3.txt
		for i in `cat tmp_58_2.txt`
			do
				if [ -d $i ]; then echo $i >> tmp_58_3.txt; else true; fi
		done
		if [ `diff tmp_58_2.txt tmp_58_3.txt | wc -l` -eq 0 ]
			then
				echo "★ 홈디렉토리가 존재하지 않는 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
				echo [58-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-58]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 홈디렉토리가 존재하지 않는 계정이 존재함" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				diff tmp_58_2.txt tmp_58_3.txt | grep "<" | awk '{print $2}' > tmp_58_4.txt
				for i in `cat tmp_58_4.txt`
					do
						cat /etc/passwd | grep $i | awk -F: '{print "계정  "$1"  의 홈디렉토리  "$6"  가 존재하지 않음"}' >> $RESULT_FILE 2>&1
				done
				echo [58-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-58]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
		rm -rf tmp_58_1.txt
		rm -rf tmp_58_2.txt
		rm -rf tmp_58_3.txt
		rm -rf tmp_58_4.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-59]숨겨진 파일 및 디렉토리 검색 및 제거
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-59]숨겨진 파일 및 디렉토리 검색 및 제거  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [59-START] >> $RESULT_FILE 2>&1
	Var_59_1="font-unix|ICE-unix|ifstat|Test-unix|X11-unix|XIM-unix|esd-"
	find /tmp/ | grep "/\." | grep -Ev $Var_59_1 > tmp_59_1.txt
	if [ `cat tmp_59_1.txt | wc -l` -eq 0 ]
	then
		echo "★ /tmp 디렉토리에 숨김 속성 파일이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [59-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-59]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ /tmp 디렉토리에 숨김 속성 파일이 존재함" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_59_1.txt >> $RESULT_FILE 2>&1
		echo [59-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-59]Result : MANUAL >> $RESULT_FILE 2>&1
	fi
	rm -rf tmp_59_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-60]ssh 원격접속 허용
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-60]ssh 원격접속 허용  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [60-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "sshd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SSH 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [60-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-60]Result : MANUAL >> $RESULT_FILE 2>&1
	else
		echo "★ SSH 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "sshd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [60-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-60]Result : GOOD >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-61]ftp 서비스 확인
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-61]ftp 서비스 확인  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [61-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [61-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-61]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ FTP 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "ftpd" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [61-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-61]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-62]ftp 계정 shell 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-62]ftp 계정 shell 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [62-START] >> $RESULT_FILE 2>&1
cat /etc/passwd | grep -w "^ftp" > tmp_62_1.txt
if [ `cat tmp_62_1.txt | wc -l` -eq 0 ]
	then
		echo "★ /etc/passwd 파일에 'ftp' 계정이 존재하지 않음" >> $RESULT_FILE 2>&1
		echo [62-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-62]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `cat tmp_62_1.txt | awk -F: '{print $7}' | egrep -v "false|nologin|null|halt|sync|shutdown" | wc -l` -eq 0 ]
			then
				echo "★ 'ftp' 계정에 로그인 가능한 쉘이 부여되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_62_1.txt >> $RESULT_FILE 2>&1
				echo [62-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-62]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ 'ftp' 계정에 로그인 가능한 쉘이 부여됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				cat tmp_62_1.txt >> $RESULT_FILE 2>&1
				echo [62-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-62]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
rm -rf tmp_62_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-63]ftpusers 파일 소유자 및 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-63]ftpusers 파일 소유자 및 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [63-START] >> $RESULT_FILE 2>&1
if [ -e /etc/ftpusers ]
	then
		if [ "$(stat -c %a /etc/ftpusers)" = "640" ] && [ "$(stat -c %U /etc/ftpusers)" = "root" ]
			then
				echo "ftpusers 파일의 소유자 및 퍼미션(640)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo [63-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-63]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "ftpusers 파일의 소유자 및 퍼미션(640)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/ftpusers >> $RESULT_FILE 2>&1
				echo [63-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-63]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
			else
				echo "/etc/ftpusers file missing" >> "$RESULT_FILE" 2>&1
				echo "[63-END]" >> "$RESULT_FILE" 2>&1
				echo >> "$RESULT_FILE" 2>&1
				echo "[U-63]Result : GOOD" >> "$RESULT_FILE" 2>&1
	fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-64]ftpusers 파일 설정 FTP 서비스 root 계정 접근제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-64]ftpusers 파일 설정 FTP 서비스 root 계정 접근제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo [64-START] >> $RESULT_FILE 2>&1
if [ `ps -ef | grep -i "ftpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ FTP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [64-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [SU-64]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "ftpusers" -exec ls -l {} \; > tmp_64_1.txt
		if [ `cat tmp_64_1.txt | wc -l` -eq 0 ]
			then
				echo "★ ftpusers 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [64-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [SU-64]Result : GOOD >> $RESULT_FILE 2>&1
			else
				find /etc -name "ftpusers" -exec cat {} \; > tmp_64_2.txt
				if [ `cat tmp_64_2.txt | grep "root" | grep -v "^ *#" | wc -l` -gt 0 ]
					then
						echo "★ FTP 서비스가 실행중이며, ftpusers 파일에 root가 존재함" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_64_1.txt >> $RESULT_FILE 2>&1
						cat tmp_64_2.txt >> $RESULT_FILE 2>&1
						echo [64-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [SU-64]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ FTP 서비스가 실행중이며, ftpusers 파일에 root가 존재하지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_64_1.txt >> $RESULT_FILE 2>&1
						cat tmp_64_2.txt >> $RESULT_FILE 2>&1
						echo [64-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [SU-64]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
		fi	
fi		
rm -rf tmp_64_1.txt
rm -rf tmp_64_2.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


### 점검 방법 “/etc/at.allow”, “/etc/at.deny” 파일의 소유자 및 권한 확인
### 위에 제시한 파일의 소유자가 root가 아니거나 파일의 권한이  이하가 아닌 경우 취약
echo [U-65]at 서비스 권한 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-65]at 서비스 권한 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ -e /etc/at.allow ] && [-e /etc/at.deny]
	then
		if [ "$(stat -c %a /etc/at.allow)" >= "750" ] && ["$(stat -c %a /etc/at.deny)" >= "750" ] && [ "$(stat -c %U /etc/at.allow)" = "root"] && [ "$(stat -c %U /etc/at.allow)" = "root" ]
			then
				echo "at.allow 파일과 at.deny 파일의 소유자 및 퍼미션(750)이 적절하게 설정됨" >> $RESULT_FILE 2>&1
				echo [65-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-65]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "at.allow 파일 또는 at.deny 소유자 및 퍼미션(750)이 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				ls -alL /etc/at.allow >> $RESULT_FILE 2>&1
				ls -alL /etc/deny.allow >> $RESULT_FILE 2>&1
				echo [65-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-65]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
			else
				echo "/etc/at.allow 파일 또는 at.deny 파일이 없음" >> $RESULT_FILE 2>&1
				echo "[65-END]" >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-65]Result : GOOD >> $RESULT_FILE 2>&1
	fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-66]SNMP 서비스 구동 점검
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-66]SNMP 서비스 구동 점검  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "snmp" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SNMP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [66-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-66]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ SNMP 서비스가 실행중임" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ps -ef | grep "snmp" | grep -v "grep" >> $RESULT_FILE 2>&1
		echo [66-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-66]Result : VULNERABLE >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-67]SNMP 서비스 Community String의 복잡성 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-67]SNMP 서비스 Community String의 복잡성 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ `ps -ef | grep "snmpd" | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ SNMP 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [67-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-67]Result : GOOD >> $RESULT_FILE 2>&1
	else
		find /etc -name "snmpd.conf" -exec cat {} \; > tmp_67_1.txt
		if [ `cat tmp_67_1.txt | wc -l` -gt 0 ]
			then
				if [ `cat tmp_67_1.txt | grep "public" | grep -v "^ *#" | wc -l` -eq 0 ]
					then
						echo "★ SNMP Community String이 임의의 값으로 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_67_1.txt | grep -v "^ *#" >> $RESULT_FILE 2>&1
						echo [67-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-67]Result : GOOD >> $RESULT_FILE 2>&1
					else
						echo "★ SNMP Community String이 기본값으로 설정됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_67_1.txt | grep -v "^ *#" >> $RESULT_FILE 2>&1
						echo [67-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-67]Result : VULNERABLE >> $RESULT_FILE 2>&1
				fi
			else
				echo "★ SNMP 서비스가 실행중이나 설정파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [67-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-67]Result : MANUAL >> $RESULT_FILE 2>&1
		fi						
fi
rm -rf tmp_67_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-68]로그온 시 경고 메시지 제공
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-68]로그온 시 경고 메시지 제공  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ `cat /etc/issue.net | wc -l` -gt 2 ]
	then
		if [ `cat /etc/motd | wc -l` -gt 0 ]
			then
				echo "★ /etc/issue.net, /etc/motd 파일에 경고 메시지가 설정됨" >> $RESULT_FILE 2>&1
				echo "[현황]" >> $RESULT_FILE 2>&1
				echo "1) /etc/issue.net 파일 내용" >> $RESULT_FILE 2>&1
				cat /etc/issue.net >> $RESULT_FILE 2>&1
				echo "2) /etc/motd 파일 내용" >> $RESULT_FILE 2>&1
				cat /etc/motd >> $RESULT_FILE 2>&1
				echo [68-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-68]Result : GOOD >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/motd 파일에 경고 메시지가 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [68-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-68]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
	else
		if [ `cat /etc/motd | wc -l` -gt 0 ]
			then
				echo "★ /etc/issue.net 파일에 경고 메시지가 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [68-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-68]Result : VULNERABLE >> $RESULT_FILE 2>&1
			else
				echo "★ /etc/issue.net, /etc/motd 파일에 경고 메시지가 설정되지 않음" >> $RESULT_FILE 2>&1
				echo [68-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-68]Result : VULNERABLE >> $RESULT_FILE 2>&1
		fi
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-69]NFS 설정파일 접근권한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-69]NFS 설정파일 접근권한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
file="/etc/exports"
if [ -f "$file" ]; then
    owner="$(stat -c %U "$file")"
    permissions="$(stat -c %a "$file")"
    if [ "$owner" = "root" ] && [ "$permissions" -le 644 ]; then
		echo "★ /etc/exports 파일의 퍼미션(644)이하로 적절하게 설정됨" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ls -l /etc/exports >> $RESULT_FILE 2>&1
		echo [69-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-69]Result : GOOD >> $RESULT_FILE 2>&1
    else
		echo "★ /etc/exports 파일의 퍼미션(644)이하로 적절하게 설정되지 않음" >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		ls -l /etc/exports >> $RESULT_FILE 2>&1
		echo [69-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-69]Result : VULNERABLE >> $RESULT_FILE 2>&1
    fi
else
    echo "The /etc/exports 파일을 찾을 수 없음." >> "$RESULT_FILE" 2>&1
    echo [69-END] >> "$RESULT_FILE" 2>&1
    echo >> "$RESULT_FILE" 2>&1
    echo "[U-69]Result : N/A" >> "$RESULT_FILE" 2>&1 
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-70]expn, vrfy 명령어 제한
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-70]expn, vrfy 명령어 제한  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "★ Sendmail 서비스가 실행중이지 않음" >> $RESULT_FILE 2>&1
		echo [70-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-70]Result : GOOD >> $RESULT_FILE 2>&1
	else
		if [ `find /etc -name "sendmail.cf" | wc -l` -eq 0 ]
			then
				echo "★ Sendmail 서비스가 실행중이나 sendmail.cf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [70-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-70]Result : MANUAL >> $RESULT_FILE 2>&1
			else
				find /etc -name "sendmail.cf" -exec cat {} > tmp_70.txt \;			
				cat tmp_70.txt | grep -i "O PrivacyOptions" > tmp_70_1.txt
				if [ `cat tmp_70_1.txt | grep -v "^ *#" | grep "noexpn" | grep "novrfy" | wc -l` -eq 0 ]
					then
						echo "★ Sendmail 서비스가 실행중이며 sendmail.cf 파일에 noexpn, novrfy 옵션이 적용되지 않음" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_70_1.txt >> $RESULT_FILE 2>&1
						echo [70-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-70]Result : VULNERABLE >> $RESULT_FILE 2>&1
					else
						echo "★ Sendmail 서비스가 실행중이며 sendmail.cf 파일에 noexpn, novrfy 옵션이 적용됨" >> $RESULT_FILE 2>&1
						echo "[현황]" >> $RESULT_FILE 2>&1
						cat tmp_70_1.txt >> $RESULT_FILE 2>&1
						echo [70-END] >> $RESULT_FILE 2>&1
						echo >> $RESULT_FILE 2>&1
						echo [U-70]Result : GOOD >> $RESULT_FILE 2>&1
				fi
		fi
fi
rm -rf tmp_70.txt
rm -rf tmp_70_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


### /etc/httpd/conf/httpd.conf 경로에서 ServerTokents Prod 옵션과 ServerSignature off 옵션 설정이 되어 있는지 확인 필요
echo [U-71]Apache 웹 서비스 정보 숨김
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-71]Apache 웹 서비스 정보 숨김  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
### 변수 선언
APACHE_CONF_FILE="/etc/httpd/conf/httpd.conf"

if [ -e "$APACHE_CONF_FILE" ]
	then
    	if grep -qE "^\s*ServerTokens\s+Prod" "$APACHE_CONF_FILE" && grep -qE "^\s*ServerSignature\s+Off" "$APACHE_CONF_FILE"
		then
        echo "httpd.conf 파일에 올바르게 설정되어 있습니다." >> $RESULT_FILE 2>&1
		echo [71-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-71]Result : GOOD >> $RESULT_FILE 2>&1
else
        echo "httpd.conf 파일에 올바르지 않게 설정되어 있습니다." >> $RESULT_FILE 2>&1
		echo [71-END] >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		grep "ServerTokens Prod" /etc/httpd/conf/httpd.conf | grep -v "#" >> $RESULT_FILE 2>&1
		grep "ServerSignature Off" /etc/httpd/conf/httpd.conf | grep -v "#" >> $RESULT_FILE 2>&1
		echo "공란이라면 ServerTonkens / ServerSignature 설정이 없는 것입니다." >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-71]Result : VULNERABLE >> $RESULT_FILE 2>&1
   	 	fi
else
	echo "httpd.conf 파일이 없습니다." >> $RESULT_FILE 2>&1
	echo [71-END] >> $RESULT_FILE 2>&1
	echo >> $RESULT_FILE 2>&1
	echo [U-71]Result : N/A >> $RESULT_FILE 2>&1
    
fi
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo [U-72]정책에 따른 시스템 로깅 설정
echo "============================================================" >> $RESULT_FILE 2>&1
echo [U-72]정책에 따른 시스템 로깅 설정  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
if [ -f /etc/syslog.conf ]
	then
		cat /etc/syslog.conf | grep -v "#" | awk '$0 != null {print $0}' > tmp_72_1.txt
	else
		if [ -f /etc/rsyslog.conf ]
			then
				cat /etc/rsyslog.conf | grep -v "#" | awk '$0 != null {print $0}' > tmp_72_1.txt
			else
				echo "★ (r)syslog.conf 파일을 찾을 수 없음" >> $RESULT_FILE 2>&1
				echo [72-END] >> $RESULT_FILE 2>&1
				echo >> $RESULT_FILE 2>&1
				echo [U-72]Result : N/A >> $RESULT_FILE 2>&1
		fi
fi
if [ `cat tmp_72_1.txt | egrep -w "cron.\*|authpriv.\*|\*.info" | wc -l` -eq 3 ]
	then
		echo "★ (r)syslog.conf 설정이 적절하게 설정됨 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_72_1.txt >> $RESULT_FILE 2>&1
		echo [72-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-72]Result : GOOD >> $RESULT_FILE 2>&1
	else
		echo "★ 아래 현황을 기반으로 수동분석 " >> $RESULT_FILE 2>&1
		echo "[현황]" >> $RESULT_FILE 2>&1
		cat tmp_72_1.txt >> $RESULT_FILE 2>&1
		echo [72-END] >> $RESULT_FILE 2>&1
		echo >> $RESULT_FILE 2>&1
		echo [U-72]Result : MANUAL >> $RESULT_FILE 2>&1
fi
rm -rf tmp_72_1.txt
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "주통 기반 72개 항목 리눅스(센트오에스)에 대한 점검이 완료 되었습니다." >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Version ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
uname -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/issue >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ ping test ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ping -c 3 www.google.com >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Interface ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ifconfig -a >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ cat /etc/passwd ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/passwd  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ cat /etc/shadow ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
cat /etc/shadow  >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Socket ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
netstat -anp | head -200 >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Daemon ]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo "ps -ef" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
ps -ef >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1


echo "============================================================" >> $RESULT_FILE 2>&1
echo "[ Iptables]"  >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
iptables -L >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1
echo >> $RESULT_FILE 2>&1

echo "========================= WEB/WAS 상태 확인 =========================" > $RESULT_FILE 2>&1
WAS_RUNNING=0

### YUM 패키지 검사 (CentOS/Rocky) ###
echo "1) YUM 패키지 검사" >> $RESULT_FILE 2>&1
if yum list installed >> $RESULT_FILE 2>&1; then
    if [ -s $RESULT_FILE ]; then
        true  # 빈 블록 방지
    else
        echo "YUM 패키지 데이터가 없습니다." >> $RESULT_FILE 2>&1
    fi
else
    echo "YUM 패키지가 설치되지 않았습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

### Snap 제거 (CentOS 기본 미지원) ###

### pip 패키지 검사 ###
echo "2) pip 패키지 검사" >> $RESULT_FILE 2>&1

# python pip 검사
echo "2-1) python 검사 결과" >> $RESULT_FILE 2>&1
if command -v pip &> /dev/null; then
    pip list --format=columns | awk 'NR>2 {print $1, $2}' >> $RESULT_FILE 2>&1
    if [ ! -s $RESULT_FILE ]; then
        echo "python pip 패키지 데이터가 없습니다." >> $RESULT_FILE 2>&1
    fi
else
    echo "python pip 패키지가 설치되지 않았습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

# python3 pip 검사
echo "2-2) python3 검사 결과" >> $RESULT_FILE 2>&1
if command -v pip3 &> /dev/null; then
    pip3 list --format=columns | awk 'NR>2 {print $1, $2}' >> $RESULT_FILE 2>&1
    if [ ! -s $RESULT_FILE ]; then
        echo "python3 pip 패키지 데이터가 없습니다." >> $RESULT_FILE 2>&1
    fi
else
    echo "python3 pip 패키지가 설치되지 않았습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

### npm 패키지 검사 ###
echo "3) npm 패키지 검사" >> $RESULT_FILE 2>&1
if command -v npm &> /dev/null; then
    npm list -g --depth=0 | grep -v "npm@" >> $RESULT_FILE 2>&1
    if [ $? -ne 0 ]; then
        echo "npm 패키지 데이터가 없습니다." >> $RESULT_FILE 2>&1
    fi
else
    echo "npm이 설치되어 있지 않습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo "============================================================" >> $RESULT_FILE 2>&1
echo "[DB / WEB / WAS 설치 및 실행 현황]" >> $RESULT_FILE 2>&1
echo "============================================================" >> $RESULT_FILE 2>&1

### MySQL DB 확인 ###
echo "4) MySQL DB 상태 확인" >> $RESULT_FILE 2>&1
if command -v mysql &> /dev/null; then
    if systemctl is-active --quiet mysqld; then
        echo "MySQL DB가 실행 중입니다." >> $RESULT_FILE 2>&1
    else
        echo "MySQL이 설치되어 있지만 실행되지 않았습니다." >> $RESULT_FILE 2>&1
    fi
else
    echo "MySQL이 설치되어 있지 않습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

### Tomcat/Nginx/Apache 확인 ###
echo "5) Tomcat/Nginx/Apache 상태 확인" >> $RESULT_FILE 2>&1

# Tomcat 확인
TOMCAT_PATHS=("/opt/tomcat" "/usr/share/tomcat" "/var/lib/tomcat")
TOMCAT_FOUND=0

for path in "${TOMCAT_PATHS[@]}"; do
    if [ -d "$path" ]; then
        echo "Tomcat 설치 경로: $path" >> $RESULT_FILE 2>&1
        TOMCAT_FOUND=1
        break
    fi
done

if command -v catalina.sh &> /dev/null || [ $TOMCAT_FOUND -eq 1 ] || rpm -qa | grep -qi "tomcat"; then
    if pgrep -f "tomcat" > /dev/null; then
        echo "Tomcat 실행 중입니다." >> $RESULT_FILE 2>&1
        WAS_RUNNING=1
    else
        echo "Tomcat이 설치되어 있지만 실행되지 않았습니다." >> $RESULT_FILE 2>&1
    fi
else
    echo "Tomcat이 설치되어 있지 않습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

# Nginx 확인
if rpm -qa | grep -qi "nginx"; then
    echo "Nginx가 설치되어 있습니다." >> $RESULT_FILE 2>&1
    if systemctl is-active --quiet nginx; then
        echo "Nginx가 실행 중입니다." >> $RESULT_FILE 2>&1
        WAS_RUNNING=1
    else
        echo "Nginx가 설치되어 있지만 실행되지 않았습니다." >> $RESULT_FILE 2>&1
    fi
else
    echo "Nginx가 설치되어 있지 않습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

# Apache 확인
if rpm -qa | grep -qi "httpd"; then
    echo "Apache HTTP Server가 설치되어 있습니다." >> $RESULT_FILE 2>&1
    if systemctl is-active --quiet httpd; then
        echo "Apache HTTP Server가 실행 중입니다." >> $RESULT_FILE 2>&1
        WAS_RUNNING=1
    else
        echo "Apache가 설치되어 있지만 실행되지 않았습니다." >> $RESULT_FILE 2>&1
    fi
else
    echo "Apache HTTP Server가 설치되어 있지 않습니다." >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

if [ $WAS_RUNNING -eq 0 ]; then
    echo "실행 중인 WEB/WAS 서버가 없습니다." >> $RESULT_FILE 2>&1
else
    echo "최소 1개 이상의 WEB/WAS 서버가 실행 중" >> $RESULT_FILE 2>&1
fi
echo >> $RESULT_FILE 2>&1

echo "==============================  END  ==============================" >> $RESULT_FILE 2>&1
echo ""

}

# OS에 맞는 진단 함수 호출
if [[ "$OS_TYPE" == "ubuntu" ]]; then
    check_ubuntu
elif [[ "$OS_TYPE" == "rocky" ]]; then
    check_rocky
elif [[ "$OS_TYPE" == "centos" ]]; then
    check_centos
else
    echo "지원되지 않는 운영 체제입니다. 스크립트 종료." >> $RESULT_FILE 2>&1
    exit 1
fi

## 결과 파일 수집 서버로 업로드 작업 수행
echo "출력 결과물을 업로드 합니다."
# 서버의 파일 이름 패턴을 설정
FILE_PATTERN="./*.txt"  # 파일 이름 패턴
UPLOAD_URL="http://<UPLOAD_SERVER_IP>:5000/upload"  # 업로드할 서버의 URL

# 파일이 존재하는지 확인하고 업로드 수행
for file in $FILE_PATTERN; do
    if [[ -f "$file" ]]; then
        echo "Uploading file: $file"
        
        # 파일을 업로드
        curl -X POST -F "file=@$file" $UPLOAD_URL
        
        if [[ $? -eq 0 ]]; then
            echo "File '$file' uploaded successfully."
        else
            echo "Failed to upload '$file'."
        fi
    else
        echo "No matching files found for pattern: $FILE_PATTERN"
    fi
done

rm -rf *.txt
rm -rf *.sh