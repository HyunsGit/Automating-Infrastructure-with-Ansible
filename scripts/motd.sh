#!/bin/bash
publicIP=`wget http://ipecho.net/plain -O - -q ; echo 2> /dev/null`
TotalPMem=`free -m | grep -v total | grep -v Swap | awk '{print $2}'`
UsingPMem=`free -m | grep -v total | grep -v Swap | awk '{print $3}'`
UsingPMemPer=`expr \( ${UsingPMem} \* 100 \/ ${TotalPMem} \)`
TotalVMem=`free -m | grep -v total | grep -v Mem | awk '{print $2}'`
UsingVMem=`free -m | grep -v total | grep -v Mem | awk '{print $3}'`
UsingVMemPer=`expr \( ${UsingVMem} \* 100 \/ ${TotalVMem} \)`
TotalHDD=`df -h | grep sda1 | awk '{print $2}'`
UsingHDD=`df -h | grep sda1 | awk '{print $3}'`
UsingHDDPer=`df -h | grep sda1 | awk '{print $5}'`
 
#color
NONE='\033[0m'
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
MAGENTA=`tput setaf 5`
CYAN=`tput setaf 6`
 
echo "=================================================================================="
echo "||                                        ||"
printf "||    DKTECHIN ${MAGENTA}카엔IDC팀${NONE} TAM의 ${GREEN}관리 대상 서버${NONE}입니다.    ||\n"
echo "||                                        ||"
printf "||    = ${CYAN}작업 환경${NONE} =                                ||\n"
echo "||        배포판 정보    : Ubuntu 16.04 LTS (64 bit)            ||"
echo "||        커널 정보    : `uname -r`                ||"
echo "||        메모리 사용량    : ${UsingPMem}M / ${TotalPMem}M (${UsingPMemPer}%)                ||"
echo "||        SWAP 사용량    : ${UsingVMem}M / ${TotalVMem}M (${UsingVMemPer}%)                ||"
echo "||        HDD 사용량    : ${UsingHDD} / ${TotalHDD} (${UsingHDDPer})                ||"
echo "||                                        ||"
printf "||    = ${CYAN}기타 정보${NONE} =                                ||\n"
echo "||        마지막 재부팅     : `uptime -s`                ||"
echo "||        공인 IP     : ${publicIP}                ||"
echo "||        gcc 버전    : `gcc --version | grep gcc | awk '{ print $4 }'`                        ||"
echo "||        javac 버전     : 9-internal                    ||"
echo "||                                        ||"
printf "||    * 실습에 필요한 패키지가 설치되지 않은 경우 임원진에게 알려주세요.    ||\n"
printf "||    * ${YELLOW}메모리, HDD 사용량이 90%% 이상이면 FAN 임원진에게 알려주세요.${NONE}        ||\n"
echo "||    * 시스템 자동 업데이트    : 매주 토요일 새벽 3시                ||"
echo "||                                        ||"
printf "||                        ${BLUE}last modified : 160330-yowu${NONE}    ||\n"
echo "||                                        ||"
echo "=================================================================================="