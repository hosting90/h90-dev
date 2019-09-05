#!/bin/bash

#
#	Script for killing Apache processes running longer than 3min
#	Run every minute by cron on non-onedesign webservers
#

#Check if we are running on right webserver
hostname -s | egrep "(h90|hz|h90hr)-w[0-9]+" > /dev/null || exit 0



function apache_kill {
	
	PROC_LIST=$(find /proc -maxdepth 1 -gid 48 ! -uid 48 ! -uid 99 -type d -mmin +3)
	for PROC in $PROC_LIST; do
		PROC_EXE=$(readlink ${PROC}/exe)
		if [[ "$PROC_EXE" == "/usr/sbin/httpd" ]]; then
			PROC_CMD=$(cat ${PROC}/cmdline)
			PROC_DIR=$(readlink ${PROC}/cwd)
			PROC_OWNER=$(stat -c '%U' ${PROC})
			PROC_PID=$(echo ${PROC##*/})
			PROC_AGE=$( expr $(date +%s) - $(stat --format=%Y $PROC) )

			kill -9 $PROC_PID
			KILL_RETCODE=$?
			if [[ $KILL_RETCODE == 0 ]]; then
				PROC_KILL_STATUS="OK: $KILL_RETCODE"
			else
				PROC_KILL_STATUS="ERROR: $KILL_RETCODE"
			fi


			echo -e "$PROC_PID\t$PROC_DIR\t$PROC_OWNER\t$PROC_AGE\t$PROC_KILL_STATUS"

		fi
	done
}

HEADER=$(echo -e "PID\tDIRECTORY\tOWNER\tAGE(sec)\tKILL_STATUS")
KILL_OUTPUT=$(apache_kill)

#If there is no output, do not send mail
if [[ -n $KILL_OUTPUT ]]; then
OUT=$(echo "$HEADER" $'\n'"$KILL_OUTPUT" | column -t -s $'\t')
sendmail admin@hosting90.cz <<EOF
Subject: ApacheKiller on $HOSTNAME
From: apache killer

Killing long running httpd processes on $HOSTNAME

$OUT
EOF

fi

