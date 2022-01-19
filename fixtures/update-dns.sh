#!/bin/sh

ACTION=$1
DOMAIN=$2
CHALLENGE_VALUE=$3

if test "$ACTION" = "present";
then
  curl -s -X POST -d "{\"host\":\"$DOMAIN\", \"value\": \"$CHALLENGE_VALUE\"}" http://challtestsrv:8055/set-txt
elif test "$ACTION" = "cleanup";
then
  curl -s -X POST -d "{\"host\":\"$DOMAIN\", \"value\": \"$CHALLENGE_VALUE\"}" http://challtestsrv:8055/clear-txt
fi
