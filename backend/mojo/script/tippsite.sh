#!/usr/bin/env bash

USAGE="Usage: $0 {start|stop|restart|hot-deploy|status|info|exec|morbo}"

HOSTNAME=$(hostname -s)
if [[ -z "$HOSTNAME" ]]; then
    echo "Unable to determine hostname."
    exit 1;
fi

PIDFILE="./script/hypnotoad.pid"
PID=`cat $PIDFILE 2>/dev/null`
if [[ -n "$PID" && -n $(ps aux| grep script/tippsite|grep -v grep| grep " $PID ") ]]; then
    RUNNING=1
fi

if [[ ! -f "./script/tippsite" ]]; then
    echo "Please run this script from the top level directory of tipp."
    exit 1
fi

function require_env_variable {
    if [[ -z "$1" ]]; then
        echo "Unable to run - $1 is missing in your environment"
        exit 1
    fi
}

PERL_VERSION=$(plenv version 2>/dev/null)
if [[ -z "$PERL_VERSION" ]]; then
    echo "Unable to run - plenv is missing."
    exit 1
fi

require_env_variable "MOJO_MODE"
export PERL5LIB="$(pwd)/lib"

if [ "$#" == "0" ]; then
    echo "$USAGE"
    exit 1
fi

COMMAND="$1"
shift

case "$COMMAND" in
    start)
        if [[ -z "$RUNNING" ]]; then
            hypnotoad ./script/tippsite
        else
            echo "Already running with pid $PID"
        fi
    ;;
    stop)
        if [[ -n "$RUNNING" ]]; then
            hypnotoad -s ./script/tippsite
        else
            echo "Not running"
        fi
    ;;
    restart)
        echo "Restarting"
        $0 stop
        $0 start
    ;;
    hot-deploy)
        if [[ -n "$RUNNING" ]]; then
            hypnotoad ./script/tippsite
        else
            echo "Not running, starting instead"
            $0 start
        fi
    ;;
    status)
        if [[ -n "$RUNNING" ]]; then
            echo "Running with pid $PID"
        else
            echo "Not running."
        fi
    ;;
    info)
        echo "Using perl $PERL_VERSION"
    ;;
    exec)
        # Run command in current environment
        echo $* | . /dev/stdin
    ;;
    morbo)
        if [[ -n "$1" ]]; then
            PORT=$1
        else
            echo "ERROR: Port missing."
            echo "Usage: $0 morbo <port>"
            exit 1;
        fi
        echo morbo -l "http://*:$PORT" -w config -w lib -w templates ./script/tippsite
        morbo -l "http://*:$PORT" -w config -w lib -w templates ./script/tippsite
    ;;
    *)
        echo "$USAGE";
        exit 1;
    ;;
esac
