#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project
#
# Runs one fuzz target with Jazzer (coverage guided), or replays inputs through it.
#   fuzz.sh run <Target> <seconds> [work dir]   fuzz from the seeds and the kept corpus
#   fuzz.sh replay <Target> <file or dir>...    run each input once and report findings
# The work dir (default build/fuzz) holds <Target>/corpus, seeds and findings. Nothing in it is
# committed. Needs JDK 21 and Gradle, and builds first.
set -eu
cd "$(dirname "$0")"
mode=$1
target=$2
shift 2

gradle --no-daemon -q fuzzClasspath >/dev/null
cp=$(cat build/fuzz-classpath.txt)

case $target in
    BppFuzz|DownloadFlowFuzz|CertificateFuzz|Es9Fuzz|JsonFuzz) max_len=16384 ;;
    *) max_len=4096 ;;
esac

jazzer() {
    java -Xmx2g -cp "$cp" com.code_intelligence.jazzer.Jazzer \
        --target_class="de.diamaneos.euicc.fuzz.$target" \
        --instrumentation_includes='de.diamaneos.**' \
        -timeout=10 -rss_limit_mb=4096 -max_len=$max_len "$@"
}

case $mode in
    run)
        seconds=$1
        work=${2:-build/fuzz}/$target
        mkdir -p "$work/corpus" "$work/findings"
        if [ ! -d "${2:-build/fuzz}/seeds/$target" ]; then
            java -cp "$cp" de.diamaneos.euicc.fuzz.Seeds "${2:-build/fuzz}/seeds"
        fi
        jazzer --keep_going=100000 --reproducer_path="$work/findings" \
            -artifact_prefix="$work/findings/" -max_total_time="$seconds" -print_final_stats=1 \
            "$work/corpus" "${2:-build/fuzz}/seeds/$target"
        ;;
    replay)
        # Jazzer writes a reproducer for each finding: keep them out of the source tree.
        mkdir -p build/fuzz/replay-findings
        jazzer --keep_going=100000 --reproducer_path=build/fuzz/replay-findings \
            -artifact_prefix=build/fuzz/replay-findings/ -runs=0 "$@"
        ;;
    *)
        echo "usage: fuzz.sh run|replay <Target> ..." >&2
        exit 2
        ;;
esac
