#!/usr/bin/env bash
# Turns the newest Playwright demo video into an optimized GIF.
set -euo pipefail
video=$(ls -t demo/out/*/video.webm | head -1)
out=${1:-../../docs/public/demo.gif}
mkdir -p "$(dirname "$out")"
palette=$(mktemp -t cvedetector-palette).png
filters="fps=10,mpdecimate,scale=1100:-1:flags=lanczos"
ffmpeg -y -loglevel error -i "$video" -vf "$filters,palettegen=max_colors=64:stats_mode=diff" "$palette"
ffmpeg -y -loglevel error -i "$video" -i "$palette" \
  -lavfi "$filters [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" -fps_mode vfr "$out"
rm -f "$palette"
ls -lh "$out"
