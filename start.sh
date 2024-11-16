#!/bin/bash
# -*- coding: utf-8 -*-
# Description: This script extracts firmware binaries using binwalk and performs Ghidra analysis.
#
# Author: Jongchan Hong
# Lab: SoftSec Lab, Sungkyunkwan University
# Email: jc1904@skku.edu
# Date: 2024-11-16

EXTRACT_DIR=./extract
GHIDRA_DIR=/opt/ghidra/ghidra_11.0_PUBLIC
INPUT_BIN=$1
FIRMWARE_NAME=$(basename "$INPUT_BIN")
PRJ_NAME=$FIRMWARE_NAME
EXTRACTED_DIR="$EXTRACT_DIR/_${FIRMWARE_NAME}.extracted"

# 파일 import 함수
import_files_recursively() {
  local dir=$1
  for entry in "$dir"/*; do
    if [ -d "$entry" ]; then
      echo "folder?: $entry"
      import_files_recursively "$entry"
    elif [ -f "$entry" ]; then
      if file "$entry" | grep -q "ELF"; then
        echo "Importing ELF file: $entry"
        "$GHIDRA_DIR/support/analyzeHeadless" "$(pwd)" "$PRJ_NAME" -import "$entry"
      elif file "$entry" | grep -q "Mach-O"; then
        echo "Importing Mach-O file: $entry"
        "$GHIDRA_DIR/support/analyzeHeadless" "$(pwd)" "$PRJ_NAME" -import "$entry"
      else
        echo "Skipping non-ELF and non-Mach-O file: $entry"
      fi
    fi
  done
}

# 변수 출력 (디버깅 용)
echo "Input Binary: $INPUT_BIN"
echo "Extract Directory: $EXTRACT_DIR"

# binwalk의 종료 상태 확인
# 먼저 추출 시도
echo "Extracting firmware with binwalk..."
rm -rf "$EXTRACT_DIR"
binwalk --run-as=root -e "$INPUT_BIN" -C "$EXTRACT_DIR"

# 추출 디렉토리에 파일이 존재하는지 확인
if [ "$(ls -A "$EXTRACT_DIR")" ]; then
  echo "Firmware extraction succeeded."
else
  echo "Extraction failed. Copying binary as is."
  rm -rf "$EXTRACTED_DIR"
  mkdir -p "$EXTRACTED_DIR"
  cp "$INPUT_BIN" "$EXTRACTED_DIR/"
fi

# 2. 기존 PRJ Temp file 삭제
rm -rf "/$PRJ_NAME.gpr"
rm -rf "/$PRJ_NAME.rep"
rm -rf "/$PRJ_NAME.lock"

# 3. 파일 import 수행
echo "import root: $EXTRACTED_DIR"
import_files_recursively "$EXTRACTED_DIR"

# 4. import 파일 기반의 분석 스크립트 실행
echo "Running analysis script..."
"$GHIDRA_DIR/support/analyzeHeadless" "$(pwd)" "$PRJ_NAME" -postScript start.py