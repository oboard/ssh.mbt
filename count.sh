#!/bin/bash

# 递归查找所有 .mbt 文件并统计总行数
total_lines=$(find . -type f -name "*.mbt" -exec cat {} + 2>/dev/null | wc -l)

# 递归统计 .mbt 文件个数（每个文件输出一个换行，再统计行数）
file_count=$(find . -type f -name "*.mbt" -exec echo \; 2>/dev/null | wc -l)

echo "文件个数: $file_count"
echo "总行数:   $total_lines"
