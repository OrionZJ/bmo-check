"""Thin command-line composition layer.

分析包只提供 typed service；这里把动态、静态和诊断命令组合成用户入口，避免
诊断代码反向进入 dynamic/static 的内部实现。
"""
