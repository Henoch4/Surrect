@echo off
cd /d "C:\Users\Henoch\Documents\Programming Folder\file-recovery-study"
set PYTHONFAULTHANDLER=1
py -X faulthandler -u pycarve.py gauntlet.img -o recovered_gaunt --frag --resume > gauntlet_run.log 2> gauntlet_run.err
