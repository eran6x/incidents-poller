@echo off

IF %1.==. GOTO No1
IF %2.==. GOTO No2

python incident_update.py -i %1  -p %2 -t INCIDENTS -a STATUS -v CLOSED
GOTO End1

:No1
  ECHO No incident id
GOTO End1
:No2
  ECHO No partition id
GOTO End1

:End1
