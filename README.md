Sensor - A libpcap-based sensor/reducer
=======================================

To compile:

gcc `pcap-config --libs` -pthread tables.c node.c tree.c treeFunctions.c sensor.c -o sensor.out
