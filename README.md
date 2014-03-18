Sensor - A libpcap-based sensor/reducer
=======================================

To compile:

$ gcc `pcap-config --libs` -pthread sensor.c node.c tree.c treeFunctions.c tables.c -o sensor

To run:

$ sensor [--<argument1> <value1> [--<argument2> <value2> ...]]

Argument (Default Value) - Description
--------------------------------------
--dev (System Default) - The packet-capture device
--filter_exp (ip) - The packet-filter expression
--tree_file (default.tree) - The decision tree file
--ip<1-8> () - The comma-separated IP-address (in CIDR notation) list
--port<1-8> () - The comma-separated port (range (<lower port>:<upper port>)) list
--ip_history_length (1) - The IP-history length
--port_history_length (1) - The source/destination port history length
--pair_history_length (1) - The socket-pair history length
--src_ip_occasional_threshold (1) - The occasinoal source-IP threshold (inclusive)
--src_ip_frequent_threshold (1) - The frequent source-IP threshold (inclusive)
--dst_ip_occasional_threshold (1) - The occasional destination-IP threshold (inclusive)
--dst_ip_frequent_threshold (1) - The frequent destination-IP threshold (inclusive)
--sp_frequent_threshold (1) - The fequent source-port threshold (inclusive)
--sp_occasional_threshold (1) - The occasional source-port threshold (inclusive)
--dp_frequent_threshold (1) - The occasional destination-port threshold (inclusive)
--dp_occasional_threshold (1) - The frequent destination-port threshold (inclusive)

Available decision tree questions:
- isTCP
- isUDP
- isICMP
- isICMPRequest
- isICMPReply
- isICMPError
- isICMPOther
- isInIPList<1-8> (associated with ip<1-8>)
- isInPortList<1-8> (associated with port<1-8>)
- isOccasionalIP (affected by ip_history_length and *_ip_occasional_threshold)
- isFrequentIP (affected by ip_history_length and *_ip_frequent_threshold)
- isOccasionalPort (affected by port_history_length and *p_occasional_threshold)
- isFrequentPort (affected by port_history_length and *p_frequent_threshold)
- isAttached (affected by pair_history_length)
