from scapy.all import sniff

# Define a packet handling function
def packet_handler(packet):
    # Display packet summary
    print(packet.summary())

# Sniff packets on the network
sniff(prn=packet_handler, filter="tcp")
