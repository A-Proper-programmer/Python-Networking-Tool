COMMON_TCP_PORTS = {
    "File Transfer": {
        20: "FTP Data",
        21: "FTP Control",
        69: "TFTP (TCP variant)",
        873: "rsync",
        2049: "NFS",
    },

    "Remote Access": {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        5900: "VNC",
        5985: "WinRM HTTP",
        5986: "WinRM HTTPS",
    },

    "Web Services": {
        80: "HTTP",
        443: "HTTPS",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate",
    },

    "Email": {
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
    },

    "Name & Directory Services": {
        53: "DNS",
        111: "RPCbind",
        389: "LDAP",
        636: "LDAPS",
    },

    "Windows Networking": {
        135: "Microsoft RPC",
        139: "NetBIOS Session",
        445: "SMB",
    },

    "Databases": {
        1433: "Microsoft SQL Server",
        1521: "Oracle Database",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
    },

    "Network Management": {
        179: "BGP",
        515: "LPD Printing",
        631: "IPP Printing",
        514: "Syslog TCP",
    },

    "Proxy Services": {
        1080: "SOCKS Proxy",
    },

    "Other Services": {
        119: "NNTP",
        50000: "SAP Dispatcher (common default)",
    }}

COMMON_UDP_PORTS={
    "Network Configuration": {
        67: "DHCP Server",
        68: "DHCP Client",
    },

    "Name Resolution": {
        53: "DNS",
    },

    "Network Discovery & Management": {
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        161: "SNMP",
        162: "SNMP Trap",
    },

    "Time Synchronization": {
        123: "NTP",
    },

    "File Transfer": {
        69: "TFTP",
    },

    "Network Security": {
        500: "IKE / IPsec",
    },

    "Logging": {
        514: "Syslog UDP",
    }}