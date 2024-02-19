rule MAL_MIRAI_x86_64_LINUX_FEB_18_2024 {
  meta:
    description = "Mirai x86_64 yara rule"
    author = "Permafr0st security"
    md5 = "d476e0c2a8e4e4d90f2eaa15c36d8a90"
    sha256 = "5d37a4c89f2e567807e2033f8c8e9cfdb75ee6ec426d58ffd930e7fdbe066157"

  strings:
    $str1 = "M-SEARCH * HTTP/1.1"
    $str2 = "ST: urn:dial-multiscreen-org:service:dial:1"
    $str3 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
    $str4 = "service:service-agent"
    $str5 = "/dev/watchdog"
    $str6 = "/dev/misc/watchdog"
    $str7 = "got malware'd"
    $str8 = "/usr/sbin/tcpdump"
    $str9 = "/usr/sbin/tshark"
    $str10 = "/usr/sbin/wireshark"
    $str11 = "/usr/sbin/dumpcap"
    $str12 = "/usr/sbin/ettercap"
    $str13 = "/usr/sbin/dsniff"
    $str14 = "/usr/sbin/ngrep"
    $str15 = "/usr/sbin/tcpflow"
    $str16 = "/usr/sbin/windump"
    $str17 = "/usr/sbin/netsniff-ng"
    $str18 = "/usr/bin/tcpdump"
    $str19 = "/usr/bin/tshark"
    $str20 = "/usr/bin/wireshark"
    $str21 = "/usr/bin/dumpcap"
    $str22 = "/usr/bin/ettercap"
    $str23 = "/usr/bin/dsniff"
    $str24 = "/usr/bin/ngrep"
    $str25 = "/usr/bin/tcpflow"
    $str26 = "/usr/bin/windump"
    $str27 = "/usr/bin/netsniff-ng"

  condition:
    ( 4 of them ) and $str7
}
