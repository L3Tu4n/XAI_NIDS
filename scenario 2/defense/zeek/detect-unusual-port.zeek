@load scan
@load base/frameworks/notice
@load base/protocols/conn

module UnusualPort;

export {
    redef enum Notice::Type += {
        Unusual_Port_Connection
    };
}

# Set lưu IP đã cảnh báo
global flagged_ips: set[addr] = set();

const allowed_ports: set[port] = {
    21/tcp,22/tcp,80/tcp,443/tcp,587/tcp,
    5044/tcp,5601/tcp,6731/tcp,
    8080/tcp,8332/tcp,9200/tcp,
    40000/tcp,40001/tcp,40002/tcp,40003/tcp,
    40004/tcp,40005/tcp,40006/tcp,
    40007/tcp,40008/tcp,40009/tcp,40010/tcp
};

const multicast_v4: subnet = 224.0.0.0/4;
const multicast_v6: subnet = [ff00::]/8;

event connection_established(c: connection)
{
    local src = c$id$orig_h;

    # 1) Bỏ qua mọi IP đang scan (Scan::attacks) hoặc đang suppress (Scan::known_scanners)
    if ( src in Scan::attacks || src in Scan::known_scanners )
        return;

    if ( src in flagged_ips )
        return;

    if ( c$id$orig_p in allowed_ports
      || c$id$resp_p in allowed_ports
      || c$id$resp_h in multicast_v4
      || c$id$resp_h in multicast_v6 )
        return;

    NOTICE([
        $note = Unusual_Port_Connection,
        $msg  = fmt("Suspicious connection to unusual port: %s:%d → %s:%d",
                    c$id$orig_h, port_to_count(c$id$orig_p),
                    c$id$resp_h, port_to_count(c$id$resp_p)),
     $conn=c]);

    add flagged_ips[src];
}