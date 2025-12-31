@load base/frameworks/notice

module DNS_TUNNELS;

export {
    redef enum Notice::Type += {
        RequestCountOverload,  # Request count exceeds threshold
        OvermuchNumber,        # Query contains too many digits
        DnsTunnelsAttack       # DNS tunneling attack
    };

    const request_count_threshold = 100 &redef;   # Threshold for request count
    const query_len_threshold = 27 &redef;        # Threshold for query length
    const percentage_of_num_count = 0.2 &redef;   # Threshold for digit percentage (20%)
    const record_expiration = 5min &redef;        # Expiration time for records
    const trusted_ip: addr = to_addr("192.168.63.2");    
}

# Table to track request counts from each source IP
global cq_table: table[addr] of count &default=0 &read_expire=record_expiration;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if (c$id$resp_p != 53)
        return;

    if (c$id$resp_h == trusted_ip)
        return;        
        
    if (query == "")
        return;

    local query_len = |query|;  # Query length
    local src_ip = c$id$orig_h; # Source IP

    # Increment the request count for the source IP
    cq_table[src_ip] += 1;

    # Check if the request count exceeds the threshold
    if (cq_table[src_ip] > request_count_threshold) {
        NOTICE([$note=RequestCountOverload,
                $conn=c,
                $msg=fmt("Host %s exceeds the request count threshold", src_ip)]);
    }

    # Check for queries longer than the threshold
    if (query_len > query_len_threshold) {
        local num_count = 0;
        # Count the number of digits in the query
        local i = 0;
        while (i < query_len) {
            local char = query[i];  # Get the character at index i
            if (char >= "0" && char <= "9") {
                num_count += 1;
            }
            i += 1;
        }
        # Calculate the digit percentage (using floating point)
        local num_percentage = (num_count + 0.0) / query_len;
        if (num_percentage > percentage_of_num_count) {
            NOTICE([$note=OvermuchNumber,
                    $conn=c,
                    $msg=fmt("Query from %s contains too many digits", src_ip)]);
            # If both conditions are met, report a DNS tunneling attack
            if (cq_table[src_ip] > request_count_threshold) {
                NOTICE([$note=DnsTunnelsAttack,
                        $conn=c,
                        $msg=fmt("Detected DNS tunneling attack from %s", src_ip)]);
            }
        }
    }
}