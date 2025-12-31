@load base/protocols/ftp
@load base/frameworks/files

module CheckForRansomwareFilenames;

type Idx: record {
    index: count;
};

type Val: record {
    rw_pattern: string;
};

export {
    redef enum Notice::Type += {
        Ransomware::KnownBadFilename
    };
}

# Bảng lưu trữ mẫu ransomware
global ransomware_filename_patterns_table: table[count] of Val;

# Đối tượng paraglob để tìm kiếm nhanh
global ransomware_filename_patterns_paraglob: opaque of paraglob;

event zeek_init()
{
    # Đọc file danh sách mẫu ransomware
    Input::add_table([$source="/opt/zeek/share/zeek/site/fsrm_patterns_for_zeek.tsv", $name="ransomware_patterns", 
                      $idx=Idx, $val=Val, $destination=ransomware_filename_patterns_table, 
                      $mode=Input::REREAD]);
}

event Input::end_of_data(name: string, source: string)
{
    if (name != "ransomware_patterns")
        return;

    # Tạo vector từ bảng mẫu
    local ransomware_filename_patterns_vector: vector of string;
    for (idx in ransomware_filename_patterns_table)
    {
        ransomware_filename_patterns_vector += ransomware_filename_patterns_table[idx]$rw_pattern;
    }

    # Khởi tạo paraglob
    ransomware_filename_patterns_paraglob = paraglob_init(ransomware_filename_patterns_vector);
}

# Kiểm tra tên tệp trong files.log cho FTP
event Files::log_files(rec: Files::Info)
{
    # Chỉ xử lý tệp từ FTP và có tên tệp
    if (!rec?$filename || rec$source != "FTP")
        return;

    # Kiểm tra tên tệp với paraglob
    local num_matches = |paraglob_match(ransomware_filename_patterns_paraglob, rec$filename)|;

    # Xử lý theo phiên bản Zeek
    @if ((Version::info$major >= 5 && Version::info$minor >= 1) || (Version::info$major >= 6))
        # Zeek 5.1+ trở lên
        if (num_matches > 0)
        {
            NOTICE([$note=Ransomware::KnownBadFilename,
                    $msg=fmt("Detected potential ransomware! Known bad file name: %s detected in FTP connection [id.orig_h: %s, id.resp_h: %s, uid: %s]", 
                             rec$filename, rec$id$orig_h, rec$id$resp_h, rec$uid),
                    $src=rec$id$orig_h, $dst=rec$id$resp_h, $uid=rec$uid]);
        }
    @else
        # Zeek 4.x trở xuống
        if (num_matches > 0 && rec?$tx_hosts && rec?$rx_hosts && rec?$conn_uids)
        {
            for (tx_host in rec$tx_hosts)
            {
                for (cuid in rec$conn_uids)
                {
                    for (rx_host in rec$rx_hosts)
                    {
                        NOTICE([$note=Ransomware::KnownBadFilename,
                                $msg=fmt("Detected potential ransomware! Known bad file name: %s in FTP connection from %s to %s", 
                                         rec$filename, tx_host, rx_host),
                                $src=tx_host, $dst=rx_host, $uid=cuid]);
                    }
                }
            }
        }
    @endif
}

# (Tùy chọn) Kiểm tra tên tệp trực tiếp từ lệnh FTP
event ftp_request(c: connection, command: string, arg: string)
{
    if (command in set("RETR", "STOR"))
    {
        local filename = arg;

        # Tách tên tệp từ đường dẫn nếu cần
        if (/.*\// in arg)
        {
            local parts = split_string(arg, /\//);
            filename = parts[|parts|-1];
        }

        # Kiểm tra tên tệp với paraglob
        local num_matches = |paraglob_match(ransomware_filename_patterns_paraglob, filename)|;
        if (num_matches > 0)
        {
            NOTICE([$note=Ransomware::KnownBadFilename,
                    $msg=fmt("Detected potential ransomware in FTP! Known bad file name: %s in command %s from %s to %s", 
                             filename, command, c$id$orig_h, c$id$resp_h),
                    $src=c$id$orig_h, $dst=c$id$resp_h, $uid=c$uid]);
        }
    }
}