module FTP; 

#redef exit_only_after_terminate = T ; 

redef default_capture_password = T ; 
redef logged_commands += {  "USER", "PASS", } ; 

export {

     redef enum Notice::Type += {
        Bruteforcer,
        BruteforceSummary, 
    } ; 

    type user_pass: record { 
        user: set[string]; 
        pass: set[string]; 
        bruteforcer: bool &default=F ; 
    } ; 

    global fail_threshold = 5 ; 
        
    global expire_bruteforcer_table: function(t: table[addr] of user_pass, src: addr ): interval ; 

    global bruteforcer_table: table[addr] of user_pass &create_expire=1 hrs &expire_func=expire_bruteforcer_table ; 
} 

# enable for DROP ACTION 
#hook Notice::policy(n: Notice::Info)
#  {
#  if ( n$note == FTP::Bruteforcer)
#    add n$actions[Notice::ACTION_EMAIL];
#  }

function expire_bruteforcer_table(t: table[addr] of user_pass, src: addr): interval
{

    local msg = fmt ("FTP bruteforcer : source: %s, Users tried: %s, number Password tried: %s", src, |t[src]$user|, |t[src]$pass|);
    NOTICE([$note=BruteforceSummary, $src=src, $msg=msg]);
    return 0 secs;
} 

event ftp_request(c: connection, command: string, arg: string) &priority=5
{ 

    local src = c$id$orig_h ; 
    local dst = c$id$resp_h ;

    #if (src in Site::local_nets()) 
    #    return ;
    #print fmt ("ftp_request: command: %s, arg: %s", command, arg); 

    if ( command == "USER" || command == "PASS" )
    { 
        if (src !in bruteforcer_table)
        {     
            local u: set[string] ; 
            local p: set[string]; 
            local up: user_pass ; 
            bruteforcer_table[src]=up ; 
            
        } 

        if (command == "USER" ) 
            add bruteforcer_table[src]$user[arg] ; 
        else 
            add bruteforcer_table[src]$pass[arg]; 
        
        if ( (! bruteforcer_table[src]$bruteforcer) && (|bruteforcer_table[src]$user| > fail_threshold || |bruteforcer_table[src]$pass| > fail_threshold )) 
        { 
            bruteforcer_table[src]$bruteforcer = T ;     
                    local msg = fmt ("FTP bruteforcer : %s, %s, pass: %s", src, |bruteforcer_table[src]$user|, |bruteforcer_table[src]$pass|); 
            NOTICE([$note=Bruteforcer, $conn=c, $msg=msg]);
        } 
    } 
    
}