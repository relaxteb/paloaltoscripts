####################################################################################
# PALO ALTO list all Global Protect Users
# This script lists the active & previous GlobalProtect Users for each device & gateway
#
# Gemaakt door: Sebastian van Dijk
# Gemaakt op: 27-11-2018
# Changelog:
#               - 23-05-2018        SvD: Previous users, menu en count toegevoegd
#               - 24-05-2018        SvD: Disconnect users & ticketing toegevoegd / code cleanup
#               - 05-01-2021 v1.2   SvD:    - All calls use Panorama
#                                           - Changed Panorama Address to Parameter
#                                           - HA removed
#                                           - Ticket procedure changed by using the serial nr
#
# Actionlist: 
#               - Cleanup Code
#               - Check API faultcode array
# 
####################################################################################

# https://www.paloaltonetworks.com/documentation/81/pan-os/cli-gsg/use-the-cli/load-configurations/load-a-partial-configuration/xpath-location-formats-determined-by-device-configuration

clear-host 

####################################################################################
# SETTINGS
####################################################################################
#region settings

#below code ignores untrusted certificate
####################################################################################
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,
WebRequest request, int certificateProblem) {
return true;
}
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
####################################################################################

# SET TLS version
####################################################################################
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
####################################################################################


#endregion

####################################################################################
# VARIABLES
####################################################################################
#region variables

# Import variables
$Panorama = "Add your Panorama Address HERE"
$domainsuffix = "Add the domain suffix for the found Palo Alto firewalls here"

# API Key PAN_API user
$key = $PaloAlto_api_key  #ENTER YOUR API KEY HERE
if (!$key) {
    write-host "No API key" -foregroundcolor red
    exit
}

# Get the Date
$date = Get-Date

# Faultcode array 
# Source: https://www.paloaltonetworks.com/documentation/71/pan-os/xml-api/pan-os-xml-api-error-codes
####################################################################################
$faultcodes = @(
    ("400", "Bad request", "A required parameter is missing, an illegal parameter value is used."), 
    ("403", "Forbidden", "Authentication or authorization errors including invalid key or insufficient admin access rights. Learn how to Get Your API Key ."),
    ("1", "Unknown command", "The specific config or operational command is not recognized."),
    ("2", "Internal errors", "Check with technical support when seeing these errors."),
    ("3", "Internal errors", "Check with technical support when seeing these errors."),
    ("4", "Internal errors", "Check with technical support when seeing these errors."),
    ("5", "Internal errors", "Check with technical support when seeing these errors."),
    ("6", "Bad Xpath", "The xpath specified in one or more attributes of the command is invalid. Check the API browser for proper xpath values."),
    ("7", "Object not present", "Object specified by the xpath is not present. For example, entry[@name='value'] where no object with name 'value' is present."),
    ("8", "Object not unique", "For commands that operate on a single object, the specified object is not unique."),
    ("10", "Reference count not zero", "Object cannot be deleted as there are other objects that refer to it. For example address object still in use in policy."),
    ("11", "Internal error", "Check with technical support when seeing these errors."),
    ("12", "Invalid object", "Xpath or element values provided are not complete."),
    ("13", "Undefined", "Undefined"),
    ("14", "Operation not possible", "Operation is allowed but not possible in this case. For example, moving a rule up one position when it is already at the top."),
    ("15", "Operation denied", "Operation is allowed. For example, Admin not allowed to delete own account, Running a command that is not allowed on a passive device."),
    ("16", "Unauthorized", "The API role does not have access rights to run this query."),
    ("17", "Invalid command", "Invalid command or parameters."),
    ("18", "Malformed command", "The XML is malformed."),
    ("19", "Success", "Command completed successfully."),
    ("20", "Success", "Command completed successfully."),
    ("21", "Internal error", "Check with technical support when seeing these errors."),
    ("22", "Session timed out", "The session for this query timed out.")
)
####################################################################################


# Define Green and Red checkmarks for CLI response
####################################################################################
$greenCheck = @{
    Object          = [Char]8730
    ForegroundColor = 'Green'
    NoNewLine       = $true
}
$redX = @{
    Object          = [Char]88
    ForegroundColor = 'Red'
    NoNewLine       = $true
}


# Create Object Classes
####################################################################################
Class ConnectedGatewayUser {
    [string]$username
    [string]$primary_username
    [string]$computer
    [string]$client
    [string]$vpn_type
    [string]$virtual_ip
    [string]$virtual_ipv6
    [string]$public_ip
    [string]$public_ipv6
    [string]$tunnel_type
    [string]$public_connection_ipv6
    [string]$login_time
    [string]$login_time_utc
    [string]$lifetime
    [string]$firewall  
    [string]$gateway
    [string]$portal

    ConnectedGatewayUser (  [string]$username , `
            [string]$primary_username , `
            [string]$computer , `
            [string]$client , `
            [string]$vpn_type , `
            [string]$virtual_ip , `
            [string]$virtual_ipv6 , `
            [string]$public_ip , `
            [string]$public_ipv6 , `
            [string]$tunnel_type , `
            [string]$public_connection_ipv6 , `
            [string]$login_time , `
            [string]$login_time_utc , `
            [string]$lifetime , `
            [string]$firewall , `
            [string]$gateway , `
            [string]$portal ) {
    
        $this.username = $username
        $this.primary_username = $primary_username
        $this.computer = $computer
        $this.client = $client
        $this.vpn_type = $vpn_type
        $this.virtual_ip = $virtual_ip
        $this.virtual_ipv6 = $virtual_ipv6
        $this.public_ip = $public_ip
        $this.public_ipv6 = $public_ipv6
        $this.tunnel_type = $tunnel_type
        $this.public_connection_ipv6 = $public_connection_ipv6
        $this.login_time = $login_time
        $this.login_time_utc = $login_time_utc
        $this.lifetime = $lifetime
        $this.firewall = $firewall  
        $this.gateway = $gateway
        $this.portal = $portal
    }

}
Class PreviousGatewayUser {
    [string]$username
    [string]$primary_username
    [string]$computer
    [string]$client
    [string]$vpn_type
    [string]$virtual_ip
    [string]$virtual_ipv6
    [string]$public_ip
    [string]$public_ipv6
    [string]$tunnel_type
    [string]$public_connection_ipv6
    [string]$login_time
    [string]$login_time_utc
    [string]$lifetime
    [string]$firewall  
    [string]$gateway

    PreviousGatewayUser (  [string]$username , `
            [string]$primary_username , `
            [string]$computer , `
            [string]$client , `
            [string]$vpn_type , `
            [string]$virtual_ip , `
            [string]$virtual_ipv6 , `
            [string]$public_ip , `
            [string]$public_ipv6 , `
            [string]$tunnel_type , `
            [string]$public_connection_ipv6 , `
            [string]$login_time , `
            [string]$login_time_utc , `
            [string]$lifetime , `
            [string]$firewall , `
            [string]$gateway) {
    
        $this.username = $username
        $this.primary_username = $primary_username
        $this.computer = $computer
        $this.client = $client
        $this.vpn_type = $vpn_type
        $this.virtual_ip = $virtual_ip
        $this.virtual_ipv6 = $virtual_ipv6
        $this.public_ip = $public_ip
        $this.public_ipv6 = $public_ipv6
        $this.tunnel_type = $tunnel_type
        $this.public_connection_ipv6 = $public_connection_ipv6
        $this.login_time = $login_time
        $this.login_time_utc = $login_time_utc
        $this.lifetime = $lifetime
        $this.firewall = $firewall  
        $this.gateway = $gateway
    }

}
Class ConnectedPortalUser {
    [string]$gp_portal_name
    [string]$vsys_id
    [string]$username
    [string]$session_id
    [string]$client_ip
    [string]$sess_start_time
    [string]$inactivity_timeout
    [string]$sec_before_inactivity_timeout
    [string]$login_lifetime
    [string]$sec_before_login_lifetime
    [string]$size_of_ck_cache
    [string]$firewall  
    
    
    ConnectedPortalUser ( [string]$gp_portal_name , `
            [string]$vsys_id, `
            [string]$username, `
            [string]$session_id, `
            [string]$client_ip, `
            [string]$sess_start_time, `
            [string]$inactivity_timeout, `
            [string]$sec_before_inactivity_timeout, `
            [string]$login_lifetime, `
            [string]$sec_before_login_lifetime, `
            [string]$size_of_ck_cache, `
            [string]$firewall) {
     
        $this.gp_portal_name = $gp_portal_name
        $this.vsys_id = $vsys_id
        $this.username = $username
        $this.session_id = $session_id
        $this.client_ip = $client_ip
        $this.sess_start_time = $sess_start_time
        $this.inactivity_timeout = $inactivity_timeout
        $this.sec_before_inactivity_timeout = $sec_before_inactivity_timeout
        $this.login_lifetime = $login_lifetime
        $this.sec_before_login_lifetime = $sec_before_login_lifetime
        $this.size_of_ck_cache = $size_of_ck_cache
        $this.firewall = $firewall
    
    }
}

Class DevicePortal {
    [string]$name
    [string]$firewall
    [string]$serial
    
    DevicePortal (  [string]$name , `
            [string]$firewall , `
            [string]$serial ) {
    
        $this.name = $name
        $this.firewall = $firewall  
        $this.serial = $serial
        
    }

}



# Create Variables
####################################################################################
$ConnectedGatewayUsers = New-Object "System.Collections.Generic.List[ConnectedGatewayUser]" 
$PreviousGatewayUsers = New-Object "System.Collections.Generic.List[PreviousGatewayUser]" 
$ConnectedPortalUsers = New-Object "System.Collections.Generic.List[ConnectedPortalUser]" 
$DevicePortals = New-Object "System.Collections.Generic.List[DevicePortal]" 
$gpportals



#endregion

####################################################################################
# FUNCTIONS
####################################################################################
#region Functions
# Define function to match faultcodes to the returned faultcode and prints faultcode when not Success
function check_faults ($code) {
    foreach ($fault in $faultcodes) {
								if ($fault[0] -eq $code) {
            if ($code -ne "19") {
                if ($code -ne "20") {
                    write-host "!!!!!!! FAULT !!!!!!! " -ForegroundColor Red
                    write-host "Exiting Script because of error: $code" -ForegroundColor Red
                    write-host $fault[2] -ForegroundColor Red
                    check_or_exit
										    
                } 
								    } 
            if ($code -eq "19") {
                check_or_exit("1")
                
            }
            if ($code -eq "20") {
                check_or_exit("1")
                
            }
								}
								

    }
}
function check_faults_v2 {
    param 
    (
        #[Parameter(Mandatory = $true)]
        [String]$code,
        #[Parameter(Mandatory = $true)] 
        [String]$status,
        #[Parameter(Mandatory = $true)] 
        [String]$msg,
        #[Parameter(Mandatory = $false)] 
        [array]$line
    )

    foreach ($fault in $faultcodes) {
								if ($fault[0] -eq $code) {
            if ($code -ne "19") {
                if ($code -ne "20") {
                    write-host "!!!!!!! FAULT !!!!!!! " -ForegroundColor Red
                    write-host "Exiting Script because of error: " $code -ForegroundColor Red
                    write-host "Exiting Script because of status: " $status -ForegroundColor Red
                    write-host "Exiting Script because of message: " $fault[2] -ForegroundColor Red
                    $line
                    check_or_exit
										    
                } 
								    } 
            if ($code -eq "19") {
                check_or_exit("1")
                
            }
            if ($code -eq "20") {
                check_or_exit("1")
                
            }
								}
								

    }
    if ($status -eq "error") {
        write-host "!!!!!!! FAULT !!!!!!! " -ForegroundColor Red
        write-host "Exiting Script because of error: " $line -ForegroundColor Red
        write-host "Exiting Script because of status: " $status -ForegroundColor Red
        write-host "Exiting Script because of message: " $msg -ForegroundColor Red
    }

    if ($status -eq "success") {
        check_or_exit("1")
    }
}
 

# Define Good / Bad function. If input then ok, else fault
function check_or_exit ($inputforfunction) {
                    
    if ($inputforfunction) {
        write-host @greenCheck 
        write-host `t -NoNewline
    }
    elseif (!$inputforfunction) { 
        write-host @redX 
        write-host `t -NoNewline
        write-host "Exiting script...."
        exit
                                             
    }

}

# Define webrequest function to Panorama API
function do_webrequest ($inputuri) {   
    try {
        [xml]$locResult = invoke-WebRequest -Uri $inputuri 
        
    }
    catch {
        #$error = $_.Exception.Response
        $errorcode = $_.Exception.Response.StatusCode.value__
        write-host "!!!!!!!!! HTTP Exception Error :"$errorcode "!!!!!!!!!" -ForegroundColor Red
        check_faults $errorcode
    }
    
    return $locResult
}

Function gateway_logout ($query) {
    $disconnectreason = "force-logout"
    foreach ($user in $ConnectedGatewayUsers) {
        if ( $query -eq $user.username ) {
            write-host "disconnecting from gateway: " $user.username $user.firewall $user.portal
            #$gp_uri ="https://$($user.firewall)/api/?type=op&cmd=<request><global-protect-gateway><client-logout><user>$($user.username)</user><reason>$($disconnectreason)</reason></client-logout></global-protect-gateway></request>&key=$($key)"
            $gp_uri = "https://$($user.firewall)/api/?type=op&cmd=<request><global-protect-gateway><client-logout><computer>$($user.computer)</computer><gateway>$($user.portal)</gateway><user>$($user.username)</user><reason>$disconnectreason</reason></client-logout></global-protect-gateway></request>&key=$($key)"
            $gpgatewayresult = do_webrequest ($gp_uri)
            #$gpgatewayresult.response.result.response
            check_faults_v2 -line $gpgatewayresult.response.result.response.user -status $gpgatewayresult.response.result.response.status  -msg $gpgatewayresult.response.result.response.error 
            write-host $gpgatewayresult.response.result.response.status $gpgatewayresult.response.result.response.user    $gpgatewayresult.response.result.response.error 
        }
    } 
}
function refresh_devices {
    # list connected devices
    $inputuri = "https://$($Panorama)/api/?key=$($key)&type=op&cmd=<show><devices><connected></connected></devices></show>"
    $webresult = do_webrequest ($inputuri)
    $devices = $webresult.response.result.devices
    return $devices
}

function refresh_info() {
    
    $devices = refresh_devices
    
    $TotalCount = @{} 
    $TotalCount.connectedgateway = 0
    $TotalCount.connectedportal = 0
    $TotalCount.previousgateway = 0
    
    # Reset Variables
    $ConnectedGatewayUsers.Clear()
    $PreviousGatewayUsers.Clear()
    $ConnectedPortalUsers.Clear()

    foreach ($device in $devices.entry) {
        
        $device.hostname += $domainsuffix

        write-host `n"Hostname: " -NoNewline 
        write-host $device.hostname `t -nonewline -ForegroundColor Green 
        write-host "Serial: " $device.serial 
        
        #write-host "Operational Mode: " -nonewline 
        #write-host $device.'operational-mode' `t -ForegroundColor Green -nonewline
                
        # }
        if ($device.'operational-mode' -ne "normal") {
            write-host "Operational Mode: " -NoNewline
            write-host $device.'operational-mode' `t -ForegroundColor Yellow 
                
        }
        if ($device.'operational-mode' -eq "normal") {
            # Only get other config on active device
            write-host "Operational Mode: " -NoNewline
            write-host $device.'operational-mode' `t -ForegroundColor Green 
            
            
            # List Gateways
            #$gp_uri = "https://$($device.hostname)/api/?type=op&cmd=<show><global-protect-gateway><gateway></gateway></global-protect-gateway></show>&key=$($key)"
            $gp_uri = "https://$($panorama)/api/?type=op&cmd=<show><global-protect-gateway><gateway></gateway></global-protect-gateway></show>&key=$($key)&target=$($device.serial)"
            $gpresult = do_webrequest ($gp_uri)
            foreach ($gpgateway in $gpresult.response.result.entry) {
                write-host "Gateway: " $gpgateway.'gateway-name'    
                
                
                # List connected Users in Gateway 
                #$gp_uri = "https://$($device.hostname)/api/?type=op&cmd=<show><global-protect-gateway><current-user><gateway>$($gpgateway.'gateway-name')</gateway></current-user></global-protect-gateway></show>&key=$($key)"
                $gp_uri = "https://$($panorama)/api/?type=op&cmd=<show><global-protect-gateway><current-user><gateway>$($gpgateway.'gateway-name')</gateway></current-user></global-protect-gateway></show>&key=$($key)&target=$($device.serial)"
                $gpresult = do_webrequest ($gp_uri)
                
                write-host `t "Active Gateway Users: " -nonewline
                write-host $gpresult.response.result.ChildNodes.count -ForegroundColor blue
                $TotalCount.connectedgateway += $gpresult.response.result.ChildNodes.count
                foreach ($gp_user in $gpresult.response.result.entry) {
                    
                    $ConnectedGatewayUsers.Add([ConnectedGatewayUser]::new($gp_user.'username' , `
                                $gp_user.'primary-username' , `
                                $gp_user.'computer' , `
                                $gp_user.'client' , `
                                $gp_user.'vpn-type' , `
                                $gp_user.'virtual-ip' , `
                                $gp_user.'virtual-ipv6' , `
                                $gp_user.'public-ip' , `
                                $gp_user.'public-ipv6' , `
                                $gp_user.'tunnel-type' , `
                                $gp_user.'public-connection-ipv6' , `
                                $gp_user.'login-time' , `
                                $gp_user.'login-time-utc' , `
                                $gp_user.'lifetime' , `
                                $device.hostname , `
                                $gpgateway.'gateway-name' , `
                                $gpgateway.'portal')
                    ) 
                }
    
                # List previous Users in Gateway 
                #$gp_uri = "https://$($device.hostname)/api/?type=op&cmd=<show><global-protect-gateway><previous-user><gateway>$($gpgateway.'gateway-name')</gateway></previous-user></global-protect-gateway></show>&key=$($key)"
                $gp_uri = "https://$($panorama)/api/?type=op&cmd=<show><global-protect-gateway><previous-user><gateway>$($gpgateway.'gateway-name')</gateway></previous-user></global-protect-gateway></show>&key=$($key)&target=$($device.serial)"
                $gpresult = do_webrequest ($gp_uri)
                
                write-host `t "Previous Gateway Users: " -nonewline
                write-host $gpresult.response.result.ChildNodes.count -ForegroundColor blue
                #$TotalCount.previousgateway += $gpresult.response.result.ChildNodes.count
                foreach ($gp_previoususer in $gpresult.response.result.entry) {
                    #write-host `t $gp_user.'username'  $gp_user.'virtual-ip'  $gp_user.'public-ip'  $gp_user.'computer'  $gp_user.'login-time'
                    $PreviousGatewayUsers.Add([PreviousGatewayUser]::new($gp_previoususer.'username' , `
                                $gp_previoususer.'primary-username' , `
                                $gp_previoususer.'computer' , `
                                $gp_previoususer.'client' , `
                                $gp_previoususer.'vpn-type' , `
                                $gp_previoususer.'virtual-ip' , `
                                $gp_previoususer.'virtual-ipv6' , `
                                $gp_previoususer.'public-ip' , `
                                $gp_previoususer.'public-ipv6' , `
                                $gp_previoususer.'tunnel-type' , `
                                $gp_previoususer.'public-connection-ipv6' , `
                                $gp_previoususer.'login-time' , `
                                $gp_previoususer.'login-time-utc' , `
                                $gp_previoususer.'lifetime' , `
                                $device.hostname , `
                                $gpgateway.'gateway-name')) 
                }
    
            }
    
    
            # List Portals
            #$gp_uri = "https://$($device.hostname)/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect/global-protect-portal&key=$($key)"
            $gp_uri = "https://$($panorama)/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect/global-protect-portal&key=$($key)&target=$($device.serial)"
            $gpresult = do_webrequest ($gp_uri)  
            foreach ($gpportal in $gpresult.response.result.'global-protect-portal'.entry) {
                Write-Host "GP Portal: " -nonewline
                write-host $gpportal.name
            
                #$DevicePortals.Add([DevicePortal]::new($gpportal.name , `
                #            $device.hostname , $device.serial  ))
                $DevicePortals.Add([DevicePortal]::new($gpportal.name , `
                            $device.hostname , `
                            $device.serial  ))
            
            }
             
            $deviceportals | Sort-Object


                
                
    
            # List Portal Users
            #$gp_uri = "https://$($device.hostname)/api/?type=op&cmd=<show><global-protect-portal><current-user></current-user></global-protect-portal></show>&key=$($key)"
            $gp_uri = "https://$($panorama)/api/?type=op&cmd=<show><global-protect-portal><current-user></current-user></global-protect-portal></show>&key=$($key)&target=$($device.serial)"

            $gpresult = do_webrequest ($gp_uri)
            write-host `t "Active Portal Users: " -nonewline 
            write-host $gpresult.response.result.'gp-portal-users'.ChildNodes.count -ForegroundColor Blue
            $TotalCount.connectedportal += $gpresult.response.result.'gp-portal-users'.ChildNodes.count
                
            foreach ($gp_user in $gpresult.response.result.'gp-portal-users'.user) {
                #write-host `t $gp_user.'username'  $gp_user.'client-ip' $gp_user.'sess-start-time'
                $ConnectedPortalUsers.Add([ConnectedPortalUser]::new($gp_user.'gp-portal-name' , `
                            $gp_user.'vsys-id', `
                            $gp_user.'username', `
                            $gp_user.'session-id', `
                            $gp_user.'client-ip', `
                            $gp_user.'sess-start-time', `
                            $gp_user.'inactivity-timeout', `
                            $gp_user.'sec-before-inactivity-timeout', `
                            $gp_user.'login-lifetime', `
                            $gp_user.'sec-before-login-lifetime', `
                            $gp_user.'size-of-ck-cache', `
                            $device.hostname)) 
            }
    
            
        }
        if ($device.'operational-mode' -ne "normal") {
            write-host "Device mode: " -nonewline
            write-host $device.'operational-mode' -ForegroundColor Red
        }
    
    }
    
    $unique = $PreviousGatewayUsers | Select-Object username -Unique
    $TotalCount.previousgateway = $unique.count
    pause
    return $TotalCount
}
    
function DisplayConnectedGatewayUsers() {    
    # LIST CONNECTED GATEWAY USERS
    Write-host `n"Gateway connected users:" -ForegroundColor Yellow
    $ConnectedGatewayUsers | sort-object username | Format-Table -Property username, computer, virtual_ip, public_ip, tunnel_type, login_time, gateway, portal, client
    <#foreach ($connecteduser in $ConnectedGatewayUsers) {
            
            write-host  $connecteduser.username `t `t `t `t `
                $connecteduser.firewall `t `
                $connecteduser.gateway `t `
                $connecteduser.login_time `t `
                "virtual ip" $connecteduser.virtual_ip `t `
                "public ip" `t $connecteduser.public_ip
        }#>
}
    
    
    
function DisplayConnectedPortalUsers() { 
    # LIST CONNECTED PORTAL USERS
    Write-host `n"Portal connected users:" -ForegroundColor Yellow
    $ConnectedPortalUsers | format-table
    <#foreach ($ConnectedPortalUser in $ConnectedPortalUsers) {
            write-host  $ConnectedPortalUser.username `t `t `t `t `
                $ConnectedPortalUser.firewall `t `
                $connectedportaluser.gp_portal_name 
        }
        write-host `n 
        #>
} 
    
function DisplayPreviousGatewayUsers() {  
    # LIST PREVIOUS GATEWAY USERS
    Write-host `n"Gateway previous users:" -ForegroundColor Yellow
    $PreviousGatewayUsers | sort-object username | Format-Table -Property username, computer, virtual_ip, public_ip, tunnel_type, login_time, gateway, portal, client
    <#foreach ($PreviousGatewayUser in $PreviousGatewayUsers) {
            write-host  $PreviousGatewayUser.username `t `t `t `t `
                $PreviousGatewayUser.firewall `t `
                $PreviousGatewayUser.gateway `t `
                $PreviousGatewayUser.login_time `t `
                "virtual ip" $PreviousGatewayUser.virtual_ip `t `
                "public ip" `t `t $PreviousGatewayUser.public_ip
        }#>
    
}

function request_ticket() { 
    <#
        .SYNOPSIS
        Short description
        
        .DESCRIPTION
        Long description
        
        .PARAMETER username
        Parameter description
        
        .EXAMPLE
        An example
        
        .NOTES
        General notes
        #>
              
    param 
    (
        [Parameter(Mandatory = $true)][String]$portal,
        [Parameter(Mandatory = $true)][String]$firewall,
        [Parameter(Mandatory = $true)][String]$duration,
        [Parameter(Mandatory = $true)][String]$request_id
    )

    
    
    #$gp_uri = "https://$($firewall)/api/?type=op&cmd=<request><global-protect-portal><ticket><portal>$($portal)</portal><duration>$($duration)</duration><request>$($request_id)</request></ticket></global-protect-portal></request>&key=$($key)"
    $gp_uri = "https://$($panorama)/api/?type=op&cmd=<request><global-protect-portal><ticket><portal>$($portal)</portal><duration>$($duration)</duration><request>$($request_id)</request></ticket></global-protect-portal></request>&key=$($key)&target=$($device.serial)"
    $gpresult = do_webrequest ($gp_uri)  
    check_faults_v2 -status $gpresult.response.status 
    
    $latest_ticket = $gpresult.response.result
    
    write-host $latest_ticket  -ForegroundColor Yellow
    pause
    

            
}
        
#endregion





####################################################################################
# START ACTUAL SCRIPT
####################################################################################
#region script initiation

#get api key 
# curl -k -X GET 'https://<firewall>/api/?type=keygen&user=<username>&password=<password>'
# $apikeyrequest=Invoke-WebRequest -Method Get 'https://panorama.address.local/api/?type=keygen&user=********&password=*******'

write-host "Date: "$date

$total = refresh_info

# Do MENU
do {
    clear-host  
    write-host "--------------------Main Menu--------------------------------------"
    write-host "1. Show Connected Gateway Users:" -NoNewline
    write-host $Total.connectedgateway -foregroundcolor blue
    write-host "2. Show Previous Gateway Users:" -NoNewline 
    write-host $Total.previousgateway -foregroundcolor blue
    write-host "3. Show Connected Portal Users:" -NoNewline 
    write-host $Total.connectedportal -foregroundcolor blue
    write-host ""
    write-host "4. Refresh info"
    write-host ""
    write-host "5. Disconnect specific user from Gateway"
    write-host "6. Request Ticket " 
    write-host ""
    write-host "Q. Quit"
    write-host ""
    write-host "-------------------------------------------------------------------"

    $inputkey = Read-Host "Please make a selection"
    switch ($inputkey) {
        '1' {
            # 1. Show Connected Gateway Users
            DisplayConnectedGatewayUsers
            pause
        }
        
        '2' {
            # 2. Show Previous Gateway Users
            DisplayPreviousGatewayUsers
            pause
        }

        '3' {
            # 3. Show Connected Portal Users
            DisplayConnectedPortalUsers
            pause
        }
        '4' {
            # 4. Refresh info
            refresh_info
            
        }
        '5' {
            # 5. Disconnect specific user from Gateway
            $readinput = Read-Host -Prompt "Enter Username to be disconnected"
            if ($readinput) {
                gateway_logout($readinput)
            }
            if (!$readinput) {
                write-host "No input entered !" -ForegroundColor Red
                pause
            }
            pause
        }
                
        '6' {
            # 6. Request Ticket
            write-host "Portals: "
            foreach ($DevicePortal in $DevicePortals) {
                write-host $DevicePortal.firewall ":" -NoNewline
                write-host $DevicePortal.name $deviceportal.serial -ForegroundColor Blue
            }
            $firewallname = Read-Host -Prompt "Enter Firewall name"
            $duration = read-host -prompt "Enter duration in Minutes"
            $request_id = Read-Host -Prompt "Enter Request in format 1111-1111"
            #foreach ($DevicePortal in $DevicePortals) {
            if ($firewallname -eq $DevicePortal.name) {
                write-host "Requesting ticket...." -NoNewline
                request_ticket -firewall $DevicePortal.serial -portal $userportal -duration $duration -request_id $request_id

            }
            #}
            

        }    
    }
}
until ($inputkey -eq 'q')

#endregion







