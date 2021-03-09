####################################################################################
# PALO ALTO import Office 365 WorldWide Region Addresses from Remote Location and Import to Palo Alto`
#
#
# https://live.paloaltonetworks.com/t5/general-articles/globalprotect-optimizing-office-365-traffic/ta-p/319669#
# https://docs.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
# https://docs.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service?view=o365-worldwide
#
# 
#
# This script does the following steps;
# 1 Download the Addresses File from Microsoft
# 2 Determines the Address Groups and gets its members
# 3 Remove the members from Address Group
# 4 Remove the member objects
# 5 Add objects and add to group, ONLY IP Addresses NO URLS !!!!
# 6 Commit to Panorama
# 7 Commit to Devicegroup
# 
# Gemaakt door: Sebastian van Dijk
# Gemaakt op: 27-11-2018
# 
####################################################################################

# https://www.paloaltonetworks.com/documentation/81/pan-os/cli-gsg/use-the-cli/load-configurations/load-a-partial-configuration/xpath-location-formats-determined-by-device-configuration

####################################################################################
# SETTINGS
####################################################################################
#region settings
#below code ignores untrusted certificate
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
#endregion


####################################################################################
# VARIABLES
####################################################################################
#region variables

# Import variables

# API Key PAN_API user
$key = $PaloAlto_api_key  #ENTER YOUR API KEY HERE

# Panorama Server
$panorama = "panorama.address.local"

# Device Group
$devicegroup = "Azure"

# Office 365 Group
$Office365Group = "ADG_Office365-WorldWide"

# Get the Date
$date = Get-Date

# webservice root URL
$microsofturl = "https://endpoints.office.com"

# path where client ID and latest version number will be stored
$datapath = $Env:TEMP + "\endpoints_clientid_latestversion.txt"
$testfile = $Env:TEMP + "\endpoints_export.txt"

$scripttag = "ScriptGenerated"
$objecttag = "Office365"
$grouptag = "Office365Group"

# Faultcode array 
# Source: https://www.paloaltonetworks.com/documentation/71/pan-os/xml-api/pan-os-xml-api-error-codes
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

# Define Green and Red checkmarks for CLI response
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

<#
Class AzureOfficeGroup {
    [string]$serviceArea
    [string]$category

    AzureOfficeGroup (  [string]$serviceArea , `
            [string]$category  ) {
    
        $this.serviceArea = $serviceArea
        $this.category = $category
        
    }

}
#>

#$AzureOfficeGroups = New-Object "System.Collections.Generic.List[AzureOfficeGroup]" 
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

    #    foreach ($fault in $faultcodes) {
    #								if ($fault[0] -eq $code) {
    if ($code -ne "19") {
        if ($code -ne "20") {
            if ($code -ne "7") {
                if ($code -ne "10") {
                Write-Host "!!!!!!! FAULT !!!!!!! " -ForegroundColor Red
                Write-Host "Exiting Script because of code: " $code -ForegroundColor Red
                if ($status) { Write-Host "Exiting Script because of status: " $status -ForegroundColor Red }
                else { Write-Host "Exiting Script because of status: " $faultcodes[$code][1] -ForegroundColor Red }
                if ($msg) { write-host "Exiting Script because of message: " $msg -ForegroundColor Red }
                else { Write-Host "Exiting Script because of message: " $fault[2] -ForegroundColor Red }
                if ($line) { write-host "Line:" $line }
                check_or_exit
            }	  
        }  
        } 
    } 
    if ($code -eq "19") {
        check_or_exit("1")
                
    }
    if ($code -eq "20") {
        check_or_exit("1")
                
    }
    if ($code -eq "7") {
        Write-Host "code:"$faultcodes[$code][0] -ForegroundColor yellow
        Write-Host "type:"$faultcodes[$code][1] -ForegroundColor yellow
        Write-Host "description:"$faultcodes[$code][2] -ForegroundColor yellow
        check_or_exit("1")
    }
    if ($code -eq "10") {
        Write-Host "code:"$faultcodes[$code][0] -ForegroundColor yellow
        Write-Host "type:"$faultcodes[$code][1] -ForegroundColor yellow
        Write-Host "description:"$faultcodes[$code][2] -ForegroundColor yellow
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
        $errorvalue = $_.Exception.Response.StatusCode.value__
        write-host "!!!!!!!!! HTTP Exception Error :"$errorvalue "!!!!!!!!!" -ForegroundColor Red
        check_faults $errorvalue
    }
    
    return $locResult
}

# Check for running jobs
function job_check ($job_id) {
    #$uri = "https://panorama.address.local/api/?type=op&cmd=<show><jobs><processed></processed></jobs></show>&key=$key"
    $uri = "https://$($panorama)/api/?type=op&cmd=<show><jobs><id>$($job_id)</id></jobs></show>&key=$($key)"
    
    while ($jobstatus.response.result.job.status -ne "FIN" ) {
        while ($jobstatus.response.result.job.result -ne "OK") {
            Start-Sleep -s 2
            [xml]$jobstatus = do_webrequest $uri
            Write-host "Waiting for Job to complete: " $jobstatus.response.result.job.id $jobstatus.response.result.job.type $jobstatus.response.result.job.status $jobstatus.response.result.job.result -ForegroundColor Magenta
        }
    }
    check_or_exit($jobstatus.response.result.job.result)
    Write-host "Job completed: " $jobstatus.response.result.job.id $jobstatus.response.result.job.type $jobstatus.response.result.job.status $jobstatus.response.result.job.result -ForegroundColor Green "`n"
}





#endregion

####################################################################################
# START ACTUAL SCRIPT
####################################################################################
#region script initiation
#get api key 
# curl -k -X GET 'https://<firewall>/api/?type=keygen&user=<username>&password=<password>'
# $apikeyrequest=Invoke-WebRequest -Method Get 'https://panorama.address.local/api/?type=keygen&user=xxxxx&password=******'

clear-host

#Checking key
if (!($key)) {
    write-host "no key found !!!" -Foreground Red
    write-host "key:" $key
    exit
}

# fetch client ID and version if data file exists; otherwise create new file
if (Test-Path $datapath) {
    write-host "Found existing file:"$datapath
    $content = Get-Content $datapath
    $clientRequestId = $content[0]
    $lastVersion = $content[1]
}
else {
    write-host "Did not found existing file so creating:"$datapath
    $clientRequestId = [GUID]::NewGuid().Guid
    $lastVersion = "0000000000"
    @($clientRequestId, $lastVersion) | Out-File $datapath
}

# call version method to check the latest version, and pull new data if version number is different
write-host "Checking Microsoft URL:"$microsofturl + "/version/Worldwide?clientRequestId=" + $clientRequestId
$version = Invoke-RestMethod -Uri ($microsofturl + "/version/Worldwide?clientRequestId=" + $clientRequestId) 

#if ($version.latest -gt $lastVersion) {
Write-Host "Version of Office 365 worldwide commercial service instance endpoints detected: Old:$lastversion New:$version"
$AddQuestion = Read-Host -Prompt "Continue?[y/n]"
if ( $AddQuestion -match "[yY]" ) { 


    # write the new version number to the data file
    @($clientRequestId, $version.latest) | Out-File $datapath

    # invoke endpoints method to get the new data
    $endpointSets = Invoke-RestMethod -Uri ($microsofturl + "/endpoints/Worldwide?clientRequestId=" + $clientRequestId)

    $endpointsets | out-file $testfile
    # find serviceareas groups and define tags
    foreach ($endpoint in $endpointSets) {
    
        #Define groups
        [array]$AzureOfficeGroups = $AzureOfficeGroups + ("Office365" + $endpoint.serviceArea + $endpoint.category)

        #Define Service Area Tags
        [array]$ServiceAreaTags = $ServiceAreaTags + $endpoint.serviceArea
    
        #Define Category Tags
        [array]$CategoryTags = $CategoryTags + $endpoint.category
    }
    
    $AzureOfficeGroups = $AzureOfficeGroups | sort-object -Unique
    $ServiceAreaTags = $ServiceAreaTags | sort-object -Unique
    $CategoryTags = $CategoryTags | sort-object -Unique

    #endregion

    ####################################################################################
    # Create Tags
    ####################################################################################
    #region tags
    foreach ($ServiceAreaTag in $ServiceAreaTags) {
        # Create Object
        write-host "Creating ServiceAreaTag:"$ServiceAreaTag -nonewline
        $element = "<comments>Created by Powershell Script on $($date) AzureOffice365Tags</comments>"
        $panapi_uri = "https://$($panorama)/api/?type=config&action=set&xpath=/config/shared/tag/entry[@name='$($ServiceAreaTag)']&element=$element&key=$($key)"
        $panapiresult = do_webrequest ($panapi_uri)
        check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
        write-host "`n"
    }

    foreach ($CategoryTag in $CategoryTags) {
        # Create Object
        write-host "Creating CategoryTag:"$CategoryTag -nonewline
        $element = "<comments>Created by Powershell Script on $($date) AzureOffice365Tags</comments>"
        $panapi_uri = "https://$($panorama)/api/?type=config&action=set&xpath=/config/shared/tag/entry[@name='$($CategoryTag)']&element=$element&key=$($key)"
        $panapiresult = do_webrequest ($panapi_uri)
        check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
        write-host "`n"
    }

    # scripttag
        
    write-host "Creating CategoryTag:"$scripttag -nonewline
    $element = "<comments>Created by Powershell Script on $($date) AzureOffice365Tags</comments>"
    $panapi_uri = "https://$($panorama)/api/?type=config&action=set&xpath=/config/shared/tag/entry[@name='$($scripttag)']&element=$element&key=$($key)"
    $panapiresult = do_webrequest ($panapi_uri)
    check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
    write-host "`n"

    # objecttag
        
    write-host "Creating CategoryTag:"$objecttag -nonewline
    $element = "<comments>Created by Powershell Script on $($date) AzureOffice365Tags</comments>"
    $panapi_uri = "https://$($panorama)/api/?type=config&action=set&xpath=/config/shared/tag/entry[@name='$($objecttag)']&element=$element&key=$($key)"
    $panapiresult = do_webrequest ($panapi_uri)
    check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
    write-host "`n"

    # grouptag
        
    write-host "Creating CategoryTag:"$grouptag -nonewline
    $element = "<comments>Created by Powershell Script on $($date) AzureOffice365Tags</comments>"
    $panapi_uri = "https://$($panorama)/api/?type=config&action=set&xpath=/config/shared/tag/entry[@name='$($grouptag)']&element=$element&key=$($key)"
    $panapiresult = do_webrequest ($panapi_uri)
    check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
    write-host "`n"
    #endregion

    ####################################################################################
    # Find groups and members and remove them from Panorama
    ####################################################################################
    #region remove
    $AddQuestion = Read-Host -Prompt "Do Remove Action?[y/n]"
    if ( $AddQuestion -match "[yY]" ) { 

        # Create or update type WorldwideGroup
        Write-Host "Updating Dynamic Address Group: $AddressGroupObject with $grouptag" -ForegroundColor Blue -NoNewline
        $xpath = "/config/shared/address-group/entry[@name='$($Office365Group)']"
        $element = "<dynamic>"
        $element += "<filter>$($grouptag)</filter>"
        $element += "</dynamic>"
        $element += "<description>Created by Powershell Script on $($date)</description>"
        $panapi_uri = "https://$($panorama)/api/?type=config&action=set&key=$key&xpath=$xpath&element=$element"
        $panapiresult = do_webrequest ($panapi_uri)
        check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg



        #Start removing members of these groups
        foreach ($AzureOfficeGroup in $AzureOfficeGroups) {
        
            # Get current objects in this Group
            Write-Host "Get current objects in Group:" -nonewline
            write-host $AzureOfficeGroup -ForegroundColor blue
            $xpath = "/config/shared/address-group/entry[@name='$($AzureOfficeGroup)']"
            $panapi_uri = "https://$($panorama)/api/?type=config&action=get&key=$key&xpath=$xpath"
            $panapiresult = do_webrequest ($panapi_uri)
            $panapiresult.response.result.entry.static.member

            # Remove Objects from type group
            write-host "Removing members in group " -nonewline
            write-host $AzureOfficeGroup -ForegroundColor blue
            $deleteditems = 0
            foreach ($member in $panapiresult.response.result.entry.static.member) {
                $deleteditems++
                #write-host "Deleting member:"  $member.'#text' "from group $AzureOfficeGroup"  -nonewline
                write-host "Deleting member:"  $member "from group $AzureOfficeGroup"  -nonewline
                $xpath = "/config/shared/address-group/entry[@name='$($AzureOfficeGroup)']/static/member[text()='$($member)']"
                $panapi_uri = "https://$($panorama)/api/?type=config&action=delete&key=$key&xpath=$xpath"
                $panapiresult = do_webrequest ($panapi_uri)
                check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
  
                start-sleep -Seconds 1

                # Remove Object
                write-host "Deleting object:" $member -nonewline
                $panapi_uri = "https://$($panorama)/api/?type=config&action=delete&xpath=/config/shared/address/entry[@name='$($member)']&element=$element&key=$($key)"
                $panapiresult = do_webrequest ($panapi_uri)
                check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg

                write-host "`n"
      
            }
            write-host "`t Deleted members: $deleteditems"
            write-host "`n"

        }
    }
    #endregion

    ####################################################################################
    # Find groups and members and add them to Panorama
    ####################################################################################
    #region  addobjects
    $AddQuestion = Read-Host -Prompt "Do Add Action?[y/n]"
    if ( $AddQuestion -match "[yY]" ) { 

        write-host "Starting to add objects....."
        # For all entries
        foreach ($endpoint in $endpointSets) {
            # Foreach entry containing IP addresses
            if ($endpoint.ips) {
                Write-Host "`n Found:" "ID:"$endpoint.id "Service:"$endpoint.serviceArea "IPs:"$endpoint.ips -ForegroundColor green

                $AddressGroupObject = ("Office365" + $endpoint.serviceArea + $endpoint.category)
            
                # Add prefixes for this entry
                foreach ($prefix in $endpoint.ips) {
                    #$AddressObject = "AZR-" + $entry.name + "-" + $prefix
                    $AddressObject = $endpoint.serviceArea + $prefix
         
                    # replace / by - 
                    $AddressObject = $AddressObject.Replace("/", "-")
            
                    # for ipv6 replace :: to __ to _
                    $AddressObject = $AddressObject.Replace(":", "_")
                    $AddressObject = $AddressObject.Replace("__", "_")

                    Write-Host "`t Creating Object:$AddressObject " -ForegroundColor Yellow -NoNewline
            
                    # Do maximum object length limit check
                    if (($AddressObject | Measure-Object -Character).Characters -gt 63) { 
                        Write-Host "Warning !!! Object name longer that 63 characters !!"
                        Pause
                        exit
                    }

                    # Create Object
                    $element = "<ip-netmask>$($prefix)</ip-netmask>"
                    $element += "<tag>"
                    $element += "<member>$($endpoint.serviceArea)</member>"
                    $element += "<member>$($endpoint.category)</member>"
                    $element += "<member>$($scripttag)</member>"
                    $element += "<member>$($objecttag)</member>"
                    $element += "</tag>"
                    $element += "<description>Created by Powershell Script on $($date)</description>"
                    $panapi_uri = "https://$($panorama)/api/?type=config&action=set&xpath=/config/shared/address/entry[@name='$($AddressObject)']&element=$element&key=$($key)"
                    $panapiresult = do_webrequest ($panapi_uri)
                    check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
          
                
                    # Create or update type Group
                    Write-Host "`t `t Adding Object $AddressObject to Address Group: $AddressGroupObject " -ForegroundColor Blue -NoNewline
                    $xpath = "/config/shared/address-group/entry[@name='$($AddressGroupObject)']"
                    $element = "<static>"
                    $element += "<member>$($AddressObject)</member>"
                    $element += "</static>"
                    $element += "<tag>"
                    $element += "<member>$($endpoint.serviceArea)</member>"
                    $element += "<member>$($endpoint.category)</member>"
                    $element += "<member>$($scripttag)</member>"
                    $element += "<member>$($grouptag)</member>"
                    $element += "</tag>"
                    $element += "<description>Created by Powershell Script on $($date)</description>"
                    $panapi_uri = "https://$($panorama)/api/?type=config&action=set&key=$key&xpath=$xpath&element=$element"
                    $panapiresult = do_webrequest ($panapi_uri)
                    check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
            
                    write-host "`n"
                    #            start-sleep -Milliseconds 200
                }    
    
            
            }
        }
    }
    #endregion
}
#}

####################################################################################
#commit to Panorama
####################################################################################
#region commitpanorama
$CommitQuestion = Read-Host -Prompt "Commit to Panorama?[y/n]"
if ( $CommitQuestion -match "[yY]" ) { 

    Write-Host "Committing to Panorama..." -nonewline
    $uri = "https://$($panorama)/api/?type=commit&cmd=<commit></commit>&key=$($key)"
    #[xml]$result = do_webrequest $uri
    $result = do_webrequest $uri
    check_faults_v2 -code $result.response.code
    Write-Host ""
    Write-Host "Commit Status: " $result.response.status
    Write-Host "Commit Code: " $result.response.code
    Write-Host "Commit Message: " $result.response.msg `n 

    # If no changes do not check for job status
    $RunningJob = $result.response.result.job
    if ($RunningJob) { job_check ($RunningJob) }
}
#endregion

####################################################################################
# Commit to $devicegroup Device Group
####################################################################################
#region commitdevices
$CommitQuestion = Read-Host -Prompt "Push to Devices?[y/n]"
if ( $CommitQuestion -match "[yY]" ) { 

    Write-Host "Committing to DeviceGroup Datacenter..." -nonewline
    $uri = "https://$($panorama)/api/?type=commit&action=all&cmd=<commit-all><shared-policy><device-group><entry name='$($devicegroup)'/></device-group></shared-policy></commit-all>&key=$($key)"
    [xml]$result = do_webrequest $uri
    check_faults_v2 -code $result.response.code
    Write-Host ""
    Write-Host "Commit Device Group Status: " $result.response.status
    Write-Host "Commit Device Group Code: " $result.response.code
    Write-Host "Commit Device Group Message: " $result.response.msg `n 

    # If no changes do not check for job status
    $RunningJob = $result.response.result.job
    if ($RunningJob) { job_check ($RunningJob) }
} 

#endregion

write-host "Finished" -foreground green    
    
