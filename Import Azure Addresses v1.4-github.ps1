####################################################################################
# PALO ALTO import Azure Addresses from XML file
#
# This script does te following steps;
# 1 read the Microsoft JSON
# 2 find all groups for the entered region
# 3 use these groups to get their members from Panorama
# 4 delete all the members from the group
# 5 for each entry matching the region create the member and add to the corresponding group
# 6 add all regional groups to 1 region group
# 7 commit to Panorama
# 8 commit to devices
#
# Gemaakt door: Sebastian van Dijk
# Gemaakt op: 27-11-2018
# 
# OLD Source for XML file : https://www.microsoft.com/en-sa/download/confirmation.aspx?id=41653
# NEW Source for JSON file: https://www.microsoft.com/en-us/download/details.aspx?id=56519
#
####################################################################################

# https://www.paloaltonetworks.com/documentation/81/pan-os/cli-gsg/use-the-cli/load-configurations/load-a-partial-configuration/xpath-location-formats-determined-by-device-configuration

Clear-Host

####################################################################################
# SETTINGS
####################################################################################
#region settings

# SET TLS version
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#below code ignores untrusted certificate
Add-Type @"
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
# Import my settings

# API Key PAN_API user
$key = $PaloAlto_api_key  #ENTER YOUR API KEY HERE

# Azure Addresses Filename
$filename = "C:\somewhere\ServiceTags_Public_20210104.json"

$panorama = "panorama.address.local"
$devicegroup = "Azure"
$addressgroupprefix = "ADG_"
$tag = "ScriptGenerated"

# Get the Date
$date = Get-Date

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
    NoNewLine       = $false
}
$redX = @{
    Object          = [Char]88
    ForegroundColor = 'Red'
    NoNewLine       = $false
}


#endregion

####################################################################################
# FUNCTIONS
####################################################################################
#region Functions
# Define function to match faultcodes to the returned faultcode and prints faultcode when not Success


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
    if ($code -eq "19") {
        check_or_exit("1")
                
    }
    if ($code -eq "20") {
        check_or_exit("1")
                
    }
    if ($code -eq "7") {
        Write-Host "code:"$faultcodes[7][0] -ForegroundColor yellow
        Write-Host "type:"$faultcodes[7][1] -ForegroundColor yellow
        Write-Host "description:"$faultcodes[7][2] -ForegroundColor yellow
        check_or_exit("1")
    }
}
								

#    }
#}
 

# Define Good / Bad function. If input then ok, else fault
function check_or_exit ($inputforfunction) {
                    
    if ($inputforfunction) {
        Write-Host @greenCheck 
        Write-Host `t -NoNewline
    }
    elseif (!$inputforfunction) { 
        Write-Host @redX 
        Write-Host `t -NoNewline
        Write-Host "Exiting script...."
        exit
                                             
    }

}

# Define webrequest function to Panorama API
function do_webrequest ($inputuri) {   
    try {

        [xml]$locResult = Invoke-WebRequest -Uri $inputuri 
        
    }
    catch {
        #$error = $_.Exception.Response
        $errorvalue = $_.Exception.Response.StatusCode.value__
        Write-Host "!!!!!!!!! HTTP Exception Error :"$errorvalue "!!!!!!!!!" -ForegroundColor Red
        Write-Host  $_.Exception
        check_faults_v2 -code $errorvalue
        
    }
    
    return $locResult
}

# Check for running jobs
function job_check ($job_id) {
    #$uri = "https://panorama.address.locallocal/api/?type=op&cmd=<show><jobs><processed></processed></jobs></show>&key=$key"
    $uri = "https://$($panorama)/api/?type=op&cmd=<show><jobs><id>$($job_id)</id></jobs></show>&key=$($key)"
    
    
    while ($jobstatus.response.result.job.status -ne "FIN" ) {
        while ($jobstatus.response.result.job.result -ne "OK") {

            Start-Sleep -s 2
            [xml]$jobstatus = do_webrequest $uri
            Write-Host "Waiting for Job to complete: " $jobstatus.response.result.job.id $jobstatus.response.result.job.type $jobstatus.response.result.job.status $jobstatus.response.result.job.result -ForegroundColor Magenta
        }
    }
    check_or_exit($jobstatus.response.result.job.result)
    Write-Host "Job completed: " $jobstatus.response.result.job.id $jobstatus.response.result.job.type $jobstatus.response.result.job.status $jobstatus.response.result.job.result -ForegroundColor Green "`n"
}


#endregion

####################################################################################
# START ACTUAL SCRIPT
####################################################################################
#region script initiation
#get api key 
# curl -k -X GET 'https://<firewall>/api/?type=keygen&user=<username>&password=<password>'
# $apikeyrequest=Invoke-WebRequest -Method Get 'https://panorama.address.locallocal/api/?type=keygen&user=admin_XXXX&password=XXXXXX'

write-host "Starting script.."
write-host "Date:" $date
write-host "File:" $filename
write-host "Panorama:" $panorama

#Checking key
if (!($key)) {
    write-host "no key found"
    write-host "key:" $key
    exit
}

#Read JSON File 
$sourcefile = $filename.Split('\')[-1]
$AzureAddresses = Get-Content $filename | ConvertFrom-Json
if (!($AzureAddresses)) {
    write-host "File could not be opened"
    write-host "Filename:" $filename
    write-host "Sourcefile:" $sourcefile
    exit
}

# DETECT Regions
$regions = @()
foreach ($azureaddress in $AzureAddresses.values) {
    $regions += $azureaddress.properties.region 
}

$regions = $regions | sort-object | Get-Unique

write-host  "Regions Found: " $regions -ForegroundColor Yellow

$query = Read-Host -Prompt "Type Azure Region to be imported: "

# Define Azure Region Group
$AddressGroupObjectRegion = $addressgroupprefix + "Azure-" + $query

# Get groups for region from file
write-host "Getting groups from file for region $query..."
#endregion

####################################################################################
# Find groups and members and remove them from Panorama
####################################################################################
#region remove
$RemoveQuestion = Read-Host -Prompt "Do Remove Action?[y/n]"
if ( $RemoveQuestion -match "[yY]" ) { 

    # Remove typegroup members and objects
    # For all entries
    foreach ($entry in $AzureAddresses.values) {
    
        # Foreach West Europe entry...
        if ($entry.properties.region -like "*$query*") {
        
            # Define group name to be used    
            $grouptypename = $addressgroupprefix + $entry.name
            write-host "Found groups from file:" -nonewline
            write-host $grouptypename -ForegroundColor blue 

            # Get current objects in this Group
            Write-Host "Get current objects in Type Group" -nonewline
            write-host $grouptypename -ForegroundColor blue
            $xpath = "/config/shared/address-group/entry[@name='$($grouptypename)']"
            $panapi_uri = "https://$($panorama)/api/?type=config&action=get&key=$key&xpath=$xpath"
            $panapiresult = do_webrequest ($panapi_uri)
            $panapiresult.response.result.entry.static.member

            # Remove Objects from type group
            write-host "Removing members in group " -nonewline
            write-host $grouptypename -ForegroundColor blue
            $deleteditems = 0
            foreach ($member in $panapiresult.response.result.entry.static.member) {
                $deleteditems++
                write-host "Deleting member"  $member.'#text' "from group $grouptypename"  -nonewline
                $xpath = "/config/shared/address-group/entry[@name='$($grouptypename)']/static/member[text()='$($member.'#text')']"
                $panapi_uri = "https://$($panorama)/api/?type=config&action=delete&key=$key&xpath=$xpath"
                $panapiresult = do_webrequest ($panapi_uri)
                check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
        

                # Remove Object
                write-host "Deleting object " $member.'#text' -nonewline
                $panapi_uri = "https://$($panorama)/api/?type=config&action=delete&xpath=/config/shared/address/entry[@name='$($member.'#text')']&element=$element&key=$($key)"
                $panapiresult = do_webrequest ($panapi_uri)
                check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
            
            }
            write-host "`t Deleted members: $deleteditems"
            write-host "`n"
        }
    }
        
    # Get current objects in Region Group
    Write-Host "`n `n Get current objects in Region Group" -nonewline
    write-host $AddressGroupObjectRegion -ForegroundColor blue
    $xpath = "/config/shared/address-group/entry[@name='$($AddressGroupObjectRegion)']"
    $panapi_uri = "https://$($panorama)/api/?type=config&action=get&key=$key&xpath=$xpath"
    $panapiresult = do_webrequest ($panapi_uri)
    $panapiresult.response.result.entry.static.member

    # Removing current objects in Region Group
    Write-Host "Deleting current objects in Region Group" -nonewline 
    write-host $AddressGroupObjectRegion -ForegroundColor blue
    foreach ($member in $panapiresult.response.result.entry.static.member) {
        # Remove Object from group
        write-host "Deleting" -nonewline
        write-host $member.'#text' -foregroundcolor blue -nonewline
        write-host "from group " -nonewline
        write-host $AddressGroupObjectRegion -foregroundcolor blue 
        $xpath = "/config/shared/address-group/entry[@name='$($AddressGroupObjectRegion)']/static/member[text()='$($member.'#text')']"
        $panapi_uri = "https://$($panorama)/api/?type=config&action=delete&key=$key&xpath=$xpath"
        $panapiresult = do_webrequest ($panapi_uri)
        check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
    }

    # Finished removing
    write-host "`n Finished Removing `n `n"

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
    foreach ($entry in $AzureAddresses.values) {
        # Foreach West Europe entry...
        if ($entry.properties.region -like "*$query*") {
            Write-Host "`n Found:" $entry.name -ForegroundColor green
            $typegroup = $addressgroupprefix + $entry.name

            # Add prefixes for this entry
            foreach ($prefix in $entry.properties.addressPrefixes) {
                #$AddressObject = "AZR-" + $entry.name + "-" + $prefix
                $AddressObject = $entry.name + $prefix
         
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
                $element += "<member>$($tag)</member>"
                $element += "</tag>"
                $element += "<description>Created by Powershell Script on $($date) sourcefile $sourcefile </description>"
                $panapi_uri = "https://$($panorama)/api/?type=config&action=set&xpath=/config/shared/address/entry[@name='$($AddressObject)']&element=$element&key=$($key)"
                $panapiresult = do_webrequest ($panapi_uri)
                check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
          
                # Create or update type Group
                Write-Host "`t `t Adding Object $AddressObject to Address Group: $typegroup " -ForegroundColor Blue -NoNewline
                $xpath = "/config/shared/address-group/entry[@name='$($typegroup)']"
                $element = "<static>"
                $element += "<member>$($AddressObject)</member>"
                $element += "</static>"
                $element += "<tag>"
                $element += "<member>$($tag)</member>"
                $element += "</tag>"
                $element += "<description>Created by Powershell Script on $($date) sourcefile $sourcefile </description>"
                $panapi_uri = "https://$($panorama)/api/?type=config&action=set&key=$key&xpath=$xpath&element=$element"
                $panapiresult = do_webrequest ($panapi_uri)
                check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
            
                write-host "`n"
                #            start-sleep -Milliseconds 200
            }    
    
            # Create or update Region Group
            Write-Host "`t `t Adding Object $typegroup to Address Group: $AddressGroupObjectRegion " -ForegroundColor Blue -NoNewline
            $xpath = "/config/shared/address-group/entry[@name='$($AddressGroupObjectRegion)']"
            $element = "<static>"
            $element += "<member>$($typegroup)</member>"
            $element += "</static>"
            $element += "<tag>"
            $element += "<member>$($tag)</member>"
            $element += "</tag>"
            $element += "<description>Created by Powershell Script on $($date) sourcefile $sourcefile </description>"
            $panapi_uri = "https://$($panorama)/api/?type=config&action=set&key=$key&xpath=$xpath&element=$element"
            $panapiresult = do_webrequest ($panapi_uri)
            check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
        }
    }
 


    <#
# Create or update Global Azure Group
$GlobalAddressObject = $addressgroupprefix + "Azure"
Write-Host "`n `n Updating Address Group: "$GlobalAddressObject "with address group object: "$AddressGroupObject
$xpath = "/config/shared/address-group/entry[@name='$($GlobalAddressObject)']"
$element = "<static>"
$element += "<member>$($AddressGroupObject)</member>"
$element += "</static>"
$element += "<description>Created by Powershell Script on $($date) sourcefile $sourcefile </description>"
$panapi_uri = "https://$($panorama)/api/?type=config&action=set&key=$key&xpath=$xpath&element=$element"
$panapiresult = do_webrequest ($panapi_uri)
check_faults_v2 -code $panapiresult.response.code -status $panapiresult.response.status -msg $panapiresult.response.msg
#>
}

#endregion

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
    #endregion

    ####################################################################################
    # Commit to Datacenter Device Group
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
}
#endregion

write-host "Finished" -foreground green






