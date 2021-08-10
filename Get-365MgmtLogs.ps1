<#
.SYNOPSIS
    Connect to Azure 365 management API, gets all log content types: Audit.SharePoint, Audit.Exchange, Audit.AzureActiveDirectory, Audit.General
.DESCRIPTION
    Connects to the Azure 365 Mangement API, uses multi-threading to collect all log content types. Exports each blog of data as a csv, later combines them as a single csv to match the search-UnifiedAuditLog cmdlet export csv.

    Script uses 3 functions.

    Set-SecArchiveFolders - Set's up the daily security archive folders for the log content type exports.
    Get-365MgmtLogs-API - Get's all the azure 365 management logs and exports them as per they're content type.
    Set-365MgmtLogs - Get's all the individal content types exports, combines them into a single csv.

.EXAMPLE
    Get-365MgmtLogs-API -Domain ***Domain_3*** -Service AzureActiveDirectory #Get AAD Logs for domain_3
.EXAMPLE
    Another example of how to use this cmdlet
.INPUTS
    -Domain is equal to your domain shortname or longname.
    -Service is equal to what Azure 365 Management Logs you would like to collect. E.G: Audit.SharePoint, Audit.Exchange, Audit.AzureActiveDirectory, Audit.General
.OUTPUTS
    Outputs a csv almost identical to the search-UnifiedAuditLog cmdlet, the audit data is a compressed .json within the .auditdata column in the csv.
.NOTES
    This script requires modification before running. My use-case was managing 3 tenancy's so they're ***Domain_1***, ***Domain_2***, ***Domain_3***. Find / Replace for the script for your own.
    This script assume's you are adept at reading and modifying powershell.

    You need to update the following variables and domains:
    
    $DFS_Long_Path -  A path to your DFS shares domain folder or folder location with tenancy seperation eg. \\Share1\Security\AzureLogs\Tenancy\ or C:\Data\Security\AzureLogs\Tenancy\
    $DFS_Short_Path - A path to your DFS shares domain folder or folder location eg. \\Share1\Security\AzureLogs\ or C:\Data\Security\AzureLogs\
    $LogFilePath - Path to where you want log files to be stored.
    $Date is set to 2 days in the past due to the busyness of our tenant and all log information not being avalaible within 24 hours
    $EDate  is set to 2 days in the past due to the busyness of our tenant and all log information not being avalaible within 24 hours

    ***Domain_1*** - Domain 1 variables
        $ClientID 
        $ClientSecret
        $Tenantdomain
        $TenantGUID
    ***Domain_2*** - Domain 2 variables
        $ClientID 
        $ClientSecret
        $Tenantdomain
        $TenantGUID
    ***Domain_3*** - Domain 3 variables
        $ClientID 
        $ClientSecret
        $Tenantdomain
        $TenantGUID

        Useful Ref:
        https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference

.COMPONENT
    The component this cmdlet belongs to
.ROLE
    The role this cmdlet belongs to
.FUNCTIONALITY
    The functionality that best describes this cmdlet
#>


[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 # TLS Error

#####################
# Code to setup folders for the day | Outside the function as it only needs to run once per day.
#####################

# Setup File folders for the day


$DFS_Short_Path = "\\***YourDomain***\security\SecArchive\Azure"
$DFS_Long_Path = "\\***YourDomain***\security\SecArchive\Azure\Tenancy"
$LogFilePath = "C:\Support\Logs"

$Date = Get-Date((get-date).AddDays(-2)) -Format "yyyy-MM-dd"
$EDate = Get-Date((get-date).AddDays(-2)) -Format "yyyyMMdd"

function Set-SecArchiveFolders {
    param (
        [Parameter(Mandatory = $true)]
        [String] $Service,
        [String] $Domain
    )
    switch ($Service) {
        SharePoint { 
            $ContentType = "SharePoint"
        }
        Exchange {
            $ContentType = "Exchange"
        }
        General {
            $ContentType = "General"
        }
        AzureActiveDirectory {
            $ContentType = "AzureActiveDirectory"
        }
    }
    switch ($Domain) {
        ***Domain_1*** {
            $TenancyName = "***Domain_1***"
        }
        ***Domain_2*** {
            $TenancyName = "***Domain_2***"
        }
        ***Domain_3*** {
            $TenancyName = "***Domain_3***"
        }
    }

    $DFS_Long_Path = "\\***YourDomain***\security\SecArchive\Azure\Tenancy"
    $Date = Get-Date((get-date).AddDays(-2)) -Format "yyyy-MM-dd"
    $EDate = Get-Date((get-date).AddDays(-2)) -Format "yyyyMMdd"
    $LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
    
    $LogFilePath = "C:\Support\Logs"
    
    $FolderPath = ("$DFS_Long_Path\$Domain\$ContentType")                                                              
    if (Test-Path -Path "$FolderPath\$Edate") {
        # if folder exists tell me
        $LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
        Write-Output "$LogDate : Folder $Tenancyname\$ContentType\$Edate Exist" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append
    }
    if (!(Test-Path -Path "$FolderPath\$Edate")) {
        mkdir "$FolderPath\$Edate" -Force
        mkdir "$FolderPath\$Edate\CSV" -Force
    }
    if (!(Test-Path -Path "$FolderPath\$Edate\CSV")) {
        mkdir "$FolderPath\$Edate\CSV" -Force
    }
}

Set-SecArchiveFolders -Service AzureActiveDirectory -Domain ***Domain_1***
Set-SecArchiveFolders -Service SharePoint -Domain ***Domain_1***
Set-SecArchiveFolders -Service Exchange -Domain ***Domain_1***
Set-SecArchiveFolders -Service General -Domain ***Domain_1***

Set-SecArchiveFolders -Service SharePoint -Domain ***Domain_2***
Set-SecArchiveFolders -Service Exchange -Domain ***Domain_2***
Set-SecArchiveFolders -Service General -Domain ***Domain_2***
Set-SecArchiveFolders -Service AzureActiveDirectory -Domain ***Domain_2***

Set-SecArchiveFolders -Service SharePoint -Domain ***Domain_3***
Set-SecArchiveFolders -Service Exchange -Domain ***Domain_3***
Set-SecArchiveFolders -Service General -Domain ***Domain_3***
Set-SecArchiveFolders -Service AzureActiveDirectory -Domain ***Domain_3***


function Get-365MgmtLogs-API {
    param (
        [Parameter(Mandatory = $true)]
        [String] $Service,
        [String] $Domain
    )
    switch ($Service) {
        SharePoint { 
            $ContentType = "SharePoint"
        }
        Exchange {
            $ContentType = "Exchange"
        }
        General {
            $ContentType = "General"
        }
        AzureActiveDirectory {
            $ContentType = "AzureActiveDirectory"
        }
    }
    switch ($Domain) {
        ***Domain_1*** {
            $KeyFile = "\\***YourDomain***\Path-To\A-Folder\Where-you-Can-Store-key-files\365MgmtApi_AES_***Domain_1***.key" #Didn't want to store the key in plain text, see my blog for creating a key.
            $Key = Get-Content $KeyFile
            $Txt = Get-Content "C:\Support\Scripts\365MgmtApi_AES_***Domain_1***.txt"
            $ClientID = "Client-ID-Goes-Here"
            $SecureObject = ConvertTo-SecureString -String $txt -Key $Key
            $ToBeStr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureObject)
            $ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ToBeStr) #Can just store here in plain text for testing. Not reccomended for prod, use a secure key.
            $TenancyName = "***Domain_1***"
            #If using automation account to run, I couldn't due to performance issues of the hybrid worker.
            #$ClientId = "Client-Id-Goes-Here"
            #$ClientID = Get-AutomationVariable -Name 'AuditApiClientId'
            #$ClientSecret = Get-AutomationVariable -Name 'AuditApiClientSecret'
            $tenantdomain = "***Domain_1***ernment.onmicrosoft.com"
            $TenantGUID = "Tenant-GUID-Goes-Here"

        }
        ***Domain_2*** {
            $KeyFile = "\\***YourDomain***\A Folder\Passwords\365MgmtApi_AES_***Domain_2***.key"
            $Key = Get-Content $KeyFile
            $Txt = Get-Content "C:\Support\Scripts\365MgmtApi_AES_***Domain_2***.txt"
            $ClientID = "Client-ID-Goes-Here"
            $SecureObject = ConvertTo-SecureString -String $txt -Key $Key
            $ToBeStr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureObject)
            $ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ToBeStr)
            $TenancyName = "***Domain_2***"
            #$ClientID = ""Client-Id-Goes-Here""
            #$ClientID = Get-AutomationVariable -Name 'AuditApiClientId-***Domain_2***'
            #$ClientSecret = Get-AutomationVariable -Name 'AuditApiClientSecret-***Domain_2***'
            $tenantdomain = "***Domain_2***.onmicrosoft.com"
            $TenantGUID = "Tenant-GUID-Goes-Here"
        }
        ***Domain_3*** {
            $KeyFile = "\\***YourDomain***\A Folder\Passwords\365MgmtApi_AES_***Domain_3***.key"
            $Key = Get-Content $KeyFile
            $Txt = Get-Content "C:\Support\Scripts\365MgmtApi_AES_***Domain_3***.txt"
            $ClientID = "Client-ID-Goes-Here"
            $SecureObject = ConvertTo-SecureString -String $txt -Key $Key
            $ToBeStr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureObject)
            $ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ToBeStr)
            $TenancyName = "***Domain_3***"
            #$ClientId = 'fa4afeab-04ec-4136-bec8-c7d678c48382'
            #$ClientID = Get-AutomationVariable -Name 'AuditApiClientId-***Domain_3***'
            #$ClientSecret = Get-AutomationVariable -Name 'AuditApiClientSecret-***Domain_3***'
            $tenantdomain = "***Domain_3***au.onmicrosoft.com"
            $TenantGUID = "Tenant-GUID-Goes-Here"
        }
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $DFS_Long_Path = "\\***YourDomain***\security\SecArchive\Azure\Tenancy"
    $loginURL = "https://login.microsoftonline.com/"

    # Date used for start date / end date - current day

    $Date = Get-Date((get-date).AddDays(-2)) -Format "yyyy-MM-dd"
    $EDate = Get-Date((get-date).AddDays(-2)) -Format "yyyyMMdd"

    <#
    #Get Auth Token for API - Refernce only, LISTED BELOW EACH CONTENT TYPE DUE TO TOKEN TIMEOUT
    $resource = "https://manage.office.com"
    $body = @{grant_type = "client_credentials"; resource = $resource; client_id = $ClientID; client_secret = $ClientSecret }
    $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body
    $headerParams = @{'Authorization' = "$($oauth.token_type) $($oauth.access_token)" } 
    #>

    ############################
    # Get API Data
    ############################

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    #Get Auth Token for API - Added at start of call due to token Timeout issue -1hr token timeout
    $resource = "https://manage.office.com"
    $body = @{grant_type = "client_credentials"; resource = $resource; client_id = $ClientID; client_secret = $ClientSecret }
    $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body
    $headerParams = @{'Authorization' = "$($oauth.token_type) $($oauth.access_token)" } 

    #Get Data from the API
    $RestData = Invoke-WebRequest -UseBasicParsing -Method GET -Headers $headerParams -Uri "$resource/api/v1.0/$tenantGUID/activity/feed/subscriptions/content?contentType=Audit.${ContentType}&startTime=${Date}T00:00&endTime=${Date}T23:59:59" # Note StartTime -EndTime Being 1 day.
    $Rest = @()
    $Rest += ($RestData.Content | ConvertFrom-Json)
    $NextPageUri = $RestData.Headers.'NextPageUri'

    #Get all data blobs until no new pages
    while ($null -ne $NextPageUri) {
        $RestData = Invoke-WebRequest -UseBasicParsing -Method GET -Headers $headerParams -Uri "$NextPageUri"
        $NextPageUri = $RestData.Headers.'NextPageUri'
        $Rest += ($RestData.Content | ConvertFrom-Json)

       
    }
    $LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt

    "$LogDate : " + [string]$Rest.contentUri.Count + " " + "Blobs to Process for $Domain $ContentType" | Write-Output | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

    #####################
    # MULTI-THREAD 
    #####################
    #$restUri = $Rest[1].contentUri
   
    $Counter = 0
    $MaxConcurrentJobs = '32'  #Max number of simultaneously running jobs
    foreach ($RestUri in $Rest.contentUri) {
        # Increment Counter
        $Counter++
        # Scriptblock
        $ScriptBlock = {
           
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  # Must be added otherwise job fails with TLS connection error

            #Get Auth Token for API - Added at start of call due to token Timeout issue -1hr token timeout
            $oauth = Invoke-RestMethod -Method Post -Uri $using:loginURL/$using:tenantdomain/oauth2/token?api-version=1.0 -Body $using:body
            $headerParams = @{'Authorization' = "$($oauth.token_type) $($oauth.access_token)" }
            $RestContent = (Invoke-WebRequest -UseBasicParsing -Headers $Using:headerParams -Uri "$Using:RestUri`?PublisherIdentifier=${Using:TenantGUID}").Content

            #Removed, not longer need json exports. Uncomment if you want jsons.
            #$RestContent | Out-File "$Using:ExportPath\$Using:TenancyName\$Using:ContentType\$Using:EDate\Json\Audit_$Using:ContentType-$Using:Edate-$Using:Counter.json"    
            
            $AuditContent = $RestContent | ConvertFrom-Json

            #This builds the csv output to match the powershell cmdlet output, embedd's the json into it.
            $ReportObject = @()
            $ReportObject = Foreach ($Json in $AuditContent) { 
                $CounterObj++
                $ObjProp0 = [ordered]@{    
                    PSComputerName     = "outlook.office365.com"
                    RunspaceId         = $Json.OrganizationId
                    PSShowComputerName = "$False"
                    RecordType         = $Json.workload
                    CreationDate       = [string]($json.CreationTime -replace "-", "/" -replace "T", " ")
                    UserIds            = $json.userid
                    Operations         = $json.Operation
                    AuditData          = $json | ConvertTo-Json -Depth 100 -Compress #Here is the data being stored as a json.
                    ResultIndex        = "0"
                    ResultCount        = "0"
                    Identity           = $json.id
                    IsValid            = "$True"
                    ObjectState        = "Unchanged"

                }
                New-Object -TypeName psobject -Property $ObjProp0
            }
            #Export csv
            $ReportObject | Export-csv -Path "$Using:ExportPath\$Using:TenancyName\$Using:ContentType\$Using:EDate\CSV\Audit_$Using:ContentType-$Using:Edate-$Using:Counter.csv" -Append -NoTypeInformation   

            #left here for troubleshooting
            #((Invoke-WebRequest -UseBasicParsing -Headers $Using:headerParams -Uri "$Using:RestUri`?PublisherIdentifier=${Using:TenantGUID}").Content | convertfrom-json) | ConvertTo-FlatObject | Export-Csv "$Using:ExportPath\$Using:TenancyName\$Using:ContentType\$Using:EDate\Audit_$Using:ContentType-$Using:Edate-$Using:Counter.csv" -NoTypeInformation                                     #?PublisherIdentifier=${Using:TenantGUID}" set due to API rate limit otherwise
        }
            
        # Start Job
        Start-Job -ScriptBlock $ScriptBlock | Out-Null
        
        # Cleanup Completed Jobs
        if (($Counter / $Counter) -eq 1 ) {
            Get-Job -State "Completed" | Remove-Job | Out-Null
        }
        # Limit Running Jobs to 32
        $RunningJobs = (Get-Job -State "Running").Count
        while ($RunningJobs -ge $MaxConcurrentJobs) {                             
            Start-Sleep 2.5
            $RunningJobs = (Get-Job -State "Running").Count
        }
    }

    #left here for troubleshooting
    #[string]$Rest.contentUri.Count + " " + "Blobs Processed for $Domain $ContentType" | Write-Output 

    <# Non multi-thread way, Archived Code. Left here for troubleshooting
    Measure-Command{
    $counter = 0
    $Rest.contentUri.count
    #Foreach datablob, get the data inside the blob and export it to csv / some location.
    $Counter = 0
    Foreach ($RestUri in $Rest.contentUri) { 
                                        $Counter++
                                     $RestContent = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri "$RestUri`?PublisherIdentifier=${TenantGUID}").Content | convertfrom-json) | Export-csv C:\Temp\ScriptTesting\Audit_$ContentType-$EDate-$Counter.csv 
    } 
    }
    #>
 
    #Wait for all jobs to finish.
    $RunningJobs1 = (Get-Job -State "Running").Count
    while ($RunningJobs1 -ge 1) {                             
        Start-Sleep 5
        $RunningJobs1 = (Get-Job -State "Running").Count
        $TimeCounter++
        If ($TimeCounter -ge 40) {
            $LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
            Write-Output "$LogDate : Time Counter $TimeCounter hit, removing stuck job" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append
            (Get-Job -State "Running") | Stop-Job
        }
            
    }

    #Collect all the individual csv's (due to multi threading performance), then export single one
    $CSV_Files = Get-ChildItem "$DFS_Long_Path\$Tenancyname\$ContentType\$EDate\CSV\*.csv"       
    $ContentTypeCSV = @()
    
    foreach ($CSV_File in $CSV_Files.FullName) {
        $ContentTypeCSV += Import-csv $CSV_File        
    }

    $ContentTypeCSV | Export-Csv "$DFS_Long_Path\$Tenancyname\$ContentType\Audit_$ContentType-$Edate.csv" -NoTypeInformation -Force #Export single csv file

    Start-Sleep 10

}

#######
# ***Domain_3***
#######
$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : ==Start ***Domain_3***==" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Start ***Domain_3*** ActiveDirectory" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

Get-365MgmtLogs-API -Domain ***Domain_3*** -Service AzureActiveDirectory #Get AAD Logs


$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finish ***Domain_3*** AzureActiveDirectory" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Start ***Domain_3*** General" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

Get-365MgmtLogs-API -Domain ***Domain_3*** -Service General #Get General Logs

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finish ***Domain_3*** General" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Start ***Domain_3*** Exchange" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

Get-365MgmtLogs-API -Domain ***Domain_3*** -Service Exchange #Get Exchange Logs

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finish ***Domain_3*** Exchange" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Start ***Domain_3*** SharePoint" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

Get-365MgmtLogs-API -Domain ***Domain_3*** -Service SharePoint #Get Sharepoint Logs

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finish ***Domain_3*** SharePoint" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : ==Finished ***Domain_3***==" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append



#######
# ***Domain_2***
#######
$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : ==Start ***Domain_2***==" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Start ***Domain_2*** ActiveDirectory" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

Get-365MgmtLogs-API -Domain ***Domain_2*** -Service AzureActiveDirectory #Get AAD Logs

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finish ***Domain_2*** ActiveDirectory" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append
$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Start ***Domain_2*** General" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

Get-365MgmtLogs-API -Domain ***Domain_2*** -Service General #Get General Logs

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finish ***Domain_2*** General" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append
$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Start ***Domain_2*** Exchange" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

Get-365MgmtLogs-API -Domain ***Domain_2*** -Service Exchange #Get Exchange Logs

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finish ***Domain_2*** Exchange" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append
$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Start ***Domain_2*** SharePoint" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

Get-365MgmtLogs-API -Domain ***Domain_2*** -Service SharePoint #Get Sharepoint Logs

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finish ***Domain_2*** SharePoint" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append
$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finished ***Domain_2***" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : ===Finished Script===" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append



#######
# ***Domain_1***
#######
$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : ==Start ***Domain_1***==" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Start ***Domain_1*** General" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

Get-365MgmtLogs-API -Domain ***Domain_1*** -Service General #Get General Logs

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finish ***Domain_1*** General" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Start ***Domain_1*** ActiveDirectory" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

Get-365MgmtLogs-API -Domain ***Domain_1*** -Service AzureActiveDirectory #Get AAD Logs

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finish ***Domain_1*** AzureActiveDirectory" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Start ***Domain_1*** Exchange" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

Get-365MgmtLogs-API -Domain ***Domain_1*** -Service Exchange #Get Exchange Logs

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finish ***Domain_1*** Exchange" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Start ***Domain_1*** SharePoint" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

Get-365MgmtLogs-API -Domain ***Domain_1*** -Service SharePoint #Get Sharepoint Logs

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : Finish ***Domain_1*** SharePoint" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

$LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
Write-Output "$LogDate : ==Finished ***Domain_1***==" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append


function Set-365MgmtLogs {
    param (
        [Parameter(Mandatory = $true)]
        [String] $Domain
    )

    switch ($Domain) {
        ***Domain_1*** {
        }
        ***Domain_2*** {
        }
        ***Domain_3*** {
        }
    }

    $TenancyName = $Domain
    
    
    $ContentType1 = "AzureActiveDirectory"
    $ContentType2 = "Exchange"
    $ContentType3 = "General"
    $ContentType4 = "SharePoint"

    $DFS_Short_Path = "\\***YourDomain***\security\SecArchive\Azure"
    $DFS_Long_Path = "\\***YourDomain***\security\SecArchive\Azure\Tenancy"
    $EDate = Get-Date((get-date).AddDays(-2)) -Format "yyyyMMdd"

    
    $OneCSV = ''
    $OneCSV = @() 

    $OneCSV = Import-csv "$DFS_Long_Path\$Tenancyname\$ContentType1\Audit_$ContentType1-$Edate.csv"
    $OneCSV += Import-csv "$DFS_Long_Path\$Tenancyname\$ContentType2\Audit_$ContentType2-$Edate.csv"
    $OneCSV += Import-csv "$DFS_Long_Path\$Tenancyname\$ContentType3\Audit_$ContentType3-$Edate.csv"
    $OneCSV += Import-csv "$DFS_Long_Path\$Tenancyname\$ContentType4\Audit_$ContentType4-$Edate.csv"
      
    $OneCSV | Export-Csv "$DFS_Short_Path\Azure365_$Domain\Office365_$Domain-$EDate.csv" -NoTypeInformation -Force

 
    $LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
    Write-Output "$LogDate : Compressing Archive " | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append
   
    #So this might fail depending on how large your tenancy is. Our's generates about 4gb CSV daily. had to yse 7zip to overcome. See my blog for the script.
    Compress-Archive -Path "$DFS_Short_Path\Azure365_$Domain\Office365_$Domain-$EDate.csv" -DestinationPath "$DFS_Short_Path\Azure365_$Domain\Office365_$Domain-$EDate.zip" -CompressionLevel Optimal -Force

    #Wait-Job $Compress #Wait for the compression to complete before trying to delete folder

    Start-Sleep -Seconds 10

    $LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
    Write-Output "$LogDate : File Compressed" | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

    Remove-Item ("$DFS_Long_Path\$TenancyName\$ContentType1\$EDate") -Recurse   #Remove the folder and all non-compressed files after zip
    #Remove-Item ("$DFS_Long_Path\$Tenancyname\$ContentType1\Audit_$ContentType1-$Edate.csv") 

    Remove-Item ("$DFS_Long_Path\$TenancyName\$ContentType2\$EDate") -Recurse   #Remove the folder and all non-compressed files after zip
    #Remove-Item ("$DFS_Long_Path\$Tenancyname\$ContentType2\Audit_$ContentType2-$Edate.csv") 

    Remove-Item ("$DFS_Long_Path\$TenancyName\$ContentType3\$EDate") -Recurse   #Remove the folder and all non-compressed files after zip
    #Remove-Item ("$DFS_Long_Path\$Tenancyname\$ContentType3\Audit_$ContentType3-$Edate.csv") 

    Remove-Item ("$DFS_Long_Path\$TenancyName\$ContentType4\$EDate") -Recurse   #Remove the folder and all non-compressed files after zip
    #Remove-Item ("$DFS_Long_Path\$Tenancyname\$ContentType4\Audit_$ContentType4-$Edate.csv") 

     
        
    $LogDate = Get-Date -Format yyyy-MM-dd:hh-mmtt
    Write-Output "$LogDate : Removed the $ContentType $Edate folder and all files within. CSV is hopefully now zipped." | Out-File "$LogFilePath\Get-365Mgmt-Logs-API-$Date.log" -Append

    #}
}

Set-365MgmtLogs -Domain ***Domain_1***  #One CSV 
Set-365MgmtLogs -Domain ***Domain_2***  #One CSV
Set-365MgmtLogs -Domain ***Domain_3***  #One CSV 
