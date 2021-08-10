# Get-365MgmtLogs
Powershell Office365 API audit log collector

Blog Post to follow.

Subscribe to and collect logs from Office365 auditing APIs (https://msdn.microsoft.com/en-us/office-365/office-365-management-activity-api-reference). Feel free to contribute other outputs if you happen to build any. Default behavior is to retrieve logs of the 2 days in the past. (Due to tenancy busyness).

Use cases:
Ad-lib log retrieval;
Scheduling regular execution to retrieve the full audit trail.

Features:
Collect General, Exchange, Sharepoint, Azure active directory;

Requirements:
Office365 tenant;
Azure application created for this script (see instructions)
AzureAD tenant ID;
Client key of the new Azure application;
Secret key (created in the new Azure application, see instructions);
App permissions to access the API's for the new Azure application (see instructions);

Subscription to the API's of your choice (General/Sharepoint/Exchange/AzureAD/DLP, run AuditLogSubscription script and follow the instructions).

Instructions:
Creating an application in Azure:
Create the 'Web app / API' type app by following these instructions: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-integrating-applications#adding-an-application

Grant your new app permissions to read the Office API's: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-integrating-applications#configure-a-client-application-to-access-web-apis

Update variables in script
