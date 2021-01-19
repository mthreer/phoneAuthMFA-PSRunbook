<#--------------------------------------

Author: Niklas Jumlin (niklas.jumlin@very-secret.se)
Version: 2020-06-24-1

The script (software) reads a synchronized attribute value and updates or adds the value to the 
phoneNumber used by Azure Multi-factor Authentication via Microsoft Graph API.

Copyright (C) 2020 Niklas jumlin

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

-----------------------------------------#>

Param
(
    [Parameter (Mandatory= $false)]
    [Object]$WebhookData
)

# If runbook was called from Webhook, WebhookData will not be null.
if ($WebhookData) {
    Write-Output $WebhookData
    
    # Check header for message to validate request
    if ($WebhookData.RequestHeader.message -eq 'Handshake-message-only-known-between-runbook-and-invoker')
    {
        Write-Output "Header has required information"}
    else
    {
        Write-Output "Header missing required information";
        exit;
    }
    # Special case for testing of data via test pane
    if (-not($WebhookData.RequestBody)) {
        $WebhookData = (ConvertFrom-Json -InputObject $WebhookData)
        Write-Output "test $WebhookData"
    }
    $Users = (ConvertFrom-Json -InputObject $WebhookData.RequestBody)
}

# Connect to Azure Automation
$Credentials = Get-AutomationPSCredential -Name 'Name of Credentials-resource object in the Automation Account'

# This function converts a given PSObject to a HashTable recursively.
# Graph returns JSON data as PSObjects. Hashtables are needed to achieve key to value pairing.
function ConvertPSObjectToHashtable {
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )
    process {
        if ($null -eq $InputObject) { return $null }
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $collection = @(
                foreach ($object in $InputObject) { ConvertPSObjectToHashtable $object }
            )
            Write-Output -NoEnumerate $collection
        }
        elseif ($InputObject -is [psobject]) {
            $hash = @{}
            foreach ($property in $InputObject.PSObject.Properties) {
                $hash[$property.Name] = ConvertPSObjectToHashtable $property.Value
            }
            $hash
        }
        else {
            $InputObject
        }
    }
}

#$VerbosePreference = "Continue"

#This is the ClientID (Application ID) of the registered Enterprise App in Azure AD
$ClientID = "3965db2e-1dff-428c-8ce1-79bdb537b91e"

#This is your Office 365 Tenant Domain Name or Tenant Id
#$TenantId = "jumlin.onmicrosoft.com"
$TenantId = "3619ea90-fa6e-40bf-aa11-2d4a18ad4521"

$ReqTokenBody = @{
    Client_Id       =   $ClientID
    Client_Secret   =   Get-AutomationVariable -Name ClientSecret #This is the Client_Secret of the registered Enterprise app in Azure AD
    Grant_Type      =   "Password"
    Scope           =   "https://graph.microsoft.com/.default"
    Username        =   $Credentials.Username # The username provided to the Credentials-resource object in the Automation Account
    Password        =   [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credentials.Password)) # The password provided to the Credentials-resource object in the Automation Account
}
Try {
    $OAuthReq = Invoke-RestMethod -Method POST -Uri https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token -Body $ReqTokenBody -ContentType application/x-www-form-urlencoded -ErrorAction Stop
    $TokenType = $OAuthReq.token_type
    $AccessToken = $OAuthReq.access_token
    Write-Output "Auth success! `'$TokenType`' AccessToken retrieved" 
}
Catch {
    if ($_.ErrorDetails.Message) {
        Write-Error "$((($_.ErrorDetails.Message | ConvertFrom-Json).error_description -split "`n")[0])" 
    }
    else {
        Write-Error "$($_.CategoryInfo.Reason): $($_.Exception.Message)" 
    }
    Break;
}
foreach ($User in $Users) {
    $UserPrincipalName = $User.UserPrincipalName
    # Retrieve user data with synchronized value from extensionAttribute15
    Try {
        $apiUrl = "https://graph.microsoft.com/beta/users?`$filter=UserPrincipalName eq '$UserPrincipalName'&`$select=onPremisesExtensionAttributes,mail,UserPrincipalName"
        $userAttributes = Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken"} -Uri $apiUrl -Method GET -ErrorAction Stop
        if ($userAttributes.value) {
            Write-Output "Attributes for `'$($userAttributes.value.UserPrincipalName)`' was retrieved" 
            Write-Output ("{0,-25}:{1,25}" -f 'extensionAttribute15',$($userAttributes.value.onPremisesExtensionAttributes.extensionAttribute15)) 
            $NewMFA = @{
                phoneNumber = "$($userAttributes.value.onPremisesExtensionAttributes.extensionAttribute15)"
                phoneType   = "mobile"
            }
        }
        if (-not($userAttributes.value)) {
            throw "The query did not return any data for `'$UserPrincipalName`'"
        }
        if (-not($NewMFA.phoneNumber)) {
            throw "The query did not return any data for extensionAttribute15 for user `'$UserPrincipalName`'"
        }
    }
    Catch {
        if ($_.ErrorDetails.Message) {
            Write-Output "$((($_.ErrorDetails.Message | ConvertFrom-Json).error.message -split "`n")[0])" 
        }
        else {
            Write-Output "$($_.CategoryInfo.Reason): $($_.Exception.Message)" 
        }
        Continue; # break loop
    }
    # Retrieve current authentication methods and filter for mobile type
    Try {   
        $apiUrl = "https://graph.microsoft.com/beta/users/$($userAttributes.value.UserPrincipalName)/authentication/methods"
        $Methods = Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken"} -Uri $apiUrl -Method GET -ErrorAction Stop
        if ($Methods.value) {
            $HashMethods = $Methods | ConvertPSObjectToHashtable
            $CurrentMFA = ($HashMethods.value).Where{$_.PhoneType -eq 'mobile'}.phoneNumber
            Write-Output ("{0,-25}:{1,25}" -f 'MFA phoneNumber',$CurrentMFA) 
        }
        if (-not($Methods.value)) {
            throw "The query did not return any AuthenticationMethods for `'$UserPrincipalName`'"
        }
    }
    Catch {
        if ($_.ErrorDetails.Message) {
            Write-Output "$((($_.ErrorDetails.Message | ConvertFrom-Json).error.message -split "`n")[0])" 
        }
        else {
            Write-Output "$($_.CategoryInfo.Reason): $($_.Exception.Message)" 
        }
        Continue; # break loop
    }
    #
    # Begin validation and updating/adding of new phoneNumber
    #
    if (($NewMFA.phoneNumber) -and ($CurrentMFA)) {
        # Since we only receive the last 2 digits of the phoneNumber used for authentication from MS Graph, lets compare these last two digits with the one from extensionAttribute15
        if ( $(($NewMFA.phoneNumber).Substring(($NewMFA.phoneNumber.Length)-2,2)) -eq $CurrentMFA.Substring(($CurrentMFA.Length)-2,2) ) {
            Write-Output "Current MFA phoneNumber seems to match the value from extensionAttribute15" 
        }
        # phoneNumber does not match extensionAttribute15, lets update that
        else {
            Write-Warning "The user has a phoneNumber, but it does NOT seem to match the value from extensionAttribute15." 
            Try {
                # PUT (Update) phoneNumber using value from extensionAttribute15 as source
                Write-Output "Updating phoneNumber with `'$($NewMFA.phoneNumber)`' - to match extensionAttribute15 . . ." 
                $apiUrl = "https://graph.microsoft.com/beta/users/$($userAttributes.value.UserPrincipalName)/authentication/phoneMethods/$(($HashMethods.value).Where{$_.PhoneType -eq 'mobile'}.Id)"
                $body = $NewMFA | ConvertTo-JSON
                $null = Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken"} -Body $body -ContentType application/json -Uri $apiUrl -Method PUT -ErrorAction Stop
                Write-Output "The phoneNumber for $($userAttributes.value.UserPrincipalName) was successfully updated!" 
            }
            Catch {
                if ($_.ErrorDetails.Message) {
                    Write-Output "$((($_.ErrorDetails.Message | ConvertFrom-Json).error.message -split "`n")[0])" 
                }
                else {
                    Write-Output "$($_.CategoryInfo.Reason): $($_.Exception.Message)" 
                }
                Continue; # break loop
            }
        }
    }
    # If there is currently no phoneNumber configured for MFA:
    if (-not($CurrentMFA)) {
        Write-Output "The user `'$($userAttributes.value.UserPrincipalName)`' does not have any mobile phoneNumber for MFA" 
        if ($NewMFA.phoneNumber) {
            Try {
                # PUT (Update) phoneNumber using value from extensionAttribute15 as source
                Write-Output "Adding phoneNumber: $($NewMFA.phoneNumber) . . ." 
                $apiUrl = "https://graph.microsoft.com/beta/users/$($userAttributes.value.UserPrincipalName)/authentication/phoneMethods"
                $body = $NewMFA | ConvertTo-JSON
                $null = Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken"} -Body $body -ContentType application/json -Uri $apiUrl -Method POST -ErrorAction Stop
                Write-Output "A phoneNumber for $($userAttributes.value.UserPrincipalName) was successfully added!" 
            }
            Catch {
                if ($_.ErrorDetails.Message) {
                    Write-Output "$((($_.ErrorDetails.Message | ConvertFrom-Json).error.message -split "`n")[0])" 
                }
                else {
                    Write-Output "$($_.CategoryInfo.Reason): $($_.Exception.Message)" 
                }
                Continue; # break loop
            }
        }
    }
} # end foreach user
