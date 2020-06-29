# phoneAuthMFA-PSRunbook
## Managing of phoneNumber for multi-factor auth (MFA) from a Automation Runbook towards Microsoft Graph API

## The problem

Lets say you have a customer / tenant with the requirement that MFA (Multi-Factor Authentication) and SSPR (Self-Service Password Reset) should only be registered when connected on the office network or via VPN, as measure to prevent identity theft via unsecure passwords for users yet not enrolled with MFA.

Hence, the following conditional access rules apply, together with combined-registration being enabled:\
https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-registration-mfa-sspr-combined#conditional-access-policies-for-combined-registration

During the current COVID-19 pandemic, this may cause problems for users working from home and thus a need to centrally manage the phone number used for MFA for users in Azure AD arises.

Historically, there has been no sure way to programmatically manage MFA registration for users. However, it has long been possible to manage the data via the graphical user interface / GUI in Azure AD per user. However, this is a laborious task to do manually and introduces the risk of making mistakes when handling multiple users.

Sure, you can sync the **mobile** attribute from AD, which will then be used as a suggestion for when the user first logs in and has to register MFA, but the user still has the final power to choose another phone number if desired and the users also has to complete the MFA-registration process themself, and if using combined registration, also SSPR.

## The solution

The following user feedback / voice received response from Microsoft, on May 28, 2020, that they had released features to the Graph API that enables management of phone numbers for MFA:\
[Azure Feedback: PowerShell and Graph API support for managing Multi-Factor Authentication](https://feedback.azure.com/forums/169401-azure-active-directory/suggestions/20249953-powershell-and-graph-api-support-for-managing-mult)

This solves the problem of previously not being able to programmatically manage the MFA data on behalf of the users. 
We can now via the attribute values (in my case, **extensionAttribute15** from AD) from IAM / directory services control which phone number the users should have configured for multifactor authentication (MFA).

The users can then log in and configure their MFA themselves to use the Authenticator app for example - which is the recommended method for login. However, by forcing which phone number the user receives MFA-challenges to, staff and administrators can be more safe knowing that the user logging in is the right person.

## Technical solution for authenticating to Azure via Graph API:

From the documentation from Microsoft, to be able to handle phoneAuthenticationMethod via Graph, we can see that this can only be done via Delegated Permissions:\
https://docs.microsoft.com/en-us/graph/api/phoneauthenticationmethod-update?view=graph-rest-beta&tabs=http

![Permissions required](/images/api_permissions.PNG)

Based on the above information, it appears that authentication must be done via a "service account" with a username and password, and must be given an appropriate role, in my case the **Authentication Admin** role was sufficient in order to have the necessary permissions to configure MFA on behalf of the users. We can also see that the Enterprise App, that handles authentication, must be given the necessary rights (**UserAuthenticationMethod.ReadWrite.All**) of the type Delegated Permissions, it must also be able to read the basic data of users such as UserPrincipalName etc.

![App_API_permissions](/images/App_permissions.PNG)

The rest of the App registration was done with the following configuration:

![Client_Secret](/images/app_clientsecret.PNG)

![Redirect_Purposes](/images/app_redirect_purposes.PNG)

### ROPC (Resource Owner Password Credentials)
Because this task requires a user account (service account) acting on behalf of other users, then this means that a so-called ROPC flow must be built for authenticating to MS Graph API:\
Read more: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc

> The resource owner password credentials (i.e., username and password)
> can be used directly as an authorization grant to obtain an access
> token.  The credentials should only be used when there is a high
> degree of trust between the resource owner and the client (e.g., the
> client is part of the device operating system or a highly privileged
> application), and when other authorization grant types are not
> available (such as an authorization code).
Reference: [https://tools.ietf.org/html/rfc6749#section-1.3.3](https://tools.ietf.org/html/rfc6749#section-1.3.3)

So a ROPC (Resource Owner Password Credentials) flow means, authenticating with a username and password and finally passing the Application ID and Client Secret to Graph. For this reason, _**special measures should be taken to protect the data used for authentication**_.

![ROPC](/images/ropc.PNG)

## My actions to secure these credentials resulted in the following solutions

In order to secure the use of these credentials and sensitive data, Azure is a suitable place to put this solution. Let me explain why:

In Azure there is something called Runbooks and Automation Accounts.\
https://docs.microsoft.com/en-us/azure/automation/automation-runbook-execution

Pricing is per Job run time:\
https://azure.microsoft.com/en-us/pricing/details/automation/

Runbooks are serverless scripts that can be scheduled, triggered and used to automate a lot of things. Automation Accounts is what links Runbooks (script) with resources such as login information, accounts, certificates, files and modules etc.

The following illustration shows the different input methods, the steps and the flow of how this is connected:

![runbooks-architecture](/images/runbooks-architecture.png)

One way to protect the credentials for the service account as well as the Client_Secret for the app is to put these parts of the script (authentication) in a Automation Account in Azure:

![secure assets](/images/secureassets.PNG)

* The Client_Secret can be placed in an encrypted variable (resource object) that can only be read from the specific Azure Automation Account where the runbook is running:\
https://docs.microsoft.com/en-us/azure/automation/shared-resources/variables

* Usernames and passwords can be entered into a resource object called Credentials, where they are stored encrypted and can only be read from the specific Azure Automation Account where the runbook is running:\
https://docs.microsoft.com/en-us/azure/automation/shared-resources/credentials

* Finally, in order to protect the account from unauthorized logins (if the login information somehow would have been leaked), we can limit from which locations (IP addresses) the account may log in from. I solved this with the help of Conditional Access and Named Locations, where the Azure Datacenter IP addresses located in North Europe (the same region that was chosen for the Resource Group in Azure for the Automation Account) were inserted into a Named Location and which were then allowed / exempted using Conditonal Access.    
[Download: Azure IP Ranges and Service Tags – Public Cloud](https://www.microsoft.com/en-us/download/details.aspx?id=56519) (P.S I managed to get successful results with AzureCloud.NorthEurope from the file.)

## The code

After having done all the above, we can finally start implementing the logical steps involved in setting the phoneNumber for MFA using PowerShell. The following PowerShell Runbook is in place and doesnt really contain any sensitive information that on its own can be used get access to the tenat, there is a "handshake" which protects the execution of the runbook, but on its own, it will not give access to anything else in the tenant.

[PowerShell Runbook Sourcecode](Runbook.ps1)

As I mentioned above, I also added a "handshake" to further protect the execution of the script. 
So dont forget to edit this line to set your own "secret" handshake:

```powershell
if ($WebhookData.RequestHeader.message -eq 'Handshake-message-only-known-between-runbook-and-invoker')
```

Then, to externally invoke the Runbook (script) contained in Azure Automation, you can use Webhooks that you set up for each Runbook, that will execute the runbook when RESTfully(?) called upon.\
https://docs.microsoft.com/en-us/azure/automation/automation-webhooks

See the example below for calling a REST API / Webhook (via PowerShell). The following would trigger the Runbook to execute, which logically translates into a request to check provided users extensionAttribute15 and phoneAuthenticationMethod and update them if necessary.

```PowerShell
$uri = "Your Webhook-URI which should be considered a secret"
$users = @(
           @{ UserPrincipalName="firstname1.lastname1@domain.com"},
           @{ UserPrincipalName="firstname1.lastname1@domain.com"}
)
$body = ConvertTo-Json -InputObject $users
$header = @{ Message = "Handshake-message-only-known-between-runbook-and-invoker" }
$request = Invoke-WebRequest -Method Post -Uri $uri -Body $body -Headers $header
```

As the invoker, dont forget to also edit this line to match your "secret" handshake required by the runbook:

```powershell
$header = @{ Message = "Handshake-message-only-known-between-runbook-and-invoker" }
```

Job done! :smirk:

