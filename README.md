# Trustify
## Attack Active Directory Trusts with a single tool

![logo](https://github.com/user-attachments/assets/59ecc4ad-ef36-4e4a-9499-e8b8d893d407)

--------------


Trustify a a powershell script that act as a wrapper around other tools and scripts, specifically for attacking Active Directory domains when a trust is setup.

The script simply needs to be imported from a domain-joined Windows machine (the best way remains to add your own attack Windows machine to your compromised domain). From here, you can call multiple functions that corresponds to different trust-related attack depending on what you need to do. Those functions will allow you to retrieve information, attack and take over your target domain, providing there is an AD trust to exploit.

If you want to read more about the attacks and tricks that Trustify automates, I wrote an article that is available [here](https://blog.y00ga.lol/PUBLISH/Forensike%2C+or+Forensics+for+bad+guys

----------

## Usage

In a domain-joined Windows machine, import the script into your powershell session
````
Import-Module .\Trustify.ps1
````

-------------
## Attacks 

Trustify uses a Powershell porting of Rubeus to interact with Kerberos through trusts as well as other tools. Make sure that your attack machine have a proper Internet access so that the script can import its dependencies

### Get-TrustifyDetails
Simply collect useful information about the current trusts. This function will help you selecting the attack that is best suited for your use case :
![Get-TrustifyDetails](https://github.com/user-attachments/assets/f3fcd181-5fab-449c-98f3-203209c7ae41)


### Forge-TrustAccountTicket
When a one-way (outbound) trust is set up from **Forest-B** to **Forest-A**, a trust account named ``B$`` is created in Forest-A. This trust account, ``B$`` , can have its cleartext credentials and Kerberos keys extracted from any Domain Controller in either forest with admin privileges.

This attack consists in taking over the Trust account by leveraging the trust Key. It is made possible by the fact that the **trust key actually represents the password of the trust account**. Indeed, when Forest-B compromise is achieved, an attacker can extract the associated Trust Key on Forest-B root domain DC and use it to authenticate as the ``B$`` account in Forest-A.

_Requires :_
- TrustAccountName
- Target Domain
- Corresponding Trust Key


### Compare-SAMAccountNames
This function collect every samaccountnames in your current domain as well as account names in the domain you need to attack for correlation. If an account in your current domain matches with another one in your target domain, they may also have matching passwords :
https://github.com/user-attachments/assets/5dcac0c6-02f1-4d54-adb5-416554fb31bd

_Requires :_
- Target Domain

### Check-ForeignACL
Use this function to check if domain objects in your current domain have ActiveDirectory permissions over other objects in another domain :
https://github.com/user-attachments/assets/5b10aa44-ac0a-4975-9cae-f6f96e3db2b3

_Requires :_
- Target Domain

### Add-ExtraSID
This function performs SIDHistory injection when forging a TGT for a designated account. If SIDFiltering is not enforced, you might request a TGT for a user in your current domain and adds the SID of a high-privileged group in your target domain :
https://github.com/user-attachments/assets/8249899e-e587-4550-bb5a-fb8a878ec271

### Exploit-UnconstrainedDelegation
For this attack, adding your own machine to the domain and set it up for Unconstrained Delegation is required (you can try to perform it from a server, but EDRs will probably catch the Rubeus listener...). From there, this function will start a TGT listener in a new PowerShell session. You can then force the target domain DC to authenticate to your machine through authentication coercion (PetitPotam, SpoolSample, DFSCoerce,...). When authenticating back to you, the target DC will leave a copy of its TGT on your machine, which you can then renew and use to perform DCsync
https://github.com/user-attachments/assets/466fd517-df37-4621-ab49-06fa5045f7da

_Requires :_
- Target Domain Controller hostname

### Abuse-ADCS
This one uses PSexec to :
- Connect as SYSTEM to a designated Domain Controller in the domain you compromised
- Import the [PKI-Escalate](https://github.com/heartburn-dev/PKI-Escalate) to get the required permissions over the specific container that host `pKIEnrollmentService` objects and create an ESC1 vulnerable ADCS template

Due to Configuration Naming Context (NC), this vulnerable template will replicate its way up and be requestable for any user in any domain in the target domain, providing the CA serves this other domain in the Forest
https://github.com/user-attachments/assets/7bc488fb-e916-4e08-b626-955fa70e4fbe

_Requires :_
- Target Domain Controller hostname
- Name for the future vulnerable template
- Full Path to the PSexec executable

----------
# Credits 

Hearburn for PKI-Escalate : https://github.com/heartburn-dev/PKI-Escalate
beauknowstech for Invoke-Hagrid : https://github.com/beauknowstech/Invoke-Hagrid.ps1/blob/main/Invoke-Hagrid.ps1
harmj0y for Powerview : https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
