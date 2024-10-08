# Trustify
## Attack Active Directory Trusts with a single tool

![logo](https://github.com/user-attachments/assets/59ecc4ad-ef36-4e4a-9499-e8b8d893d407)

Trustify is a powershell script that act as a wrapper around other tools and scripts, specifically for attacking Active Directory domains when a trust is setup.

The script simply needs to be imported on a domain-joined Windows machine PowerShell session (the best way remains to add your own attack Windows machine to your compromised domain). From here, you can call multiple functions that correspond to different trust-related attacks depending on what you need to do. Those functions will allow you to retrieve information, attack and take over your target domain, providing there is an AD trust to exploit.

If you want to read more about the attacks and tricks that Trustify automates, I wrote an article that is available [here](https://blog.y00ga.lol/PERSO/PUBLISH/Article+perso/(Don't)+Trust+me%2C+a+little+study+on+attacking+Active+Directory+Trusts)

----------

## Usage

On a domain-joined Windows machine, import the script into your powershell session
````
Import-Module .\Trustify.ps1
````

-------------
# Attacks 

Trustify uses a Powershell porting of Rubeus to interact with Kerberos through trusts as well as other tools. Make sure that your attack machine have a proper Internet access so that the script can import its dependencies

## Get-TrustifyDetails
Simply collect useful information about the current trusts. This function will help you selecting the attack that is best suited for your use case :

![Get-TrustifyDetails](https://github.com/user-attachments/assets/f3fcd181-5fab-449c-98f3-203209c7ae41)


## Forge-TrustAccountTicket
When a one-way (outbound) trust is set up from **Forest-B** to **Forest-A**, a trust account named ``B$`` is created in Forest-A. This trust account, ``B$`` , can have its cleartext credentials and Kerberos keys extracted from any Domain Controller in either forest with admin privileges.

This attack consists in taking over the Trust account by leveraging the trust Key. It is made possible by the fact that the **trust key actually represents the password of the trust account**. Indeed, when Forest-B compromise is achieved, an attacker can extract the associated Trust Key on Forest-B root domain DC and use it to authenticate as the ``B$`` account in Forest-A. <br />

_Requires :_
- TrustAccountName
- Target Domain
- Corresponding Trust Key


## Compare-SAMAccountNames
This function collect every samaccountnames in your current domain as well as account names in the domain you need to attack for correlation. If an account in your current domain matches with another one in your target domain, they may also have matching passwords :<br />


https://github.com/user-attachments/assets/37147507-c3cc-4e8b-8f9a-48bf6472a3f2


<br />

_Requires :_
- Target Domain

## Check-ForeignACL
Use this function to check if domain objects in your current domain have ActiveDirectory permissions over other objects in another domain :<br />
  

https://github.com/user-attachments/assets/c4373f52-422a-4c6b-9b8d-cade807dae4c

<br />

_Requires :_
- Target Domain

## Add-ExtraSID
This function performs SIDHistory injection when forging a TGT for a designated account. If SIDFiltering is not enforced, you might request a TGT for a user in your current domain and adds the SID of a high-privileged group in your target domain :<br />



https://github.com/user-attachments/assets/ba967156-df2e-47ae-a469-af973ec55df9


 <br />

_Requires :_
- Username of the account that will receive ExtraSID
- krbtgt hash
- Target Domain
- Name of a high privileged group in the target Domain

## Exploit-UnconstrainedDelegation
For this attack, adding your own machine to the domain and set it up for Unconstrained Delegation is required (you can try to perform it from a server, but EDRs will probably catch the Rubeus listener...). From there, this function will start a TGT listener in a new PowerShell session. You can then force the target domain DC to authenticate to your machine through authentication coercion (PetitPotam, SpoolSample, DFSCoerce,...). When authenticating back to you, the target DC will leave a copy of its TGT on your machine, which you can then renew and use to perform DCsync <br />


https://github.com/user-attachments/assets/cf4c91a1-4786-48b3-b481-4b976c1e9a2a



<br />

_Requires :_
- Target Domain Controller hostname

## Abuse-ADCS
This one uses PSexec to :
- Connect as SYSTEM to a designated Domain Controller in the domain you compromised
- Import the [PKI-Escalate](https://github.com/heartburn-dev/PKI-Escalate) tool to get the required permissions over the specific container that host `pKIEnrollmentService` objects and create an ESC1 vulnerable ADCS template

Due to Configuration Naming Context (NC), this vulnerable template will replicate its way up and be requestable for any user in any domain in the target domain, providing the CA serves this other domain in the Forest : <br />


https://github.com/user-attachments/assets/ccd96f24-2c1b-46d7-987c-41e8348af2ad


 
 <br />

_Requires :_
- Target Domain Controller hostname
- Name for the future vulnerable template
- Full Path to the PSexec executable

----------
# Credits 

- Heartburn for PKI-Escalate : https://github.com/heartburn-dev/PKI-Escalate
- beauknowstech for Invoke-Hagrid : https://github.com/beauknowstech/Invoke-Hagrid.ps1/blob/main/Invoke-Hagrid.ps1
- harmj0y for Powerview : https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
