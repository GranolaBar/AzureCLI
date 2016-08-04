configuration DemoAD2
{
	param
	(
       	[Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()]       [string] $domain,
                                                                      [string] $AppName,
                                                                      [string] $SampleAppLocation,
		[Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $LocalUserAccount,
		[Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $DomainUserAccount
    )
	
    Import-DscResource -ModuleName xNetworking
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xPendingReboot

	Node localhost
	{

		LocalConfigurationManager
		{
			RebootNodeIfNeeded = $true
		}

		WindowsFeature DNS 
		{ 
			Ensure = "Present" 
			Name   = "DNS"
		}

		WindowsFeature DNSTools
		{ 
			Ensure = "Present" 
			Name   = "RSAT-DNS-Server"
		}

		xDnsServerAddress DnsServerAddress 
		{ 
			Address        = '10.0.9.250' 
			InterfaceAlias = 'Ethernet'
			AddressFamily  = 'IPv4'
			DependsOn      = "[WindowsFeature]DNS"
		}

		WindowsFeature ADDSInstall
		{
			Ensure = "Present"
			Name = "AD-Domain-Services"
			IncludeAllSubFeature = $true
		}

		WindowsFeature ADTools
		{
			Ensure = "Present"
			Name = "RSAT-AD-Tools"
			IncludeAllSubFeature = $true
		}

		xWaitForADDomain DscForestWait 
        { 
            DomainName           = $domain 
            DomainUserCredential = $DomainUserAccount
        } 

		xADDomainController BDC
		{
			DomainName                    = $domain
			DomainAdministratorCredential = $DomainUserAccount
			SafemodeAdministratorPassword = $DomainUserAccount
			DependsOn                     = "[WindowsFeature]ADDSInstall"
		}

		xPendingReboot Reboot1
		{ 
			Name      = "RebootServer"
			DependsOn = "[xADDomainController]BDC"
		}
    }
}

