configuration DemoAD1
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
	

	Node localhost
	{
		LocalConfigurationManager
		{
			RebootNodeIfNeeded = $true
			DebugMode = "ForceModuleImport"
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
			Address        = '127.0.0.1' 
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

		xADDomain FirstDS
		{
			DomainName                    = $domain
			DomainAdministratorCredential = $LocalUserAccount
			SafemodeAdministratorPassword = $LocalUserAccount
			DependsOn                     = "[WindowsFeature]ADDSInstall"
		}

	}
}
