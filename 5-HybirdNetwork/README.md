
# Hybrid Network VPN

## Description
Extends an on-premises network onto Azure using a site-to-site virtual private network (VPN). The traffic flows between the on-premises network and an Azure Virtual Network (VNet) through an IPSec VPN tunnel. This architecture is suitable for hybrid applications with the following characteristics:
* Parts of the application run on-premises while others run in Azure.
* The traffic between on-premises hardware and the cloud is likely to be light, or it is beneficial to trade slightly extended latency for the flexibility and processing power of the cloud.
* The extended network constitutes a closed system. There is no direct path from the Internet to the Azure VNet.
* Users connect to the on-premises network to use the services hosted in Azure. The bridge between the on-premises network and the services running in Azure is transparent to users.
Examples of scenarios that fit this profile include:
* Line-of-business applications used within an organization, where part of the functionality has been migrated to the cloud.
* Development/test/lab workloads.

## Architecture diagram
![diagram](../images/hybridNetwork.png)

## Prescriptive Guidance
Prescriptive  guidance plus considerations for availability, manageability, and security is available [here](https://azure.microsoft.com/en-us/documentation/articles/guidance-hybrid-network-vpn/).

## Related Training
* [Azure Network Security Groups (NSGs)](https://azure.microsoft.com/en-us/documentation/articles/virtual-networks-nsg/)
* [Adding reliability to an N-tier architecture on Azure](https://azure.microsoft.com/en-us/documentation/articles/guidance-compute-n-tier-vm/)
* [Networking basics for building applications in Azure](https://azure.microsoft.com/en-us/documentation/videos/azurecon-2015-networking-basics-for-building-applications-in-azure/)
* [Microsoft Azure Fundamentals: Configure an Availability Set](https://azure.microsoft.com/en-us/documentation/articles/virtual-machines-windows-create-availability-set/)

## Tools
* [Installing and configuring Azure PowerShell](https://azure.microsoft.com/en-us/documentation/articles/powershell-install-configure/)

## Deployment

### Deploy using the Azure Portal
[![Deploy to Azure](../images/azurebtn.png)](https://valoremconsulting.github.io/AzureCLI/redirect.html)

You will need to be logged into the Azure portal under the subscription you would like to use.

### PowerShell
```PowerShell
New-AzureRmResourceGroup           -ResourceGroupName YourResourceGroup5 -location "Central US"
New-AzureRmResourceGroupDeployment -ResourceGroupName YourResourceGroup5 -TemplateUri "https://clijsonpublic.blob.core.windows.net/hn-stageartifacts/azuredeploy.json" -TemplateParameterUri "https://clijsonpublic.blob.core.windows.net/hn-stageartifacts/azuredeploy.parameters.json"
```
[Install and configure Azure PowerShell](https://azure.microsoft.com/en-us/documentation/articles/powershell-install-configure/)

### CLI
```
azure group create            -n "YourResourceGroup5" -l "Central US"
azure group deployment create -g "YourResourceGroup5" -f "https://raw.githubusercontent.com/ValoremConsulting/AzureCLI/master/5-HybirdNetwork/Templates/azuredeployGitHub.json" 
```
[Install and Configure the Azure Cross-Platform Command-Line Interface](https://azure.microsoft.com/en-us/documentation/articles/xplat-cli-install/)
