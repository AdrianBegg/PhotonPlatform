##########################################################################################
# Name: Build-PhotonCloudHost.ps1
# Author: Adrian Begg (adrian.begg@ehloworld.com.au)
#
# Date: 3/06/2017
# Purpose: Script to configure a Lab Photon Controller ESXi Cloud Host
# 
# The following assumes that a host has just been build from a kickstart script with add
# default password of vmware123
##########################################################################################

# Declarations
$strcsvHostFile = "PhotonHosts.csv"
$PhotonControllerIP = 
$PhotonCtlESXiDomain = "photon.pigeonnuggets.com"
$VIUsername = "root"
$VIPassword = "vmware123"
$NTPServer = "192.168.88.10"
$LicenseKey = "XXXXXX" # ESXi 6.5 Hypervisor Licence

# Check inputs
if(!(Test-Path $strcsvHostFile)){
	throw "The file $strcsvHostFile does not exist. Please check the path and try again."
	Break
}
$strHostName = Read-Host "Enter the hostname of the host to configure"
$objHost = Import-Csv -Path $strcsvHostFile | ?{$_.Hostname -eq $strHostName }
if($objHost.Count -eq 0){
	throw "The host provided $strHostName does not exist in the configuration file; please add the required entries into $strcsvHostFile."
}

$strNewRootPwd = Read-Host "Enter the new root password for the host"

# MAIN
$PhotonCtlESXiHostName = $objHost.HostName
$PhotonCtlESXiHostIP = $objHost.ManagementIP
$PhotonCtlESXiHostsiSCSI = $objHost.iSCSIIP
$PhotonCtlESXiHostsiSCSIMask = $objHost.iSCSINetMask
$iSCSITarget = $objHost.iSCSITargets

try{
	Write-Host "Connecting to $PhotonCtlESXiHostIP ..."
	$viConnection = Connect-VIServer $PhotonCtlESXiHostIP -User $VIUsername -Password $VIPassword -WarningAction SilentlyContinue
} catch {
	throw "Unable to connect to the host to configure. Please check credentials and IP and try again."
}

Write-Host "Configuring NTP and SSH services ..."
# Set the NTP Settings
Get-VMHost | Add-VMHostNtpServer -NtpServer $NTPServer
Get-VmHostService | Where-Object {$_.key -eq "ntpd"} | Start-VMHostService > $nul
Get-VmHostService | Where-Object {$_.key -eq "ntpd"} | Set-VMHostService -policy "automatic" > $nul
	
# Enable SSH and set to automatic (This is required for the deployment of the Agents)
Get-VmHostService | Where-Object {$_.key -eq "TSM-SSH"} | Start-VMHostService > $nul
Get-VmHostService | Where-Object {$_.key -eq "TSM-SSH"} | Set-VMHostService -policy "automatic" > $nul

Write-Host "Setting the Management Network vmk0 and binding NICs ..."
# Update the Network properties on vmk0
Set-VMHostNetwork -Network (Get-VmHostNetwork) -HostName $PhotonCtlESXiHostName -DomainName $PhotonCtlESXiDomain

# Add the second NIC to the main vSwitch for Redundency
$VMHostNetworkAdapter = Get-VMHostNetworkAdapter -Physical -Name vmnic1
Get-VirtualSwitch -Name "vSwitch0" | Add-VirtualSwitchPhysicalNetworkAdapter -VMHostPhysicalNic $VMHostNetworkAdapter -Confirm:$false

Write-Host "Configuring vSwitch for iSCSI traffic ..."
# Create a a second vSwitch for iSCSI Traffic and configure Software iSCSI
Get-VMHostStorage | Set-VMHostStorage -SoftwareIScsiEnabled $True > $nul
Get-VMHost | New-VirtualSwitch -Name "iSCSI" -NIC vmnic2
$vPortGroup =  New-VirtualPortGroup -VirtualSwitch "iSCSI" -Name "iSCSI"
$iSCSIMgtvmk = New-VMHostNetworkAdapter -VirtualSwitch "iSCSI" -ManagementTrafficEnabled $true -IP $PhotonCtlESXiHostsiSCSI -SubnetMask $PhotonCtlESXiHostsiSCSIMask -PortGroup $vPortGroup
# Set the Port Binding on the iSCSI Adapter
$hba = Get-VMHostHba -Type iSCSI
$esxcli = Get-EsxCli
$Esxcli.iscsi.networkportal.add($HBA, $Null, "vmk1") > $nul
	
# Add the iSCSI Target
Get-VMHost | Get-VMHostHba -Type iScsi | New-IScsiHbaTarget -Address $iSCSITarget > $nul
Read-Host "Please configure the iSCSI Target servers for iQN: $($(Get-VMHostHba -Type iSCSI).IScsiName) and press enter once configuration complete."
Get-VMHostStorage -RescanAllHba > $nul

Write-Host "Changing the root Password ..."

# Change the root password of the host
Set-VMHostAccount -UserAccount "root" -Password $strNewRootPwd

Write-Host "Assigning the licnence ..."
# Assign the vSphere Licence to the hsot - IMPORTANT : This need to be done AFTER configuration; the vSphere API is not included in the ESXi Free
Get-VMHost | Set-VMHost -LicenseKey $LicenseKey > $nul

Disconnect-VIServer -Confirm:$false
# TO DO: Add the host to the Photon Controller; this is manual at this point
