##########################################################################################
# Name: Module-VMWare-PhotonPlatform.psm1
# Date: 12/07/2017 (v0.1)
# Author: Adrian Begg (adrian.begg@ehloworld.com.au)
#
# Purpose: PowerShell modules to leverage Photon Platform v1.2.1 API for management
# of the Platform in Powershell.
#
##########################################################################################
# Change Log
# v0.1 - Inital Creation of codebase
##########################################################################################
# Known Issues/To-Do
#
# 1. Limited testing of all methods; this is first cut of these methods built whilst I am
# building the platform on my lab; lots of error checking needed to be added and this has
# not been tested at scale.
#
# 2. Impcomplete implementation; lots of methods left to write :)
#
# 3. Typing is a mess; using PSObject to save time; the objects should be strongly typed in the future.
#
# 4. Documentation - Needs work
##########################################################################################
### Ignore TLS/SSL errors
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,
WebRequest request, int certificateProblem) {
return true;
}
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#region: Common-API-Methods
function Connect-PCServer(){
	<#
	.SYNOPSIS
	 This cmdlet establishes a connection to the REST API of a Photon Controller and caches an authToken

	.DESCRIPTION
	 This cmdlet establishes a connection to the REST API of a Photon Controller and caches an authToken

	.PARAMETER Server
	Specifies the IP address of the Photon Controller; please note you can not use the Load Balancer IP

	.PARAMETER Port
	Specifies the TCP Port for the connection; the Default is TCP 443 (Authenticated)

	.PARAMETER Credentials
	Specifies a PSCredential object that contains credentials for authenticating with the server. This is the SSO credentials

	.EXAMPLE
	Connect-PCServer -Server "photonplatform.pigeonnuggets.com"

	Connects to the Photon Platform server at https://photonplatform.pigeonnuggets.com:443 and prompts for Credentials

	.EXAMPLE
	Connect-PCServer -Server "photonplatform.pigeonnuggets.com" -Credentials $Cred

	Connects to the Photon Platform server at https://photonplatform.pigeonnuggets.com:443 using the Credentials in the PSCredential object $Cred

	.EXAMPLE
	Connect-PCServer -Server "photonplatform.pigeonnuggets.com" -Credentials $Cred -Port 19821
	Connects to the Photon Platform server at https://photonplatform.pigeonnuggets.com:19821 using the Credentials in the PSCredential object $Cred

	.NOTES
	  NAME: Connect-PCServer
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-17
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller connect
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/API-Documentation
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $Server,
		[Parameter(Mandatory=$False)]
			[ValidateRange(1,65536)] [int] $Port=443,
		[Parameter(Mandatory=$False)] [PSCredential] $Credentials = $Host.ui.PromptForCredential("Enter credentials for $Server", "Please enter your user name and password for the Lightwave SSO Service in the same format as you use to conenct to Photon Controller.", "", "")
	)
	# First step is to get the Lightwave server
	[string] $AuthURI = "https://" + $Server + ":" + $Port + "/v1/system/auth"
	try{
		$webclient = New-Object system.net.webclient
		$JSONResponseServers = ConvertFrom-Json($webclient.DownloadString($AuthURI))
	} catch {
		throw "An error occured connecting to $LightwaveURI to find the Lightwave Authentication service."
	}
	# Connect to the Lightwave service to obtain a token
	[string] $AuthenticationServer = $JSONResponseServers.endpoint + ":" + $JSONResponseServers.port
	[string] $AuthenticationDomain = $JSONResponseServers.domain
	[string]$AuthTokenURI = "https://" + $AuthenticationServer + "/openidconnect/token"

	# NOTE: Documented version https://github.com/vmware/photon-controller/wiki/API-Documentation is different; the scope should be rs_esxcloud NOT rs_photon ?
	[string] $TokenRequestBody = "grant_type=password&username=$($Credentials.UserName)&password=$($Credentials.GetNetworkCredential().Password)&scope=openid offline_access rs_esxcloud at_groups"

	$webclient = New-Object system.net.webclient
	$webclient.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
	# Convert the Authentication date to byte array for upload
	[byte[]]$baAuthData = [System.Text.Encoding]::ASCII.GetBytes($TokenRequestBody)
	try{
		$baAuthToken = $webclient.UploadData($AuthTokenURI, "POST", $baAuthData)
		# Convert the Byte Array to JSON
		$AuthToken = ConvertFrom-Json([System.Text.Encoding]::ASCII.GetString($baAuthToken))
	} catch {
		throw "An error occured connecting to Lightwave to Obtain an Auth Token. Please check the username and password provided and try again."
	}
	$objPhotonPlatform = New-Object System.Management.Automation.PSObject
	$objPhotonPlatform | Add-Member Note* Name $Server
	$objPhotonPlatform | Add-Member Note* ServiceURI ("https://" + $Server + ":" + $Port + "/")
	$objPhotonPlatform | Add-Member Note* Port $Port
	$objPhotonPlatform | Add-Member Note* User $Credentials.UserName
	$objPhotonPlatform | Add-Member Note* Domain $AuthenticationDomain
	$objPhotonPlatform | Add-Member Note* AuthenticationServer $AuthenticationServer
	$objPhotonPlatform | Add-Member Note* AccessToken $AuthToken.access_token
	$objPhotonPlatform | Add-Member Note* TokenType $AuthToken.token_type
	$objPhotonPlatform | Add-Member Note* RefreshToken $AuthToken.refresh_token
	$objPhotonPlatform | Add-Member Note* IdToken $AuthToken.id_token
	$objPhotonPlatform | Add-Member Note* TokenExpiry $AuthToken.expires_in
	$objPhotonPlatform | Add-Member Note* IsConnected $true
	Set-Variable -Name "DefaultPCServer" -Value $objPhotonPlatform -Scope Global
}

function Request-TokenRefresh(){
	<#
	.SYNOPSIS
	 This cmdlet attempts to refresh the authentication token if an expired token is recieved during an API call.

	.DESCRIPTION
	 This cmdlet attempts to refresh the authentication token if an expired token is recieved during an API call.

	 .EXAMPLE
	 Request-TokenRefresh

	 Attempts to refresh the Authentication Token for the currently connected Platform Controller Server connection.

	.NOTES
	  NAME: Request-TokenRefresh
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-17
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller authenticate
	  REFERENCE: https://gowalker.org/github.com/vmware/photon-controller-go-sdk/photon/lightwave#OIDCClient_GetTokenByRefreshTokenGrant
	#>
	# Check if we are currently connected to Photon Platform
	if(!$global:DefaultPCServer.IsConnected){
		throw "You are not currently connected to any servers; unable to refresh the token."
	}
	# Derived (kind of) from https://gowalker.org/github.com/vmware/photon-controller-go-sdk/photon/lightwave#OIDCClient_GetTokenByRefreshTokenGrant definition and some Fiddler reverse engineering
	[string]$AuthTokenURI = "https://" + $global:DefaultPCServer.AuthenticationServer + "/openidconnect/token"
	[string] $TokenRequestBody = $global:DefaultPCServer.Domain + "&grant_type=refresh_token&refresh_token=" + $global:DefaultPCServer.RefreshToken + "&redirect_uri=" + $ServiceURI + "&scope=openid offline_access rs_esxcloud at_groups"
	[byte[]]$baAuthData = [System.Text.Encoding]::ASCII.GetBytes($TokenRequestBody)
	$webclient = New-Object system.net.webclient
	$webclient.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
	try{
		$baAuthToken = $webclient.UploadData($AuthTokenURI, "POST", $baAuthData)
		# Convert the Byte Array to JSON
		$AuthToken = ConvertFrom-Json([System.Text.Encoding]::ASCII.GetString($baAuthToken))
	} catch {
		Disconnect-PCServer
		throw "An error occured connecting to Lightwave to Obtain an Auth Token for Token Refresh. The connection has been disconnected; please reconnect with Connect-PCServer."
	}
	# TODO: Add checks that the response is value and contains the values we expect before the set
	# Set the values returned to be the new access token

	$global:DefaultPCServer.AccessToken = $AuthToken.access_token
	$global:DefaultPCServer.IdToken = $AuthToken.id_token
	$global:DefaultPCServer.TokenType = $AuthToken.token_type
	$global:DefaultPCServer.TokenExpiry = $AuthToken.expires_in
}

function Disconnect-PCServer(){
	<#
	.SYNOPSIS
	 This cmdlet disconnects the session from the cloud managemnet servers.

	.DESCRIPTION
	 This cmdlet disconnects the session from the default Photon Platform servers.

	.EXAMPLE
	 Disconnect-PCServer

	 Disconnects/ends the currently connected session to the Photon Platform.

	.NOTES
	  NAME: Disconnect-PCServer
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-06-28
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller disconnect
	#>
	Set-Variable -Name "DefaultPCServer" -Value $null -Scope Global
}

function Get-PCAPIResponseJSON(){
	<#
	.SYNOPSIS
	 This cmdlet performs a HTTP GET against the URI and returns the JSON Response

	.DESCRIPTION
	 This cmdlet performs a HTTP GET against the provided URI and returns the JSON Response

	.PARAMETER URI
	The URI to make the API GET Request against

	.EXAMPLE
	Get-PCAPIResponseJSON -URI "https://photonplatform.pigeonnuggets.com/v1/available"

	Will perfrom a HTTP GET against the Photon Platform https://photonplatform.pigeonnuggets.com:443/v1/available and return the response as application/json

	.NOTES
	  NAME: Get-PCAPIResponseJSON
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-17
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller API GET JSON
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $URI
	)
	if(!$global:DefaultPCServer.IsConnected){
		throw "You are not currently connected to any servers. Please connect first using a Connect-PCServer cmdlet."
	}
	# Create a Web Client for the request based ont he API
	[string] $strTokenHeader = $Global:DefaultPCServer.TokenType + " " + $Global:DefaultPCServer.AccessToken

	$webclient = New-Object system.net.webclient
	$webclient.Headers.Add("Authorization", $strTokenHeader)
	$webclient.Headers.Add("Content-Type", "application/json")

	# A bool value used in the loop to control and allow retry in the event of a 401
	[bool] $APICallCompleted = $false
	# To prevent infinite loops
	[int] $intTryCount = 0
	while (-not $APICallCompleted){
		try{
			ConvertFrom-Json($webclient.DownloadString($URI))
			$APICallCompleted = $true
			$intRetryCount++
		} catch {
			# Check if the Exception thrown is 401 Unauthorized and try and refresh the token
			if(($intRetryCount -le 1) -and ($_.Exception.GetBaseException().Response.StatusCode -eq "Unauthorized")){
				try{
					Request-TokenRefresh
				} catch {
					# If the token can not be refreshed need to break
					$APICallCompleted = $true
					throw $_
				}
			} else {
				$APICallCompleted = $true
				throw "An error occured attempting to make HTTP GET against $URI"
			}
			$intRetryCount++
		}
	}
}

function Update-PCAPIDataJSON(){
	<#
	.SYNOPSIS
	 This cmdlet performs a HTTP PUT against the provided URI and returns the JSON Response

	.DESCRIPTION
	 This cmdlet performs a HTTP PUT against the provided URI and returns the JSON Response

	.PARAMETER URI
	The URI to make the API PUT Request against

	.PARAMETER Data
	The Data Payload for the request body to PUT

	.EXAMPLE
	Update-PCAPIDataJSON -URI "https://photonplatform.pigeonnuggets.com/v1/tenants/213291292-1212312/quota -Data "{"id":"12312312312322131"}"

	Will perfrom a HTTP PUT against the Photon Platform https://photonplatform.pigeonnuggets.com/v1/tenants/213291292-1212312/quota and a data payload {"id":"12312312312322131"} and return the response from the API in JSON format

	.NOTES
	  NAME: Update-PCAPIDataJSON
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-17
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller API PUT JSON
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $URI,
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $Data
	)
	if(!$global:DefaultPCServer.IsConnected){
		throw "You are not currently connected to any servers. Please connect first using a Connect-PCServer cmdlet."
	}
	# Create a Web Client for the request
	[string] $strTokenHeader = $Global:DefaultPCServer.TokenType + " " + $Global:DefaultPCServer.AccessToken
	$webclient = New-Object system.net.webclient
	$webclient.Headers.Add("Authorization", "$strTokenHeader")
	$webclient.Headers.Add("Content-Type", "application/json")
	# A bool value used in the loop to control and allow retry in the event of a 401
	[bool] $APICallCompleted = $false
	# To prevent infinite loops
	[int] $intTryCount = 0
	while (-not $APICallCompleted){
		try{
			# Convert the data to a ByteArray for the PUT and perform the call
			[byte[]]$baData = [System.Text.Encoding]::ASCII.GetBytes($Data)
			$Result = $webclient.UploadData($URI, "PUT", $baData)

			$APICallCompleted = $true
			$intRetryCount++

			# Convert the Byte Array to JSON and return
			ConvertFrom-Json([System.Text.Encoding]::ASCII.GetString($Result))
		} catch {
			# Check if the Exception thrown is 401 Unauthorized and try and refresh the token
			if(($intRetryCount -le 1) -and ($_.Exception.GetBaseException().Response.StatusCode -eq "Unauthorized")){
				try{
					Request-TokenRefresh
				} catch {
					# If the token can not be refreshed need to break
					$APICallCompleted = $true
					throw $_
				}
			} else {
				$APICallCompleted = $true
				throw "An error occured attempting to make HTTP PUT against $URI"
			}
		}
		$intRetryCount++
	}
}

function Publish-PCAPIDataJSON(){
	<#
	.SYNOPSIS
	 This cmdlet performs a HTTP POST against the provided URI and returns the JSON Response

	.DESCRIPTION
	 This cmdlet performs a HTTP POST against the provided URI and returns the JSON Response

	.PARAMETER URI
	The URI to make the API POST Request against

	.PARAMETER Data
	Optionally the data to include in the post to the URI

	.EXAMPLE
	Publish-PCAPIDataJSON -URI "https://photonplatform.pigeonnuggets.com/v1/system/enable-service-type" -Data "{`"imageId`":`"XXXXX-XXXXX-XXXXX-XXXXX`",`"type`":`"KUBERNETES`"}"

	Will perfrom a HTTP POST against the Photon Platform https://photonplatform.pigeonnuggets.com/v1/system/enable-service-type and a data payload {"imageId":"XXXXX-XXXXX-XXXXX-XXXXX","type":"KUBERNETES"} and return the response from the API in JSON format

	.EXAMPLE
	Publish-PCAPIDataJSON -URI "https://photonplatform.pigeonnuggets.com/v1/infrastructure/hosts/12/exit-maintenance"

	Will perfrom a HTTP POST against the Photon Platform https://photonplatform.pigeonnuggets.com/v1/infrastructure/hosts/12/exit-maintenance with no data payload and return the response from the API in JSON format

	.NOTES
	  NAME: Publish-PCAPIDataJSON
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-17
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller API POST JSON
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $URI,
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [string] $Data
	)
	if(!$global:DefaultPCServer.IsConnected){
		throw "You are not currently connected to any servers. Please connect first using a Connect-PCServer cmdlet."
	}
	# Create a Web Client for the request
	[string] $strTokenHeader = $Global:DefaultPCServer.TokenType + " " + $Global:DefaultPCServer.AccessToken
	$webclient = New-Object system.net.webclient
	$webclient.Headers.Add("Authorization", "$strTokenHeader")
	$webclient.Headers.Add("Content-Type", "application/json")

	# A bool value used in the loop to control and allow retry in the event of a 401
	[bool] $APICallCompleted = $false
	# To prevent infinite loops
	[int] $intTryCount = 0
	while (-not $APICallCompleted){
		try{
			# Convert the data to a ByteArray for the POST
			[byte[]]$baData = [System.Text.Encoding]::ASCII.GetBytes($Data)
			$Result = $webclient.UploadData($URI, "POST", $baData)

			$APICallCompleted = $true
			$intRetryCount++

			# Convert the Byte Array to JSON and return
			ConvertFrom-Json([System.Text.Encoding]::ASCII.GetString($Result))
		} catch {
			# Check if the Exception thrown is 401 Unauthorized and try and refresh the token
			if(($intRetryCount -le 1) -and ($_.Exception.GetBaseException().Response.StatusCode -eq "Unauthorized")){
				try{
					Request-TokenRefresh
				} catch {
					# If the token can not be refreshed need to break
					$APICallCompleted = $true
					throw $_
				}
			} else {
				$APICallCompleted = $true
				throw "An error occured attempting to make HTTP POST against $URI"
			}
		}
		$intRetryCount++
	}
}

function Remove-PCAPIDataJSON(){
	<#
	.SYNOPSIS
	 This cmdlet performs a HTTP DELETE against the provided URI and returns the JSON Response

	.DESCRIPTION
	 This cmdlet performs a HTTP DELETE against the provided URI and returns the JSON Response

	.PARAMETER URI
	The URI to make the API DELETE Request against

	.PARAMETER Data
	Optionally the data to include in the post to the URI

	.EXAMPLE
	Remove-PCAPIDataJSON -URI "https://photonplatform.pigeonnuggets.com:443/v1/flavors/XXXXX-XXXXX-XXXXX-XXXXX -Data  "{`"id`":`"XXXXX-XXXXX-XXXXX-XXXXX`"}"

	Will perfrom a HTTP DELETE against the Photon Platform https://photonplatform.pigeonnuggets.com/v1/flavors/XXXXX-XXXXX-XXXXX-XXXXX with a JSON data payload to remove the Flavor with ID XXXXX-XXXXX-XXXXX-XXXXX and return the response from the API in JSON format

	.NOTES
	  NAME: Remove-PCAPIDataJSON
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-17
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller API DELETE JSON
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $URI,
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [string] $Data
	)
	if(!$global:DefaultPCServer.IsConnected){
		throw "You are not currently connected to any servers. Please connect first using a Connect-PCServer cmdlet."
	}
	# Create a Web Client for the request
	[string] $strTokenHeader = $Global:DefaultPCServer.TokenType + " " + $Global:DefaultPCServer.AccessToken
	$webclient = New-Object system.net.webclient
	$webclient.Headers.Add("Authorization", "$strTokenHeader")
	$webclient.Headers.Add("Content-Type", "application/json")

	# A bool value used in the loop to control and allow retry in the event of a 401
	[bool] $APICallCompleted = $false
	# To prevent infinite loops
	[int] $intTryCount = 0
	while (-not $APICallCompleted){
		try{
			# Convert the data to a ByteArray for the POST
			[byte[]]$baData = [System.Text.Encoding]::ASCII.GetBytes($Data)
			$Result = $webclient.UploadData($URI, "DELETE", $baData)

			$APICallCompleted = $true
			$intRetryCount++

			# Convert the Byte Array to JSON and return
			ConvertFrom-Json([System.Text.Encoding]::ASCII.GetString($Result))
		} catch {
			# Check if the Exception thrown is 401 Unauthorized and try and refresh the token
			if(($intRetryCount -le 1) -and ($_.Exception.GetBaseException().Response.StatusCode -eq "Unauthorized")){
				try{
					Request-TokenRefresh
				} catch {
					# If the token can not be refreshed need to break
					$APICallCompleted = $true
					throw $_
				}
			} else {
				$APICallCompleted = $true
				throw "An error occured attempting to make HTTP DELETE against $URI"
			}
		}
	$intRetryCount++
	}
}

# UNTESTED
function Publish-PCAPIDataMultiPart(){
	<#
	.SYNOPSIS
	 This cmdlet performs a HTTP POST of type Multipart/form-data against the provided URI and returns the JSON Response.

	.DESCRIPTION
	 This cmdlet performs a HTTP POST of type Multipart/form-data against the provided URI and returns the JSON Response. This cmdlet
	 expects a collection of parts to be uploaded.

	 ** TEST METHOD ** Should be only one method for both types testing if this works first

	.PARAMETER URI
	The URI to make the API POST Request against

	.PARAMETER Data
	The Mulitpart Data to include in the post to the URI

	.EXAMPLE
	Publish-PCAPIDataMultiPart -URI "https://photonplatform.pigeonnuggets.com/v1/images" -Data "XXXXXX"

	Will perfrom a HTTP POST against the Photon Platform https://photonplatform.pigeonnuggets.com/v1/images and a data payload XXXXXXX and return the response from the API in JSON format

	.NOTES
	  NAME: Publish-PCAPIDataMultiPart
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-10-04
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller API POST JSON
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $URI,
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [string] $Data
	)
	if(!$global:DefaultPCServer.IsConnected){
		throw "You are not currently connected to any servers. Please connect first using a Connect-PCServer cmdlet."
	}
	# Create a Web Client for the request
	[string] $strTokenHeader = $Global:DefaultPCServer.TokenType + " " + $Global:DefaultPCServer.AccessToken

	$URIHeaders = @{
		'Authorization' = $strTokenHeader
		'Content-Type' = "application/json"
	}
	# A bool value used in the loop to control and allow retry in the event of a 401
	[bool] $APICallCompleted = $false
	# To prevent infinite loops
	[int] $intTryCount = 0
	while (-not $APICallCompleted){
		try{
			# Make the call to the API
			$Request = Invoke-WebRequest -Uri $URI -Body $multipartContent -Method Post	-Headers $URIHeaders
			(ConvertFrom-Json $Request.Content).value
		} catch {
			# Check if the Exception thrown is 401 Unauthorized and try and refresh the token
			if(($intRetryCount -le 1) -and ($_.Exception.GetBaseException().Response.StatusCode -eq "Unauthorized")){
				try{
					Request-TokenRefresh
				} catch {
					# If the token can not be refreshed need to break
					$APICallCompleted = $true
					throw $_
				}
			} else {
				$APICallCompleted = $true
				throw "An error occured attempting to make HTTP POST against $URI"
			}
		}
		$intRetryCount++
	}
}
#endregion

#region: Support Functions
function Test-ValidCIDRRange(){
	<#
	.SYNOPSIS
	 This cmdlet returns true if a provided string matches an IP range in CIDR Format

	.DESCRIPTION
	 This cmdlet returns true if a provided string matches an IP range in CIDR Format

 	.PARAMETER IPAddressRange
	The IP address range to test against

	.EXAMPLE
	Test-ValidCIDRRange "10.10.0.0/16"
	Returns a true as the provided value is in the correct format

	.NOTES
	  NAME: Test-ValidCIDRRange
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-10-06
	  STATE: Alpha (Testing)
	 #>
	Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True)]
			[ValidateNotNullorEmpty()] [string] $IPAddressRange
	)
	($IPAddressRange -match "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))")
}

function Test-ValidIPString(){
	<#
	.SYNOPSIS
	 This cmdlet returns true if a provided string matches a valid pattern for a single IP

	.DESCRIPTION
	 This cmdlet returns true if a provided string matches a valid pattern for a single IP

 	.PARAMETER IPAddress
	The IP address to test against

	.EXAMPLE
	Test-ValidIPString "10.10.0.0"
	Returns a true as the provided value is in the correct format

	.NOTES
	  NAME: Test-ValidIPString
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-10-06
	  STATE: Alpha (Testing)
	 #>
	Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True)]
			[ValidateNotNullorEmpty()] [string[]] $IPAddress
	)
	[bool] $boolValid = $true
	foreach($objIP in $IPAddress){
		if(!($objIP -match "([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")){
			$boolValid = $false
		}
	}
	$boolValid
}
#endregion

#region: Task Management
function Watch-TaskCompleted(){
	<#
	.SYNOPSIS
	 This cmdlet monitors a running task and returns True when the task completes.

	.DESCRIPTION
	 This cmdlet monitors a running task and returns True when the task completes

	.PARAMETER Task
	A PSObject containing a Task object returned by an API POST call

	.PARAMETER Timeout
	Optionally the timeout in seconds before the cmdlet should terminate if the task has not completed.

	Default is 60 seconds.

	.EXAMPLE
	Watch-TaskCompleted -Task $RemoveTask -Timeout 60

	Monitors the task in the object $RemoveTask for a maximum of 60 seconds and returns True when the task completes

	.NOTES
	  NAME: Watch-TaskCompleted
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-17
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller task
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [PSObject] $Task,
		[Parameter(Mandatory=$False)]
			[ValidateRange(1,3600)] [int] $Timeout = 60
	)
	$boolTaskComplete = $false
    Do {
		$objTaskStatus = Get-PCAPIResponseJSON -URI $Task.selfLink
		if($objTaskStatus.state -eq "ERROR"){
			throw "An error occured execuitng task $($objTaskStatus.operation) for host with $($objTaskStatus.entity.id). Errors: $($objTaskStatus.steps.errors.message)"
			Break
		} elseif($objTaskStatus.state -eq "COMPLETED"){
			$boolTaskComplete = $true
		}
        $Timeout--
        Start-Sleep -Seconds 1
    } Until (($Timeout -eq 0) -or $boolTaskComplete)
	if(($Timeout -eq 0) -and !$boolTaskComplete){
		throw "A timeout occured waiting for the task $($Task.operation) for host with $($Task.entity.id) to complete."
	}
	$boolTaskComplete
}
#endregion


#region: AvailabilityZone
function Get-AvailabilityZone(){
	<#
	.SYNOPSIS
	 This cmdlet returns a collection of Availability Zones as defined on the Photon Controller

	.DESCRIPTION
	 This cmdlet returns a collection of Availability Zones as defined on the Photon Controller

	.PARAMETER Name
	Optionally the Name of the Availability Zone to filter the results by.

	.EXAMPLE
	Get-AvailabilityZone

	Returns a collection of all configured Availability Zones Photon Platform

	.EXAMPLE
	Get-AvailabilityZone -Name "West Coast"

	Returns the Availability Zone with the Name "West Coast" if it exists on the Photon Platform.

	.NOTES
	  NAME: Get-AvailabilityZone
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-02
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller availability zones
	#>
	Param(
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [string] $Name
	)
	# Make API call to return the zones
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/zones"
	$colAPIZones = (Get-PCAPIResponseJSON -URI $URI).items
	# Filter the objects based on Name if provided
	if(!([string]::IsNullOrEmpty($Name))){
		$colAPIZones = $colAPIZones | ?{$_.Name -eq $Name}
	}
	# Collection to add our constructed objects to for return to the caller
	$colAvailabilityZones = New-Object -TypeName System.Collections.ArrayList
	foreach($zone in $colAPIZones){
		$objZone = New-Object System.Management.Automation.PSObject
		$objZone | Add-Member Note* Id $zone.id
		$objZone | Add-Member Note* Name $zone.name
		$objZone | Add-Member Note* State $zone.state
		$objZone | Add-Member Note* Tags $zone.tags
		$colAvailabilityZones.Add($objZone) > $null
	}
	$colAvailabilityZones
}

#### UNTESTED : ALSO REQUIRES THAT GET-CLOUDHOST IS AMENDED
function Set-AvailabilityZone(){
	<#
	.SYNOPSIS
	 This cmdlet sets the Availability Zones for a Photon Cloud Host

	.DESCRIPTION
	 This cmdlet sets the Availability Zones for a Photon Cloud Host

	.PARAMETER HostName
	The Name of the Cloud Host

	.PARAMETER HostId
	The Id of the Cloud Host

	.PARAMETER AvailabilityZone
	The Name of the Availability Zone

	.EXAMPLE
	Set-AvailabilityZone -HostName "photonesx1.photon.pigeonnuggets.com" -AvailabilityZone "APAC-Brisbane"

	Sets the availability zone for Cloud Host with the DNS Hostname "photonesx1.photon.pigeonnuggets.com" to the Availability Zone "APAC-Brisbane"

	.EXAMPLE
	Set-AvailabilityZone -HostId "XXXX-XXXXX-XXXXX-XXXXX-XXXXX" -AvailabilityZone "APAC-Brisbane"

	Sets the availability zone for Cloud Host with the Id "XXXX-XXXXX-XXXXX-XXXXX-XXXXX" to the Availability Zone "APAC-Brisbane"

	.NOTES
	  NAME: Set-AvailabilityZone
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-02
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller availability zones
	#>
	Param(
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $HostName,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $HostId,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $AvailabilityZone
	)
	# Get the Host Object
	if($PSCmdlet.ParameterSetName -eq "ByName"){
		$CloudHost = Get-CloudHosts -CloudHost $HostName
	}
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$CloudHost = Get-CloudHosts -Id $HostId
	}
	# Check that the host exists
	if($CloudHost -eq $null){
		throw "A host could not be found with the provided filter. Please check the provided values and try again."
	}
	# Next check if the AvailabilityZone exists and retreive it
	$objAvailabilityZone = Get-AvailabilityZone -Name $AvailabilityZone
	if($objAvailabilityZone -eq $null){
		throw "An availability zone with the name $AvailabilityZone does not exist. Please check the name and try again."
	}
	# We have what we need set the values
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/infrastructure/hosts/" + $CloudHost.Id + "/set_availability_zone"
	[string] $DataPayload = "{`"availabilityZoneId`":`"$($objAvailabilityZone.id)`"}"
	$UpdateTask = Publish-PCAPIDataJSON -URI $URI -Data $DataPayload
	$objTaskComplete = Watch-TaskCompleted -Task $UpdateTask -Timeout 60
	if($objTaskComplete){
		if((Get-CloudHosts -CloudHost $CloudHost.Name).AvailabilityZone -eq $AvailabilityZone){
			$true
		} else{
			$false
		}
	}
}

function Remove-AvailabilityZone(){
	<#
	.SYNOPSIS
	 This cmdlet removes an Availability Zones on the Photon Controller if it exists

	.DESCRIPTION
	 This cmdlet removes an Availability Zones on the Photon Controller if it exists

	.PARAMETER Name
	The Name of the Availability Zone

	.EXAMPLE
	Remove-AvailabilityZone -Name "APAC-Brisbane"

	Removes the Availability Zone named "APAC-Brisbane" on the Photon Platform if it exists

	.NOTES
	  NAME: Remove-AvailabilityZone
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-02
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller availability zones
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $Name
	)
	# First check if the Availabily Zone exists
	$AvailabilityZone = Get-AvailabilityZone -Name $Name
	if($AvailabilityZone -eq $null){
		throw "An availability zone with the name $Name does not exist. Please check the name and try again."
	}
	# Make the API call to create the zone
	$URI =  $Global:DefaultPCServer.ServiceURI + "v1/zones/" + $AvailabilityZone.id
	[string] $DataPayload = "{`"id`":`"($AvailabilityZone.id)`"}"
	$RemoveTask = Remove-PCAPIDataJSON -URI $URI -Data $DataPayload
	$objTaskComplete = Watch-TaskCompleted -Task $RemoveTask -Timeout 60
	if($objTaskComplete){
		if((Get-AvailabilityZone -Name $Name).State -eq "PENDING_DELETE"){
			$true
		} else{
			$false
		}
	}
}

function New-AvailabilityZone(){
	<#
	.SYNOPSIS
	 This cmdlet creates a new Availability Zones on the Photon Controller

	.DESCRIPTION
	 This cmdlet creates a new Availability Zones on the Photon Controller

	.PARAMETER Name
	The Name of the Availability Zone

	.EXAMPLE
	New-AvailabilityZone -Name "APAC-Brisbane"

	Creates a new Availability Zone named "APAC-Brisbane" on the Photon Platform

	.NOTES
	  NAME: New-AvailabilityZone
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-02
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller availability zones
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $Name
	)
	# First check if the Availabily Zone exists
	if((Get-AvailabilityZone -Name $Name) -ne $null){
		throw "An availability zone with the name $Name already exists."
	}
	# Make the API call to create the zone
	$URI =  $Global:DefaultPCServer.ServiceURI + "v1/zones"
	[string] $DataPayload = "{`"name`":`"$Name`"}"
	$CreateTask = Publish-PCAPIDataJSON -URI $URI -Data $DataPayload
	$objTaskComplete = Watch-TaskCompleted -Task $CreateTask -Timeout 60
	if($objTaskComplete){
		if((Get-AvailabilityZone -Name $Name) -ne $null){
			$true
		} else{
			$false
		}
	}
}
#endregion

#region: HostManagement
function Get-CloudHosts(){
	<#
	.SYNOPSIS
	 This cmdlet returns a collection of Cloud Hosts defined on the Photon Controller

	.DESCRIPTION
	 This cmdlet returns a collection of Cloud Hosts defined on the Photon Controller

	.PARAMETER CloudHost
	Optionally the IP address or DNS hostname of a Host to use as a filter

	.PARAMETER ById
	Optionally the Host Id to use as a filter

	.EXAMPLE
	Get-CloudHosts
	Returns a collection of Cloud Hosts configured on the Photon Platform

	.EXAMPLE
	Get-CloudHosts -Host "192.168.10.20"
	Returns the host details for the host with the IP 192.168.10.20

	.EXAMPLE
	Get-CloudHosts -Host "photonesx1.photon.pigeonnuggets.com"
	Returns the host details for the host with the DNS Hostname photonesx1.photon.pigeonnuggets.com

	.EXAMPLE
	Get-CloudHosts -Id "XXXX-XXXXX-XXXXX-XXXXX-XXXXX"
	Returns the host details for the host with the Host Id XXXX-XXXXX-XXXXX-XXXXX-XXXXX

	.NOTES
	  NAME: Get-CloudHosts
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-02
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller cloud hosts
	#>
	[CmdletBinding(DefaultParameterSetName="Default")]
	Param(
		[Parameter(Mandatory=$False,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $CloudHost,
		[Parameter(Mandatory=$False,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $Id
	)
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/infrastructure/hosts"
	# Collection of Cloud Hosts
	$colAPICloudHosts = (Get-PCAPIResponseJSON -URI $URI).items

	# Check if a filter for Name has been provided
	if($PSCmdlet.ParameterSetName -eq "ByName"){
		# Find the host with the IP or DNS host name provided
		if(!($CloudHost -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")){
			# Perform a lookup of the name in DNS so we can match the host data
			try{
				[string]$HostIP = (Resolve-DnsName $CloudHost -DnsOnly).IPAddress
			} catch {
				throw "The hostname $Host can not be resolved in DNS. Please check the hostname and try again."
			}
		} else {
			[string]$HostIP = $CloudHost
		}
		$colAPICloudHosts = $colAPICloudHosts | ?{$_.address -eq $HostIP}
	}
	# Check if a filter for Id has been provided
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$colAPICloudHosts = $colAPICloudHosts | ?{$_.Id -eq $Id}
	}
	# Collection to add our constructed objects to for return to the caller
	$colCloudHosts = New-Object -TypeName System.Collections.ArrayList
	foreach($hostObject in $colAPICloudHosts){
		$objPhotonHost = New-Object System.Management.Automation.PSObject
		$objPhotonHost | Add-Member Note* Id $hostObject.id
		$objPhotonHost | Add-Member Note* IPAddress $hostObject.address
		$objPhotonHost | Add-Member Note* ESXVersion $hostObject.esxVersion
		$objPhotonHost | Add-Member Note* State $hostObject.state
		$objPhotonHost | Add-Member Note* Metadata $hostObject.metadata
		$objPhotonHost | Add-Member Note* UsageTags $hostObject.UsageTags
		$objPhotonHost | Add-Member Note* AvailabilityZone $hostObject.AvailabilityZone
		$colCloudHosts.Add($objPhotonHost) > $null
	}
	$colCloudHosts
}

function Enter-HostSuspendMode(){
	<#
	.SYNOPSIS
	 This cmdlet places a Cloud Hosts on the Photon Controller into Suspend mode.

	.DESCRIPTION
	 This cmdlet places a Cloud Hosts on the Photon Controller into Suspend mode.

	.PARAMETER ESXiHost
	The IP address or DNS hostname of the Host to place into Suspend.

	.EXAMPLE
	Enter-HostSuspendMode -ESXiHost "192.168.10.20"
	Places the cloud host with the IP 192.168.10.20 into suspend mode in Photon Platform.

	.EXAMPLE
	Enter-HostSuspendMode -ESXiHost "photonesx1.photon.pigeonnuggets.com"
	Places the cloud host with the DNS Hostname photonesx1.photon.pigeonnuggets.com	into suspend mode in Photon Platform.

	.NOTES
	  NAME: Enter-HostSuspendMode
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-06-25
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller cloud hosts suspend
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $ESXiHost
	)
	# Find the host
	$objMaintenanceHost = Get-CloudHosts -CloudHost $ESXiHost
	# Check if the host state is READY and Suspend It
	if($objMaintenanceHost.State -eq "READY"){
		# The host must first be suspended; invoke a Suspend Task
		$URI = $Global:DefaultPCServer.ServiceURI + "v1/infrastructure/hosts/$($objMaintenanceHost.Id)/suspend"
		$objSuspendTask = Publish-PCAPIDataJSON -URI $URI
		# Now check the status of the task; will timeout if the task does not complete within 60 seconds
		$objSuspendTaskComplete = Watch-TaskCompleted -Task $objSuspendTask -Timeout 60
		if($objSuspendTaskComplete){
			if((Get-CloudHosts -CloudHost $ESXiHost).State -eq "SUSPENDED"){
				$true
			} else {
				$false
			}
		}
	} else {
		throw "The current host state is $($objMaintenanceHost.State); the host must be in a READY state to suspend."
	}
}

function Enter-HostMaintenanceMode(){
	<#
	.SYNOPSIS
	 This cmdlet places a Cloud Hosts on the Photon Controller into maintenance mode.

	.DESCRIPTION
	 This cmdlet places a Cloud Hosts on the Photon Controller into maintenance mode.

	.PARAMETER ESXiHost
	The IP address or DNS hostname of the Host to place in maintenance mode.

	.EXAMPLE
	Enter-HostMaintenanceMode -ESXiHost "192.168.10.20"
	Places the cloud host with the IP 192.168.10.20 into maintenance mode in Photon Platform.

	.EXAMPLE
	Enter-HostMaintenanceMode -ESXiHost "photonesx1.photon.pigeonnuggets.com"
	Places the cloud host with the DNS Hostname photonesx1.photon.pigeonnuggets.com	into maintenance mode in Photon Platform.

	.NOTES
	  NAME: Enter-HostMaintenanceMode
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-06-25
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller cloud hosts maintenance
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $ESXiHost
	)
	# Find the host
	$objMaintenanceHost = Get-CloudHosts -CloudHost $ESXiHost
	# Check if the host is already in maintenance mode
	if($objMaintenanceHost.State -eq "MAINTENANCE"){
		throw "The current host state is $($objMaintenanceHost.State); the host must be in a SUSPENDED or READY state to place into maintenance mode."
	}
	# Check if the host state is READY and Suspend It
	if($objMaintenanceHost.State -eq "READY"){
		# The host must first be suspended; invoke a Suspend Task
		Enter-HostSuspendMode -ESXiHost $ESXiHost > $nul
	}
	# Get an updated status for the host
	$objMaintenanceHost = Get-CloudHosts -CloudHost $ESXiHost
	# Now that the suspend job has completed; check the host is suspended and remove the VMs
	if($objMaintenanceHost.State -eq "SUSPENDED"){
		# Remove the Virtual Machines from the host in preparation for placing into maintenance mode
		$URI = $Global:DefaultPCServer.ServiceURI + "v1/infrastructure/hosts/$($objMaintenanceHost.Id)/vms"
		$objRunningVMs = (Get-PCAPIResponseJSON -URI $URI).items
		foreach($objRunningVM in $objRunningVMs){
			# Perform a Delete Operation against the VM
			$result = Remove-CloudVM -Id ($objRunningVM.id)
			if($result -eq $false){
				throw "An error occured removing he running VMs from the host $ESXiHost. The host has not been put in Maintenance Mode as a result"
			}
		}
	}
	# Finally enter Maintenance Mode
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/infrastructure/hosts/$($objMaintenanceHost.Id)/enter-maintenance"
	$objMaintanenceTask = Publish-PCAPIDataJSON -URI $URI
	# Now check the status of the task; will timeout if the task does not complete within 60 seconds
	$objMaintanenceTaskComplete = Watch-TaskCompleted -Task $objMaintanenceTask -Timeout 60
	# Update the status
	$objMaintenanceHost = Get-CloudHosts -CloudHost $ESXiHost
	if($objMaintenanceHost.State -eq "MAINTENANCE"){
		$true
	}
}

Function Exit-HostMaintenanceMode(){
	<#
	.SYNOPSIS
	 This cmdlet removes a Cloud Host on the Photon Controller from maintenance mode.

	.DESCRIPTION
	 This cmdlet removes a Cloud Host on the Photon Controller from maintenance mode.

	.PARAMETER ESXiHost
	The IP address or DNS hostname of the Host to place in maintenance mode.

	.EXAMPLE
	Exit-HostMaintenanceMode -ESXiHost "192.168.10.20"
	Removes the cloud host with the IP 192.168.10.20 from maintenance mode in Photon Platform.

	.EXAMPLE
	Exit-HostMaintenanceMode -ESXiHost "photonesx1.photon.pigeonnuggets.com"
	Removes the cloud host with the DNS Hostname photonesx1.photon.pigeonnuggets.com from maintenance mode in Photon Platform.

	.NOTES
	  NAME: Exit-HostMaintenanceMode
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-06-25
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller cloud hosts maintenance
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $ESXiHost
	)
	# Find the host
	$objMaintenanceHost = Get-CloudHosts -CloudHost $ESXiHost
	# Check if the host is already in maintenance mode
	if(!($objMaintenanceHost.State -eq "MAINTENANCE")){
		throw "The current host state is $($objMaintenanceHost.State); the host must be in a MAINTENANCE to run this cmdlet."
	}
	# TO DO: Maybe add a check if the host is available; this will prevent a No route to host exception being thrown by Photon Platform
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/infrastructure/hosts/$($objMaintenanceHost.Id)/exit-maintenance"
	$objMaintanenceTask = Publish-PCAPIDataJSON -URI $URI
	# Now check the status of the task; will timeout if the task does not complete within 60 seconds
	$objMaintanenceTaskComplete = Watch-TaskCompleted -Task $objMaintanenceTask -Timeout 60
	# Update the status
	$objMaintenanceHost = Get-CloudHosts -CloudHost $ESXiHost
	if($objMaintenanceHost.State -eq "READY"){
		$true
	}
}

# !!! TO DO !!!!
function Add-CloudHost(){
	throw "Not yet implementated"
}

# !!! TO DO !!!!
function Remove-CloudHost(){
	throw "Not yet implementated"
}
#endregion

#region:Image Management
function Get-CloudImage(){
	<#
	.SYNOPSIS
	 Returns a Cloud Image for the provided Image by ID on the Photon Platform

	.DESCRIPTION
	 This cmdlet return a Cloud Image on the Photon Platform and thier properties. If no image is found the funciton returns $null

	 .PARAMETER ImageId
	The ImageId of the Image to return
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $ImageId
	)
	if(!$global:DefaultPCServer.IsConnected){
		throw "You are not currently connected to any servers. Please connect first using a Connect-PCServer cmdlet."
	}
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/images/$ImageId"
	try{
		$Image = Get-PCAPIResponseJSON -URI $URI
	} catch {
		$null
	}
	if($Image -ne $null){
		# Retreive tasks assocaited with the Image
		$strTaskURI = $image.selfLink + "/tasks"
		$colImageTasks = (Get-PCAPIResponseJSON -URI $strTaskURI).items

		# Retrieve the Image Access Management (IAM) for the Image
		$strIAMURI = $image.selfLink + "/iam"
		$colImageIAM = (Get-PCAPIResponseJSON -URI $strIAMURI)
		$objPhotonImage = New-Object System.Management.Automation.PSObject
		$objPhotonImage | Add-Member Note* Id $image.id
		$objPhotonImage | Add-Member Note* Name $image.name
		$objPhotonImage | Add-Member Note* Tags $image.Tags
		$objPhotonImage | Add-Member Note* State $image.state
		$objPhotonImage | Add-Member Note* SizeBytes $image.size
		$objPhotonImage | Add-Member Note* ImageScope $image.scope
		$objPhotonImage | Add-Member Note* ImageSettings $image.settings
		$objPhotonImage | Add-Member Note* ReplicationType $image.replicationType
		$objPhotonImage | Add-Member Note* ReplicationProgress $image.replicationProgress
		$objPhotonImage | Add-Member Note* SeedingProgress $image.seedingProgress
		$objPhotonImage | Add-Member Note* IAM $colImageIAM
		$objPhotonImage | Add-Member Note* Tasks $colImageTasks
		$objPhotonImage
	}
}

# !!! TO DO !!!!
# TO DO: Combine Get-CloudImage and Get-CloudImages
function Get-CloudImages(){
	<#
	.SYNOPSIS
	 Returns a collection of Cloud Images on the Photon Platform

	.DESCRIPTION
	 This cmdlet returns a collection of Cloud Images on the Photon Platform and thier properties
	#>
	if(!$global:DefaultPCServer.IsConnected){
		throw "You are not currently connected to any servers. Please connect first using a Connect-PCServer cmdlet."
	}
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/images"
	# Collection of Cloud Images
	$colAPICloudImages = (Get-PCAPIResponseJSON -URI $URI).items

	# Collection to add our constructed objects to for return to the caller
	$colCloudImages = New-Object -TypeName System.Collections.ArrayList
	foreach($image in $colAPICloudImages){
		$objPhotonImage = Get-CloudImage $image.id
		$colCloudImages.Add($objPhotonImage) > $null
	}
	$colCloudImages
}

function Find-CloudImage(){
	<#
	.SYNOPSIS
	 This cmdlet return a Cloud Hosts defined on the Photon Controller by the IP or Hostname of the Hypervisor

	.DESCRIPTION
	 This cmdlet return a Cloud Hosts defined on the Photon Controller by the IP or Hostname of the Hypervisor

	.PARAMETER ImageName
	The display name of the Image to Query
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $ImageName
	)
	# Get a collection of the Cloud Images
	$colCloudImages = Get-CloudImages
	$foundImage = $colCloudImages | ?{$_.Name -eq $ImageName}
	if($foundImage -eq $null){
		throw "The cloud image with the Name $ImageName can not be found in the Cloud. Please check the detials and try again."
	} else {
		$foundImage
	}
}

# !!! TO DO !!!!
# TO BE TESTED !!! COMPLETELY UNTESTED AT THIS TIME
# Update documentation
function Remove-CloudImage(){
	<#
	.SYNOPSIS
	 Removes an Image from the Photon Platform

	.DESCRIPTION
	 TBD

	.PARAMETER CloudImage
	The Image object of the Cloud Image to remove.
	#>
	Param(
		[Parameter(Mandatory=$True)] [PSObject] $CloudImage
	)
	$RemoveImageURI = $Global:DefaultPCServer.ServiceURI + "v1/images/$($CloudImage.Id)"
	$APIData = "{`"Id`":`"$($CloudImage.Id)`"}"
	$DeleteImage = Remove-PCAPIDataJSON -URI $RemoveImageURI -Data $APIData
}

function Disable-CloudImageServices(){
	<#
	.SYNOPSIS
	 Disables a Service Image in Photon Platform

	.DESCRIPTION
	 This cmdlet disables/unmarks a provided Cloud Service Image

	.PARAMETER Service
	The Service Type to remove the Service (Valid Types: KUBERNETES, HABOUR)
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $Service
	)
	# Check if the service is set and if it is disable it
	$ServiceEnabled = (Get-PCDeploymentConfig | ?{$_.ServiceConfiguration.ServiceType -eq $Service}) -ne $null
	if($ServiceEnabled){
		$DisableURI = $Global:DefaultPCServer.ServiceURI + "v1/system/disable-service-type"
		[string] $DisableData = "{`"type`":`"$Service`"}"
		try{
			$DisableService = Publish-PCAPIDataJSON -URI $DisableURI -Data $DisableData
		} catch {
			throw "An error occured disabling the current image assigned for this service."
		}
	}
	return $true
}

function Set-CloudImageServices(){
	<#
	.SYNOPSIS
	 Marks an Image as a Kubernetes/Habour Image in Photon Platform

	.DESCRIPTION
	 Sets the provided Image as the designated service image for the Photon Platform. This can be used to set
	 the KUBERNETES or HABOUR images for the solution

	.PARAMETER CloudImage
	The display name of the Image to Query

	.PARAMETER Service
	The Service Type to mark the Image as (Valid Types: KUBERNETES, HABOUR)
	#>
	Param(
		[Parameter(Mandatory=$True)] [PSObject] $CloudImage,
		[Parameter(Mandatory=$True)] [string] $Service
	)
	# First check if the provided Cloud Image is valid
	if((Get-CloudImage -ImageId $CloudImage.Id) -eq $null){
		throw "The provided object does not appear to be a valid Cloud Image. Please verify and try again."
	}
	# Next check if the service is already set and if it is disable it
	$DisableService = Disable-CloudImageServices -Service $Service
	# Next set the Service Image
	$SetServiceURI = $Global:DefaultPCServer.ServiceURI + "v1/system/enable-service-type"
	$SetServiceData = "{`"imageId`":`"$($CloudImage.Id)`",`"type`":`"$Service`"}"
	$EnableService = Publish-PCAPIDataJSON -URI $SetServiceURI -Data $SetServiceData
	$objTaskComplete = Watch-TaskCompleted -Task $EnableService -Timeout 60
	if($objTaskComplete){
		$ServiceEnabled = (Get-PCDeploymentConfig | ?{$_.ServiceConfiguration.ServiceType -eq $Service}) -ne $null
		if($ServiceEnabled){
			$true
		} else{
			$false
		}
	}
}

# TESTING REQUIRED !!!!
function Import-CloudImage(){
	<#
	.SYNOPSIS


	.DESCRIPTION


	.PARAMETER Replication
	The replication mode for the image; valid values are "EAGER"; ONDEMAND is presently not supported in v1.2.1

	.PARAMETER ImageName
	The display name for the Image being uploaded

	.PARAMETER FileName
	The Fully Qualified local file path to the OVA file for upload. Image must be either a vmdk or an ova file.

	.EXAMPLE
	Import-CloudImage -Replication "EAGER" -ImageName "Kubernetes" -FileName "D:\Photon\Kubernetes-1.6.ova"

	Will attempt to upload

	.NOTES
	  NAME: Remove-PCAPIDataJSON
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-17
	  STATE: Alpha (Testing)
	  REFERENCE: https://get-powershellblog.blogspot.com.au/2017/09/multipartform-data-support-for-invoke.html
	  REQUIRES: PowerShell 6.0.0-beta.8+
	  NOTES: PowerShell Core now has partial multipart/form-data support in both Web Cmdlets as at PowerShell 6.0.0-beta.8+
	  KEYWORDS: vmware photon controller API DELETE JSON
	#>
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateSet('EAGER',IgnoreCase=$True)] [string] $Replication,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateNotNullorEmpty()] [string] $ImageName,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateScript({Test-Path $_ })] [string] $FileName
	)
	# Load the type System.Net.Http to craft the input
	Add-Type -AssemblyName System.Net.Http

	# Check that the file provided exists and is a VMDK or OVA
	$objImageFile = Get-Item $FileName
	if(!($objImageFile.Extension -in (".ova",".vmdk"))){
		throw "Image must be either a vmdk or an ova file. The provided file $FileName does not appear to be a vmdk or OVA file."
	}
	# Prepare the request to the API
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/images"

	# Construct a MultipartFormData request
	$multipartContent = [System.Net.Http.MultipartFormDataContent]::new()
	$stringHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
	$stringHeader.Name = "ImageReplication"
	$StringContent = [System.Net.Http.StringContent]::new($Replication)
	$StringContent.Headers.ContentDisposition = $stringHeader
	$multipartContent.Add($stringContent)

	$multipartFile = $FileName
	$FileStream = [System.IO.FileStream]::new($multipartFile, [System.IO.FileMode]::Open)
	$fileHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
	$fileHeader.Name = $ImageName
	$fileHeader.FileName = $objImageFile.Name
	$fileContent = [System.Net.Http.StreamContent]::new($FileStream)
	$fileContent.Headers.ContentDisposition = $fileHeader
	$fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
	$multipartContent.Add($fileContent)

	# Make the request to the caller
	$NewImageTask = Publish-PCAPIDataMultiPart -URI $URI -Data $multipartContent
	$objTaskComplete = Watch-TaskCompleted -Task $NewImageTask -Timeout 60
	if($objTaskComplete){
		if((Find-CloudImage -ImageName $ImageName) -eq $null){
			$true
		} else{
			$false
		}
	}
	$FileStream.Close()
	$fileContent.Close()
}

# !!! TO DO !!!!
# - Get/Set/Modify Image Access Management Policy
function Set-CloudImageIAM(){
	throw "Not yet implementated"
}
#endregion

#region:Services
# TO DO: Work on this alot more :)
function Get-CloudServices(){
	<#
	.SYNOPSIS
	 Returns a collection of Cloud Services currently configured for the deployment

	.DESCRIPTION
	 Returns a collection of Cloud Services currently configured for the deployment

	.EXAMPLE
	Get-CloudServices

	Returns a collection of the currently configured services.

	.NOTES
	  NAME: Get-CloudServices
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-18
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller services
	  REFERENCE:
	#>
	$ServiceConfiguration = (Get-PCDeploymentConfig).ServiceConfiguration
	$ServiceConfiguration
}

# UNTESTED/Development Code
function Enter-ServiceMaintenance(){
#POST /v1/services/{id}/trigger_maintenance
# JSON: {"id" : ""}
	throw "Not yet implementated"
}

function Set-ServiceVersion(){
#POST /v1/services/{id}/change_version
#JSON { "id" : ""
# ServiceChangeVersionOperation {
#	 newImageId (String): This property specifies the ID of the image for which the service will use to change versions.
#	}
#}
	throw "Not yet implementated"
}

# UNTESTED
function Resize-CloudService(){
	<#
	.SYNOPSIS
	 Resizes and existing Cloud Service and sets the Slave and Worker Count for the specified Service

	.DESCRIPTION
	 TBD

	.PARAMETER Service
	The Name of the Service to resize (Valid Types: KUBERNETES, HABOUR)

	.PARAMETER WorkerCount
	This property specifies the desired number of worker VMs.

	.EXAMPLE
	Resize-CloudService -Id XXXXX-XXXXX-XXXXX-XXXXX -WorkerCount 10
	Will resize the Cloud Service with the Id XXXXX-XXXXX-XXXXX-XXXXX and set a WorkerCount of 10

	.NOTES
	  NAME: Resize-CloudService
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-25
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller resize service
	  REFERENCE:
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $Service,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,4000)] [int] $WorkerCount
	)
	# Next get the Service Id/check that the service exists
	## TO DO !!!!!!
	$serviceId = ""

	$SetServiceURI = $Global:DefaultPCServer.ServiceURI + "v1/services/" + + "/resize"
	# Add the properties to the ServiceResizeOperation
	$objServiceResizeOperation = New-Object System.Management.Automation.PSObject
	$objServiceResizeOperation | Add-Member Note* newWorkerCount $WorkerCount

	# Create an object and parse to JSON and post to the API
	$objServiceResize = New-Object System.Management.Automation.PSObject
	$objServiceResize | Add-Member Note* id $serviceId
	$objServiceResize | Add-Member Note* ServiceResizeOperation $objServiceResizeOperation
	$objTaskServiceResize = Publish-PCAPIDataJSON -URI $SetServiceURI -Data (ConvertTo-JSON $objServiceResize)

	# Watch the task for completion and check the resize operation has occured; need to validate the the update occured
	$objTaskComplete = Watch-TaskCompleted -Task $objTaskServiceResize -Timeout 60
	if($objTaskComplete){
		$true
	} else{
		$false
	}
}

function New-CloudKubernetesService(){
	<#
	.SYNOPSIS
	 This cmdlet creates a new Kubernetes Cloud Service in a Project on the Photon Platform.

	.DESCRIPTION
	This cmdlet creates a new Kubernetes Cluster in a Project on the Photon Platform.

	.PARAMETER TenantName
	The Name of the Tenancy hosting the Project

	.PARAMETER ProjectName
	The Name of the Project (can not include any spaces) hosting the service

	.PARAMETER ServiceName
	The Name of the new Kubernetes Cluster

	.PARAMETER Subnet
	The Name of the Cloud Subnet (from Get-CloudSubnet) for the Service Mangement VMs to tbe deployed

	.PARAMETER MasterIP
	The IP addresses of the Master Nodes for the Kubernetes Service

	.PARAMETER NumberOfMasters
	The number of master nodes to deploy

	.PARAMETER DNSIP
	The IP address of the DNS Server for Kubernetes machines

	.PARAMETER GatewayIP
	The IP address of the Default Gateway for Kubernetes machines

	.PARAMETER SubnetMask
	The Subnet Mask for the Management VM Networks (eg. 255.255.255.0)

	.PARAMETER LoadBalancerIP
	The IP address of the Load Balancer for the Kubernetes Service

	.PARAMETER ContainerNetwork
	The Network for the Container in CIDR format (eg. 10.2.0.0/16)

	.PARAMETER ETCDCluster
	Default: False
	If set to true an ETCD Cluster will be deployed.

	.PARAMETER ETCDIP
	A string array of IP addresses for the ETCD Service; if ETCDCluster is false One IP is required; if it is true 3 IPs must be provided

	.PARAMETER Flavor
	The Flavor to use for the Service VM Deployment

	.PARAMETER DiskFlavor

	.PARAMETER WorkerCount

	.PARAMETER WorkerBatchExpansionSize


	.EXAMPLE
	New-CloudProject -TenantName "Marketing" -ProjectName "Marketing-Campaign-2017" -CPUCost 10 -MemoryGBCost 50 -VMCountCost 20 -DiskCount 10 -StorageQuota 100 -SecurityGroups "photon.pigeonnuggets.com\MarketingAdmins"
	Adds a new Cloud Project to the "Marketing" tenant with the Name "Marketing-Campaign-2017" with a CPU Count of 10, Memory Cost of 50GB, VM count of 20, a Disk Count of 10 and a Storage Quota of 100GB and  and a VM count of 20 and assigns the group MarketingAdmins permission to the project

	.NOTES
	  NAME: New-CloudService
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-10-06
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller new services cluster
	  REFERENCE:
	#>
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateNotNullorEmpty()] [string] $ProjectName,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateNotNullorEmpty()] [string] $ServiceName,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,4000)] [int] $NumberOfMasters,
		[Parameter(Mandatory=$True)]
			[ValidateScript({($NumberOfMasters -eq $_.Count) -and (Test-ValidIPString $_)})] [string[]] $MasterIP,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateScript({Test-ValidIPString $_ })] [string] $DNSIP,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateScript({Test-ValidIPString $_ })] [string] $GatewayIP,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateScript({Test-ValidIPString $_ })] [string] $SubnetMask,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateScript({Test-ValidIPString $_ })] [string] $LoadBalancerIP,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateScript({Test-ValidCIDRRange $_ })] [string] $ContainerNetwork,
		[Parameter(Mandatory=$True)]
			[bool] $ETCDCluster = $false,
		[Parameter(Mandatory=$True)]
			[ValidateScript({($_.Count -in @(1,3)) -and (Test-ValidIPString $_)})] [string[]] $ETCDIP,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateNotNullorEmpty()] [string] $Flavor,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False)]
			[ValidateNotNullorEmpty()] [string] $DiskFlavor,
		[Parameter(Mandatory=$False, ValueFromPipeline=$False)]
			[ValidateRange(1,10000)] [int] $WorkerCount = 1,
		[Parameter(Mandatory=$False, ValueFromPipeline=$False)]
			[ValidateRange(1,10000)] [int] $WorkerBatchExpansionSize = 1
	)
	throw "Not yet implemented"
}
#endregion

#region: Subnets
function Get-CloudSubnets(){
	<#
	.SYNOPSIS
	 This cmdlet returns a collection of Cloud Subnet Objects

	.DESCRIPTION
	 This cmdlet returns a collection of Cloud Subnet Objects

 	.PARAMETER Name
	Optionally a filter for the Name of the Subnet

	.PARAMETER Tags
	Optionally a filter for Subnet tagged with the provided Tags

	.PARAMETER Id
	Optionally a filter for the Subnet based on the Subnet Id

 	.EXAMPLE
	Get-CloudSubnets
	Returns a collection of Cloud Subnets defined on the Photon Plaform

 	.EXAMPLE
	Get-CloudSubnets -Name "TestSubnet1"
	Returns a Cloud Subnet with the Name "TestSubnet1" if it exists

	.EXAMPLE
	Get-CloudSubnets -Tags "Prod"
	Returns a collection of Cloud Subnets with the Tag "Prod"

	.EXAMPLE
	Get-CloudSubnets -Id "XXXXX-XXXXX-XXXXX-XXXXX"
	Returns the Cloud Subnets with the Id XXXXX-XXXXX-XXXXX-XXXXX if it exists

	.NOTES
	  NAME: Get-CloudSubnets
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-21
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller subnets
	  REFERENCE:
	 #>
	[CmdletBinding(DefaultParameterSetName="Default")]
	Param(
		[Parameter(Mandatory=$False,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $Name,
		[Parameter(Mandatory=$False,ParameterSetName = "ByTag")]
			[ValidateNotNullorEmpty()] [string[]] $Tags,
		[Parameter(Mandatory=$False,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $Id
	)
	$URISunet =  $Global:DefaultPCServer.ServiceURI + "v1/subnets"
	# Get the Subnets for the Platform
	$Subnets = (Get-PCAPIResponseJSON -URI $URISunet).items

	# Filter the results if filters have been provided
	if($PSCmdlet.ParameterSetName -eq "ByName"){
		$Subnets = $Subnets | ?{$_.Name -eq $Name}
	}
	if($PSCmdlet.ParameterSetName -eq "ByTag"){
		$Subnets = $Subnets | ?{$_.tags -contains $Tags}
	}
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$Subnets = $Subnets | ?{$_.Id -eq $Id}
	}
	# Create a Collection of Subnet Objects
	$colSubnets = New-Object -TypeName System.Collections.ArrayList
	foreach($subnet in $Subnets){
		$objSubnet = New-Object System.Management.Automation.PSObject
		$objSubnet | Add-Member Note* Id $subnet.id
		$objSubnet | Add-Member Note* Name $subnet.name
		$objSubnet | Add-Member Note* Tags $subnet.tags
		$objSubnet | Add-Member Note* Kind $subnet.kind
		$objSubnet | Add-Member Note* Description $subnet.description
		$objSubnet | Add-Member Note* "Type" $subnet.type
		$objSubnet | Add-Member Note* DefaultSubnet $subnet.isDefault
		$objSubnet | Add-Member Note* State $subnet.state
		$objSubnet | Add-Member Note* PortGroup $subnet.portGroups.Names
		$colSubnets.Add($objSubnet) > $nul
	}
	$colSubnets
}

function Remove-CloudSubnet(){
	<#
	.SYNOPSIS
	 This cmdlet deletes a Cloud Subnet from the Photon Platform

	.DESCRIPTION
	 This cmdlet deletes a Cloud Subnet from the Photon Platform

 	.PARAMETER Name
	The Name of the Subnet to remove.

	.EXAMPLE
	Remove-CloudSubnet -Name "Prod"
	Deletes the Cloud Subnet with the name "Prod"

	.NOTES
	  NAME: Remove-CloudSubnet
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-21
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller subnet delete
	  REFERENCE:
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $Name
	)
	$Subnet = Get-CloudSubnets -Name $Name
	if($Subnet -eq $null){
		throw "No subnet found with the name $Name. Check the name and try again."
	}
	# The default subnet can also not be removed; a new one must be set first
	if($Subnet.DefaultSubnet){
		throw "The specified Subnet is currently the default for the Platform and can not be removed. Please set a new default and try again."
	}
	$URIRemoveSubnet =  $Global:DefaultPCServer.ServiceURI + "v1/subnets/" + $Subnet.Id
	[string] $DataPayload = "{`"id`":`"$($Subnet.Id)`"}"
	$RemoveTask = Remove-PCAPIDataJSON -URI $URIRemoveSubnet
	$objTaskComplete = Watch-TaskCompleted -Task $RemoveTask -Timeout 60
	if($objTaskComplete){
		if((Get-CloudSubnets -Name $Name) -eq $null){
			$true
		} else{
			$false
		}
	}
}

function New-CloudSubnet(){
	<#
	.SYNOPSIS
	 This cmdlet creates a Cloud Subnet from the Photon Platform

	.DESCRIPTION
	 This cmdlet creates a Cloud Subnet from the Photon Platform

 	.PARAMETER Name
	The Name of the Subnet

	.PARAMETER Description
	A Description for the Subnet

	.PARAMETER PortGroup
	The Port Group Label of the Port Group on the ESXi hosts backing the Cloud Subnet

	.PARAMETER DNSServers
	NOT IMPLEMENTED IN API AT THIS TIME !!!
	The IP addresses of the DNS server that will be used by the subnet

	.PARAMETER PrivateIPCIDR
	NOT IMPLEMENTED IN API AT THIS TIME !!!
	CIDR of the private IPs of the subnet

	.PARAMETER Default
	Optionally sets the Subnet as the default for the deployment

	.PARAMETER Tags
	NOT IMPLEMENTED IN API AT THIS TIME !!!
	Optionally the tags to add to the subnet

	.EXAMPLE
	New-CloudSubnet -Name "Prod"
	Creates the Cloud Subnet with the name "Prod"

	.EXAMPLE
	New-CloudSubnet -Name "Lab" -Description "Network for hosting the K8S containers" -PortGroups "VM Network" -Default $true
	Creates a Network Lab bound to the PortGroup "VM Network" on the backend and sets this as the default

	.NOTES
	  NAME: New-CloudSubnet
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-21
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller subnet create
	  REFERENCE:
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $Name,
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $Description,
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string[]] $PortGroups,
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [string[]] $DNSServers,
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [string] $PrivateIPCIDR,
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [string[]] $Tags,
		[Parameter(Mandatory=$False)]
			[bool] $Default = $false
	)
	# Create an object with the mandatory properties for constructing the JSON call
	$objSubnet = New-Object System.Management.Automation.PSObject
	$objSubnet | Add-Member Note* name $Name
	$objSubnet | Add-Member Note* description $Description
	# Create a nested object to correctly form the JSON
	$objPortGroup = New-Object System.Management.Automation.PSObject
	$objPortGroup | Add-Member Note* names $PortGroups
	$objSubnet | Add-Member Note* portGroups $objPortGroup

	# Check if tags have been provided and add them to the object
	if(!([string]::IsNullOrEmpty($Tags))){
		$objSubnet | Add-Member Note* Tags $Tags
	}
	# Check if the CIDR Range has been provided and if it is valid
	if(!([string]::IsNullOrEmpty($PrivateIPCIDR))){
		if(Test-ValidCIDRRange $PrivateIPCIDR){
			$objSubnet | Add-Member Note* privateIpCidr $PrivateIPCIDR
		} else {
			throw "The CIDR of the private IPs provided $PrivateIPCIDR is not in a valid format. Please review and try again."
		}
	}
	# Check if a DNS Specification was provided
	if(!([string]::IsNullOrEmpty($DNSServers))){
		$objSubnet | Add-Member Note* dnsServerAddresses $DNSServers
	}

	# Make the POST to the Photon Platform to create the Subnet Object
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/subnets"
	$objCreateSubnet = Publish-PCAPIDataJSON -URI $URI -Data (ConvertTo-JSON $objSubnet)
	$objTaskComplete = Watch-TaskCompleted -Task $objCreateSubnet -Timeout 60
	if($objTaskComplete){
		$objPlatformSubnet = Get-CloudSubnets -Name $Name
		if($objPlatformSubnet -ne $null){
			# Check if the Subnet needs to be set as default
			if($Default){
				# Make the call to the function to set the default subnet
				$setDefault = Set-CloudSubnetDefault -Id $objPlatformSubnet.Id
				if($setDefault){
					$true
				} else {
					Write-Warning "The subnet has been created however an error occured setting it as the default subnet."
				}
			}
			$true
		} else{
			$false
		}
	}
}

function Set-CloudSubnetDefault(){
	<#
	.SYNOPSIS
	 This cmdlet sets the specified Cloud Subnet as the Default for the Photon Platform

	.DESCRIPTION
	 This cmdlet sets the specified Cloud Subnet as the Default for the Photon Platform

 	.PARAMETER Name
	The Name of the Subnet

	.PARAMETER Id
	The unique identified of the Subnet

	.EXAMPLE
	New-CloudSubnet -Name "Prod"
	Creates the Cloud Subnet with the name "Prod"

	.NOTES
	  NAME: Set-CloudSubnetDefault
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-02
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller subnet default
	  REFERENCE:
	#>
	param(
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $Name,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $Id
		)
	# Check if the Subnet exists
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$objSubnet = Get-CloudSubnets -Id $Id
		if($objSubnet -eq $null){
			throw "A subnet with the ID of $Id cannot be found. Please check the Id and try again."
		}
	} elseif($PSCmdlet.ParameterSetName -eq "ByName"){
		$objSubnet = Get-CloudSubnets -Name $Name
		if($objSubnet -eq $null){
			throw "A subnet with the Name of $Name cannot be found. Please check the subnet name and try again."
		}
	}
	# Now set as the default
	$URI =  $Global:DefaultPCServer.ServiceURI + "v1/subnets/" + $objSubnet.Id + "/set_default"
	[string] $DataPayload = "{`"id`":`"$($objSubnet.Id)`"}"
	$UpdateTask = Publish-PCAPIDataJSON -URI $URI -Data $DataPayload
	$objTaskComplete = Watch-TaskCompleted -Task $UpdateTask -Timeout 60
	if($objTaskComplete){
		if(((Get-CloudSubnets -Id $objSubnet.Id).DeafultSubnet) -eq $true){
			$true
		} else{
			$false
		}
	}
}
#endregion

#region:Quotas
function New-CloudQuota(){
	<#
	.SYNOPSIS
	 This cmdlet creates a new Cloud Quota specification object for the Photon Platform for Tenants and Projects.

	.DESCRIPTION
	This cmdlet creates a new Cloud Quota specification object for the Photon Platform for Tenants and Projects.

	.PARAMETER CPUCost
	The vCPU Count quota for the new Project. This can not exceed the quota available to the tenancy.

	.PARAMETER MemoryGBCost
	The Memory quota in GB for the new Project. This can not exceed the quota available to the tenancy.

	.PARAMETER VMCountCost
	The count (number) of VMs quota for the new Project. This can not exceed the quota available to the tenancy.

	.PARAMETER DiskCount
	The number of disks (Count) quota for the new Project. This can not exceed the quota available to the tenancy.

	.PARAMETER StorageQuota
	The Storage Quota in GB for the new Project. This can not exceed the quota available to the tenancy.

	.EXAMPLE
	New-CloudQuota -CPUCost 20 -MemoryGBCost 100 -VMCountCost 40 -DiskCount 20 -StorageQuota 200
	Returns a Cloud Quota object for use with a Cloud Project or Tenant with the vCPU Count of 20, Memory quota of 100GB, VM Count of 40, Disk Count of 20 and a Storage Quota of 200GB

	.NOTES
	  NAME: New-CloudQuota
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-27
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller quota
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Tenants,-Quotas,-and-Projects
	#>
	param(
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,128)] [int] $CPUCost,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,4000)] [int] $MemoryGBCost,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,10000)] [int] $VMCountCost,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,10000)] [int] $DiskCount,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,10000)] [int] $StorageQuota
	)
	# Create a Quota Specification object and return it to the caller
	$objQuotaSepcification = New-Object System.Management.Automation.PSObject
	$objQuotaSepcification | Add-Member Note* "vm.cpu" (New-QuotaItem -Limit $CPUCost -Unit "COUNT")
	$objQuotaSepcification | Add-Member Note* "vm.memory" (New-QuotaItem -Limit $MemoryGBCost -Unit "GB")
	$objQuotaSepcification | Add-Member Note* "vm.count" (New-QuotaItem -Limit $VMCountCost -Unit "COUNT")
	$objQuotaSepcification | Add-Member Note* "ephemeral-disk" (New-QuotaItem -Limit $DiskCount -Unit "COUNT")
	$objQuotaSepcification | Add-Member Note* "ephemeral-disk.capacity" (New-QuotaItem -Limit $StorageQuota -Unit "GB")
	$objQuotaSepcification | Add-Member Note* "persistent-disk" (New-QuotaItem -Limit $DiskCount -Unit "COUNT")
	$objQuotaSepcification | Add-Member Note* "persistent-disk.capacity" (New-QuotaItem -Limit $StorageQuota -Unit "GB")
	$objQuotaSepcification
}

function New-QuotaItem(){
	<#
	.SYNOPSIS
	 This cmdlet returns a new Cloud Quota Item object

	.DESCRIPTION
	The cmdlet constructs a PSObject for a new Quota Costs which can be used with the New-CloudQuota cmdlet to create quota specifications for use with the Tenant and Project constructs.

	.PARAMETER Limit
	A number (fractional numbers are allowed) which depicts the limit for the provided unit.

	.PARAMETER Unit
	Units can be B, KB, MB, GB (for size) or COUNT (for totals).

	.PARAMETER Usage
	Optionally; the current usage for the Quota Item; default is 0

	.EXAMPLE
	New-QuotaItem -Limit 20 -Unit "COUNT"
	Creates a new Cloud Quota of type "ephemeral-disk" with a limit value of Count 20 and usage of 0

	.EXAMPLE
	New-QuotaItem -Limit 60 -Unit "GB" -Usage 20
	Creates a new Cloud Quota of type "vm.memory" with a limit value of 60GB and a Usage Value of 20GB

	.NOTES
	  NAME: New-QuotaItem
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-27
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller new quota
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Tenants,-Quotas,-and-Projects
	#>
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, HelpMessage="A limit for the provided quota item (fractional numbers are allowed)")]
			[ValidateRange(0,2147483647)] [int] $Limit,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Units can be B, KB, MB, GB (for size) or COUNT (for totals).")]
			[ValidateSet("B","KB","MB","GB","COUNT")] [string] $Unit,
		[Parameter(Mandatory=$False, ValueFromPipeline=$False, HelpMessage="Optionally the usage for the quota.")]
			[ValidateRange(0,2147483647)] [int] $Usage = 0
	)
	# Create an object with the properties of a Quota Item
	$objQuotaItem = New-Object System.Management.Automation.PSObject
	$objQuotaItem | Add-Member Note* limit $Limit
	$objQuotaItem | Add-Member Note* usage $Usage
	$objQuotaItem | Add-Member Note* unit $Unit
	$objQuotaItem
}

function Get-CloudQuota(){
	<#
	.SYNOPSIS
	 This cmdlet returns the Quota for a Cloud Tenant or Project on the Photon Platform

	.DESCRIPTION
	This cmdlet returns the Quota for a Cloud Tenant or Project on the Photon Platform.

	.PARAMETER TenantName
	The Unique Name of the Tenant

	.PARAMETER ProjectName
	The Project Name

	.EXAMPLE

	.EXAMPLE

	.NOTES
	  NAME: Get-CloudQuota
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-03
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller tenants security
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Tenants,-Quotas,-and-Projects
	#>
	Param(
		[Parameter(Mandatory=$True,ParameterSetName = "Tenant")]
			[switch] $Tenant,
		[Parameter(Mandatory=$True,ParameterSetName = "Tenant")]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$True,ParameterSetName = "Project")]
			[switch] $Project,
		[Parameter(Mandatory=$True,ParameterSetName = "Tenant")]
		[Parameter(Mandatory=$True,ParameterSetName = "Project")]
			[ValidateNotNull()] [string] $ProjectName
	)
	# Get the Host Object
	if($PSCmdlet.ParameterSetName -eq "ByName"){
		$TenantExists = ((Get-CloudTenants -Name $TenantName) -ne $null)
	}
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$TenantExists = ((Get-CloudTenants -Id $TenantId) -ne $null)
	}
	# Check that an object was returned
	if(!$TenantExists){
		throw "A Cloud Tenant matching the filters provided can not be found. Please verify and try again."
	}

}
#endregion

#region: Tenants
function Get-CloudTenants(){
	<#
	.SYNOPSIS
	 This cmdlet returns a collection of Tenants

	.DESCRIPTION
	 This cmdlet returns a collection of Tenants based on the provided filter

 	.PARAMETER Name
	Optionally a filter for the Name of the Subnet

	.PARAMETER Tags
	Optionally a filter for Subnet tagged with the provided Tags

 	.EXAMPLE
	Get-CloudTenants
	Returns a collection of Cloud Subnets defined on the Photon Plaform

 	.EXAMPLE
	Get-CloudTenants -Name "Tenant1"
	Returns a Tenant with the Name "Tenant1"

	.EXAMPLE
	Get-CloudTenants -Tags "Prod"
	Returns a collection of Tenants with the Tag "Prod"

	.NOTES
	  NAME: Get-CloudTenants
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-03
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller tenants
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Tenants,-Quotas,-and-Projects
	 #>
	[CmdletBinding(DefaultParameterSetName="Default")]
	Param(
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $Name,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $Id,
		[Parameter(Mandatory=$True,ParameterSetName = "ByTags")]
			[ValidateNotNullorEmpty()] [string] $Tags
	)
	$URI =  $Global:DefaultPCServer.ServiceURI + "v1/tenants"
	# Get a list of tenants for the Organisation
	$Tenants = (Get-PCAPIResponseJSON -URI $URI).items

	# Filter the results if filters have been provided
	if($PSCmdlet.ParameterSetName -eq "ByName"){
		$Tenants = $Tenants | ?{$_.Name -eq $Name}
	}
	if($PSCmdlet.ParameterSetName -eq "ByTag"){
		$Tenants = $Tenants | ?{$_.tags -contains $Tags}
	}
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$Tenants = $Tenants | ?{$_.Id -eq $Id}
	}
	# Create a Collection of Subnet Objects
	$colTenants = New-Object -TypeName System.Collections.ArrayList
	foreach($tenant in $Tenants){
		$objTenant = New-Object System.Management.Automation.PSObject
		$objTenant | Add-Member Note* Id $tenant.id
		$objTenant | Add-Member Note* Name $tenant.name
		$objTenant | Add-Member Note* Tags $tenant.tags
		$objTenant | Add-Member Note* Kind $tenant.kind
		$objTenant | Add-Member Note* Quota $tenant.quota
		$objTenant | Add-Member Note* SecurityGroups $tenant.tenant
		$colTenants.Add($objTenant) > $nul
	}
	$colTenants
}

# UNFINISHED CODE : Need to add Remove-Project handler
function Remove-CloudTenant(){
	<#
	.SYNOPSIS
	 This cmdlet removes a Cloud Tenant if it exists.

	.DESCRIPTION
	 This cmdlet removes a Cloud Tenant if it exists and has no projects present. If the force parameter is provided any projects are also removed.

	.PARAMETER TenantName
	The name of the Tenant to remove

	.PARAMETER Force
	Optional - If set will remove any Projects that exist in this tenant

	.EXAMPLE
	Remove-CloudTenant -TenantName "Marketing"
	Removes the Tenant "Marketing" from the Photon Platform if no projects currently exist.

	.EXAMPLE
	Remove-CloudTenant -TenantName "Marketing" -Force
	Removes the Tenant "Marketing" from the Photon Platform and any projects under the tenant.

	.NOTES
	  NAME: Remove-CloudTenant
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-27
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller remove tenant
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Tenants,-Quotas,-and-Projects
	#>
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$True, HelpMessage="The name of the tenant to remove")]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$False, ValueFromPipeline=$False)]
			[ValidateNotNullorEmpty()] [bool] $Force = $false
	)
	# Check if the Tenant exists and only one object was returned
	$objTenant = Get-CloudTenants -Name $TenantName
	if(($objTenant -ne $null) -and ($objTenant.Count -eq $null)){
		# Check if the tenancy has projects
		[string] $ProjectsURI = $Global:DefaultPCServer.ServiceURI + "v1/tenants/" + $objTenant.id + "/projects"
		# TO DO !!!!!:
		# - If projects exist remove these first by calling Remove-CloudProject

		[string] $URI = $Global:DefaultPCServer.ServiceURI + "v1/tenants/" + $objTenant.id
		$RemoveTask = Remove-PCAPIDataJSON -URI $URI
		$objTaskComplete = Watch-TaskCompleted -Task $RemoveTask -Timeout 60
		if($objTaskComplete){
			if((Get-CloudTenants -Name $TenantName) -eq $null){
				$true
			} else{
				$false
			}
		}
	} else {
		throw "No Tenant can be found with the name $TenantName. Please review and try again."
	}
}

function New-CloudTenant(){
	<#
	.SYNOPSIS
	 This cmdlet creates a new Cloud Tenant in the Photon Platform

	.DESCRIPTION
	A tenant is the top-level tenancy element in Photon Controller. A tenant has quotas and projects.

	A tenant administrator can manage the projects in a tenant. A tenant has a set of Lightwave security groups that specifies the set of users who can act as tenant administrators.

	.PARAMETER Name
	The Unique Name of the New Tenant

	.PARAMETER CPUCost
	The vCPU Count quota for the new Tenant

	.PARAMETER MemoryGBCost
	The Memory quota in GB for the new Tenant

	.PARAMETER VMCountCost
	The count (number) of VMs quota for the new Tenant

	.PARAMETER DiskCount
	The number of disks (Count) quota for the new Tenant

	.PARAMETER StorageQuota
	The Storage Quota in GB for the new Tenant

	.PARAMETER SecurityGroups
	Optionally the security groups associated with the tenant; these are Lightwave groups (domain\groupname)

	.PARAMETER Tags
	Optionally tags assocaited with the Tenant

	.EXAMPLE
	New-CloudTenant -Name "Marketing" -CPUCost 20 -MemoryGBCost 100 -VMCountCost 40 -DiskCount 20 -StorageQuota 200 -SecurityGroups "photon.pigeonnuggets.com\MarketingAdmins"
	Adds a new Cloud Tenant "Marketing" with a CPU Count of 20, Memory Cost of 100GB, VM count of 40, a Disk Count of 20 and a Storage Quota of 200GB and  and a VM count of 40

	.NOTES
	  NAME: New-CloudTenant
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-27
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller new tenants
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Tenants,-Quotas,-and-Projects
	#>
	param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $Name,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,128)] [int] $CPUCost,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,4000)] [int] $MemoryGBCost,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,10000)] [int] $VMCountCost,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,10000)] [int] $DiskCount,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,10000)] [int] $StorageQuota,
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [string[]] $SecurityGroups = @(),
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [string[]] $Tags = @()
		)
	# Check if the object already exists
	if((Get-CloudTenants -Name $Name) -ne $null){
		throw "A Cloud Tenant with the name $Name already exists. Please remove it first or select another name for the Tenant."
	}
	# Next create the Cloud Tenant Object
	$objTenant = New-Object System.Management.Automation.PSObject
	$objTenant | Add-Member Note* name $Name
	$objTenant | Add-Member Note* tags $Tags
	$objTenant | Add-Member Note* projects @("")
	$objTenant | Add-Member Note* securityGroups $SecurityGroups
	# Create a new object for the Quota items
	$objTenantQuotaItems = New-Object System.Management.Automation.PSObject
	$objTenantQuotaItems | Add-Member Note* quotaItems (New-CloudQuota -CPUCost $CPUCost -MemoryGBCost $MemoryGBCost -VMCountCost $VMCountCost -DiskCount $DiskCount -StorageQuota $StorageQuota)
	$objTenant | Add-Member Note* quota $objTenantQuotaItems

	# Make the call to the API to add the object
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/tenants"
	$objCreateTenantTask = Publish-PCAPIDataJSON -URI $URI -Data (ConvertTo-JSON $objTenant -Depth 5)
	$objTaskComplete = Watch-TaskCompleted -Task $objCreateTenantTask -Timeout 60
	if($objTaskComplete){
		if((Get-CloudTenants -Name $Name) -ne $null){
			$true
		} else{
			$false
		}
	}
}

## DOES NOT APPEAR TO WORK
## May be not correctly implemented throws a 500 Server Error
function Set-CloudTenantSecurityGroups(){
	<#
	.SYNOPSIS
	 This cmdlet amends the Security Groups for the Cloud Tenant in the Photon Platform

	.DESCRIPTION
	This cmdlet amends the Security Groups for the Cloud Tenant Administrators in the Photon Platform.

	.PARAMETER TenantName
	The Unique Name of the Tenant

	.PARAMETER TenantId
	The Tenant Id

	.PARAMETER SecurityGroups
	The security groups to set as the tenant Administrators; these are Lightwave groups (domain\groupname)

	.EXAMPLE
	Set-CloudTenantSecurityGroups -TenantName "Marketing" -SecurityGroups @("photon.pigeonnuggets.com\MarketingAdmins","photon.pigeonnuggets.com\PromoAdmins")
	Sets the Tenant Administrators for the Tenant with the Name "Marketing" to photon.pigeonnuggets.com\MarketingAdmins and photon.pigeonnuggets.com\PromoAdmins

	.EXAMPLE
	Set-CloudTenantSecurityGroups -TenantName "Marketing" -SecurityGroups @("")
	Removes all Tenant Administrator groups from the Tenant with the Name "Marketing"

	.NOTES
	  NAME: Set-CloudTenantSecurityGroups
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-27
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller tenants security
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Tenants,-Quotas,-and-Projects
	#>
	Param(
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $TenantId,
		[Parameter(Mandatory=$False,ParameterSetName = "ById")]
		[Parameter(Mandatory=$False,ParameterSetName = "ByName")]
			[ValidateNotNull()] [string[]] $SecurityGroups
	)
	# Get the Host Object
	if($PSCmdlet.ParameterSetName -eq "ByName"){
		$objTenant = (Get-CloudTenants -Name $TenantName)
		$TenantExists = ($objTenant -ne $null)
	}
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$objTenant = (Get-CloudTenants -Id $TenantId)
		$TenantExists = ($objTenant -ne $null)
	}
	# Check that an object was returned
	if(!$TenantExists){
		throw "A Cloud Tenant matching the filters provided can not be found. Please verify and try again."
	}

	# Create an object for the API call
	$objTenantSecurity = New-Object System.Management.Automation.PSObject
	$objTenantSecurity | Add-Member Note* id $objTenant.Id
	$objTenantSecurity | Add-Member Note* ResourceList $SecurityGroups

	# Make the call to the API to add the object
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/tenants/" + $objTenant.Id + "/set_security_groups"
	$objUpdateTask = Publish-PCAPIDataJSON -URI $URI -Data (ConvertTo-JSON $objTenantSecurity)
	$objTaskComplete = Watch-TaskCompleted -Task $objUpdateTask -Timeout 60
	if($objTaskComplete){
		$true
	} else{
		$false
	}
}

# Overrides the tenant quota with a new specification
function Set-CloudTenantQuota(){
	# URI: /v1/tenants/id/quota (PUT)
	throw "Not yet implemented"
}
#endregion

#region:Projects
function Get-CloudProjects(){
	<#
	.SYNOPSIS
	 This cmdlet returns a Cloud Projects in the provided Tenancy on the Photon Platform if it exists.

	.DESCRIPTION
	This cmdlet returns a Cloud Project in the provided Tenancy on the Photon Platform if it exists.

	.PARAMETER TenantName
	The Name of the Tenancy hosting the Project

	.PARAMETER ProjectName
	Optional

	The Name of the Project

	.EXAMPLE
	Get-CloudProjects -TenantName "Marketing" -ProjectName "Marketing Campaign 2017"
	Returns the object for the project "Marketing Campaign 2017" in the tenancy "Marketing" if it exists

	.EXAMPLE
	Get-CloudProjects -TenantName "Marketing"
	Returns the objects for the projects in the tenancy "Marketing" if any exist

	.NOTES
	  NAME: Get-CloudProjects
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-27
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller get projects
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Tenants,-Quotas,-and-Projects
	#>
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$True, HelpMessage="The name of the tenant to query")]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$False, ValueFromPipeline=$False, HelpMessage="The name of the project to query")]
			[ValidateNotNullorEmpty()] [string] $ProjectName
	)
	# First retreive the Tenant and check if it exists
	$Tenant = Get-CloudTenants -Name $TenantName
	if($Tenant -eq $null){
		throw "A tenant with the name $TenantName can not be found on the Platform. Please check the Tenant Name and try again."
	}
	# Get a collection of Tenant Projects
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/tenants/" + $Tenant.Id + "/projects"
	$JSONProjects = (Get-PCAPIResponseJSON -URI $URI).items

	# Check if a ProjectName was provided and filter the collection
	if(!([string]::IsNullOrEmpty($ProjectName))){
		$JSONProjects = $JSONProjects | ?{$_.name -eq $ProjectName}
	}
	# Create a Collection of Projects
	$colProjects = New-Object -TypeName System.Collections.ArrayList
	foreach($project in $JSONProjects){
		$objProject = New-Object System.Management.Automation.PSObject
		$objProject | Add-Member Note* Id $project.id
		$objProject | Add-Member Note* kind $project.kind
		$objProject | Add-Member Note* Name $project.name
		$objProject | Add-Member Note* Tag $project.tags

		# Construct a collection of quota items that we can work with
		$colQuotaItems = New-Object -TypeName System.Collections.ArrayList
		$project.quota.quotaitems | Get-Member -type NoteProperty | foreach-object {
			$QuotaItemName = $_.Name
			$QuotaItemLimit = $project.quota.quotaitems."$($_.Name)".Limit
			$QuotaItemUnit = $project.quota.quotaitems."$($_.Name)".Unit
			$QuotaItemUsage = $project.quota.quotaitems."$($_.Name)".Usage

			$objQuotaSepcification = New-Object System.Management.Automation.PSObject
			$objQuotaSepcification | Add-Member Note* $QuotaItemName (New-QuotaItem -Limit $QuotaItemLimit -Unit $QuotaItemUnit -Usage $QuotaItemUsage)
			$colQuotaItems.Add($objQuotaSepcification) > $nul
		}
		# Create the objects to ensure the correct structure to match the JSON objects
		$objProject | Add-Member Note* Quota $colQuotaItems

		# Create a collection of Security Group objects
		$colSecurityGroups = New-Object -TypeName System.Collections.ArrayList
		foreach($securityGroup in $project.securityGroups){
			$objSecurityGroup = New-Object System.Management.Automation.PSObject
			$objSecurityGroup | Add-Member Note* Inherited $securityGroup.inherited
			$objSecurityGroup | Add-Member Note* Name $securityGroup.Name
			$colSecurityGroups.Add($objSecurityGroup) > $nul
		}
		$objProject | Add-Member Note* securityGroups $colSecurityGroups
		$colProjects.Add($objProject) > $nul
	}
	$colProjects
}

# TESTED BASIC
function New-CloudProject(){
	<#
	.SYNOPSIS
	 This cmdlet creates a new Cloud Project in the provided Tenancy on the Photon Platform.

	.DESCRIPTION
	This cmdlet creates a new Cloud Project in the provided Tenancy on the Photon Platform.

	.PARAMETER TenantName
	The Name of the Tenancy hosting the Project

	.PARAMETER ProjectName
	The Name of the Project (can not include any spaces)

	.PARAMETER CPUCost
	The vCPU Count quota for the new Project. This can not exceed the quota available to the tenancy.

	.PARAMETER MemoryGBCost
	The Memory quota in GB for the new Project. This can not exceed the quota available to the tenancy.

	.PARAMETER VMCountCost
	The count (number) of VMs quota for the new Project. This can not exceed the quota available to the tenancy.

	.PARAMETER DiskCount
	The number of disks (Count) quota for the new Project. This can not exceed the quota available to the tenancy.

	.PARAMETER StorageQuota
	The Storage Quota in GB for the new Project. This can not exceed the quota available to the tenancy.

	.PARAMETER SecurityGroups
	Optionally the security Groups associated with the project as Lightwave authentication groups (domain\groupname)

	.EXAMPLE
	New-CloudProject -TenantName "Marketing" -ProjectName "Marketing-Campaign-2017" -CPUCost 10 -MemoryGBCost 50 -VMCountCost 20 -DiskCount 10 -StorageQuota 100 -SecurityGroups "photon.pigeonnuggets.com\MarketingAdmins"
	Adds a new Cloud Project to the "Marketing" tenant with the Name "Marketing-Campaign-2017" with a CPU Count of 10, Memory Cost of 50GB, VM count of 20, a Disk Count of 10 and a Storage Quota of 100GB and  and a VM count of 20 and assigns the group MarketingAdmins permission to the project

	.NOTES
	  NAME: New-CloudProject
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-27
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller new projects
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Tenants,-Quotas,-and-Projects
	#>
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, HelpMessage="The name of the tenant hosting the project")]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, HelpMessage="The name of the project to create")]
			[ValidateNotNullorEmpty()] [string] $ProjectName,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,128)] [int] $CPUCost,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,4000)] [int] $MemoryGBCost,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,10000)] [int] $VMCountCost,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,10000)] [int] $DiskCount,
		[Parameter(Mandatory=$True)]
			[ValidateRange(1,10000)] [int] $StorageQuota,
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [string[]] $SecurityGroups = @()
	)
	# First check if the Project Name contains spaces (it is not allowed to)
	if($ProjectName -match " "){
		throw "The provided Project Name contains spaces. This is not supported, please use a different name and try again"
	}
	# First resolve the Tenant Object hosting the project
	$ProjectTenant = Get-CloudTenants -Name $TenantName
	if($ProjectTenant -eq $null){
		throw "A tenant with the name $TenantName can not be found on the Platform. Please check the Tenant Name and try again."
	} else {
		# Check if the tenancy has a project with that name already
		$ExistingProjects = Get-CloudProjects -TenantName $TenantName
		if(($ExistingProjects | ?{$_.Name -eq $ProjectName}) -ne $null){
			throw "A project with the name $ProjectName already exists for $TenantName. Please check the Tenant Name and the Project Name and try again."
		} else {
			# If the security groups were provided need to parse the values for "\"
			#if(!([string]::IsNullOrEmpty($SecurityGroups))){
				#$SecurityGroups = $SecurityGroups.Replace("\","\\")
			#}
			# Next create the tenant object for the Project
			$objProject = New-Object System.Management.Automation.PSObject
			$objProject | Add-Member Note* name $ProjectName
			# Create a new object for the Quota items
			$objProjectQuotaItems = New-Object System.Management.Automation.PSObject
			$objProjectQuotaItems | Add-Member Note* quotaItems (New-CloudQuota -CPUCost $CPUCost -MemoryGBCost $MemoryGBCost -VMCountCost $VMCountCost -DiskCount $DiskCount -StorageQuota $StorageQuota)
			$objProject | Add-Member Note* quota $objProjectQuotaItems
			$objProject | Add-Member Note* securityGroups $SecurityGroups

			# Make the call to the API to add the object
			$URI = $Global:DefaultPCServer.ServiceURI + "v1/tenants/" + $ProjectTenant.Id + "/projects"
			$objCreateProject = Publish-PCAPIDataJSON -URI $URI -Data (ConvertTo-JSON $objProject  -Depth 5)
			$objTaskComplete = Watch-TaskCompleted -Task $objCreateProject -Timeout 60
			if($objTaskComplete){
				if((Get-CloudProjects -TenantName $TenantName -ProjectName $ProjectName) -ne $null){
					$true
				} else{
					$false
				}
			}
		}
	}
}

function Remove-CloudProject(){
	<#
	.SYNOPSIS
	 This cmdlet deletes a Cloud Project from the Photon Platform and all assosicated objects

	.DESCRIPTION
	 This cmdlet deletes a Cloud Project from the Photon Platform and all assosicated objects

 	.PARAMETER TenantName
	The Name of the Tenant hosting the project

 	.PARAMETER ProjectName
	The Name of the Project to Remove

 	.PARAMETER Force
	Forces the deletion even if the Project contains instances of VMs

	.EXAMPLE
	Remove-CloudProject -TenantName "Marketing" -ProjectName "Campaign 2016"
	Deletes the Cloud Project with the name Campaign 2016 from the Tenant with the name "Marketing"

	.NOTES
	  NAME: Remove-CloudProject
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-27
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller project delete
	  REFERENCE:
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $ProjectName,
		[Parameter(Mandatory=$False, ValueFromPipeline=$False)]
			[ValidateNotNullorEmpty()] [bool] $Force = $false
	)
	# Check if the tenancy has a project with that name already
	$objProject = Get-CloudProjects -TenantName $TenantName -ProjectName $ProjectName
	if($objProject -eq $null){
		throw "A project with the name $ProjectName can not be found. Please check the Tenant Name and the Project Name and try again."
	} else {
		[string] $ProjectURI = $Global:DefaultPCServer.ServiceURI + "v1/projects/" + $objProject.id
		# TO DO:
		# - If projects exist remove the VMs first
		$RemoveTask = Remove-PCAPIDataJSON -URI $ProjectURI
		$objTaskComplete = Watch-TaskCompleted -Task $RemoveTask -Timeout 60
		if($objTaskComplete){
			if((Get-CloudProjects -TenantName $TenantName -ProjectName $ProjectName) -eq $null){
				$true
			} else {
				$false
			}
		} else {
			throw "An error occured removing the Project. Please review and try again."
		}
	}
}
#endregion

#region:Flavors
function Get-CloudFlavor(){
	<#
	.SYNOPSIS
	 This cmdlet returns a collection of Cloud Flavor Objects

	.DESCRIPTION
	 This cmdlet returns a collection of Cloud Flavor objects. A flavor is a named collection of costs for a VM or disk image. Flavors are closely related to quotas: The costs that a flavor specifies are subtracted from the total allocation in the quota you are using.

	.PARAMETER FlavorType
	Optionally the Flavor type to filter on (vm: A VM flavor specifies the costs in creating a VM. ephemeral-disk: Ephemeral disks are used for your boot disks when creating a VM. persistent-disk: Persistent disks can be attached to your VMs and can persist after a VM is removed.)

	.PARAMETER FlavorName
	Optionally the Flavor Name to filter on

	.EXAMPLE
	Get-CloudFlavor
	Returns a collection of Cloud Flavors defined on the Photon Plaform

	.EXAMPLE
	Get-CloudFlavor -FlavorType "vm"
	Returns a collection of Cloud Flavors defined on the Photon Plaform with the Flavor Type "vm"

	.EXAMPLE
	Get-CloudFlavor -FlavorType "vm" -FlavorName "ServiceFlavor"
	Returns a collection of Cloud Flavors defined on the Photon Plaform with the Flavor Type "vm" and the FlavorName "ServiceFlavor"

	.EXAMPLE
	Get-CloudFlavor -FlavorName "ServiceFlavor"
	Returns a collection of Cloud Flavors defined on the Photon Plaform with the FlavorName "ServiceFlavor"

	.NOTES
	  NAME: Get-CloudFlavor
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-10
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller flavor
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Flavors
	#>
	Param(
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [string] $FlavorType,
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [string] $FlavorName
	)
	if(!([string]::IsNullOrEmpty($FlavorType))){
		$URIFlavours =  $Global:DefaultPCServer.ServiceURI + "v1/flavors?kind=" + $FlavorType
	} else {
		$URIFlavours =  $Global:DefaultPCServer.ServiceURI + "v1/flavors"
	}
	# Get the objects via API call
	$FlavorsJSON = Get-PCAPIResponseJSON -URI $URIFlavours

	if(!([string]::IsNullOrEmpty($FlavorName))){
		$Flavors = ($FlavorsJSON.items | ?{$_.Name -eq $FlavorName})
	} else {
		$Flavors = $FlavorsJSON.items
	}
	# Return the flavors matching the criteria
	$Flavors
}

function New-CloudFlavor(){
	<#
	.SYNOPSIS
	 This cmdlet creates a new Cloud Flavor of the provided type

	.DESCRIPTION
	 A flavor is a named collection of costs for a VM or disk image. Flavors are closely related to quotas: The costs that a flavor specifies are subtracted from the total allocation in the quota you are using.

	 The following are the allowed types:
	 vm: A VM flavor specifies the costs in creating a VM.
	 ephemeral-disk: Ephemeral disks are used for your boot disks when creating a VM.
	 persistent-disk: Persistent disks can be attached to your VMs and can persist after a VM is removed.

	.PARAMETER VM
	The Switch to set the Flavor Type to VM

	.PARAMETER ephemeral-disk
	The Switch to set the Flavor Type to Ephemeral Disk

	.PARAMETER persistent-disk
	The Switch to set the Flavor Type to Persistent Disk

	.PARAMETER Name
	The Display Name for the flavor

	.PARAMETER CPUCost
	The vCPU Count quota for the VM Flavor

	.PARAMETER MemoryGBCost
	The Memory quota in GB for the VM Flavor

	.PARAMETER CountCost
	The count (number) of VMs for the VM Flavor

	.PARAMETER DiskCount
	The number of disks (Count) for the Disk Flavor

	.PARAMETER CustomFlavorCosts
	A collection of Custom Flavor Costs created using the New-FlavorCost cmdlet

	.EXAMPLE
	New-CloudFlavor -persistentdisk -Name "PersistentDisk-TestFlavor" -DiskCount 10
	Adds a new Cloud Flavor of type Persistent Disk with a Disk Count of 10

	.EXAMPLE
	New-CloudFlavor -ephemeraldisk -Name "EphemeralDisk-TestFlavor" -DiskCount 20
	Adds a new Cloud Flavor of type Ephemeral Disk with a Disk Count of 20

	.EXAMPLE
	New-CloudFlavor -vm -Name "Kubernetes-Flavor" -CPUCost 20 -MemoryGBCost 100 -CountCost 40
	Adds a new Cloud Flavor of type VM with a CPU Count of 20, Memory Cost of 100GB and a VM count of 40

	.EXAMPLE
	New-CloudFlavor -vm -Name "Kubernetes-Flavor" -CPUCost 10 -MemoryGBCost 50 -CountCost 40 -CustomFlavorCosts $customerFlavors
	Adds a new Cloud Flavor of type VM with a CPU Count of 10, Memory Cost of 50GB and a VM count of 40 and a custom cost object $customerFlavors made from calling New-FlavorCost cmdlet

	.NOTES
	  NAME: New-CloudFlavor
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-10
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller new flavor
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Flavors
	#>

	param(
		[Parameter(Mandatory=$True,ParameterSetName = "vm")]
		[Parameter(Mandatory=$True,ParameterSetName = "ephemeral-disk")]
		[Parameter(Mandatory=$True,ParameterSetName = "persistent-disk")]
			[ValidateNotNullorEmpty()] [string] $Name,
		[Parameter(Mandatory=$True,ParameterSetName = "vm")]
			[switch] $VM,
		[Parameter(Mandatory=$True,ParameterSetName = "vm")]
			[ValidateRange(1,128)] [int] $CPUCost,
		[Parameter(Mandatory=$True,ParameterSetName = "vm")]
			[ValidateRange(1,4000)] [int] $MemoryGBCost,
		[Parameter(Mandatory=$False,ParameterSetName = "vm")]
			[ValidateRange(1,10000)] [int] $CountCost,
		[Parameter(Mandatory=$True,ParameterSetName = "ephemeral-disk")]
			[switch] $ephemeraldisk,
		[Parameter(Mandatory=$True,ParameterSetName = "persistent-disk")]
			[switch] $persistentdisk,
		[Parameter(Mandatory=$True,ParameterSetName = "ephemeral-disk")]
		[Parameter(Mandatory=$True,ParameterSetName = "persistent-disk")]
			[ValidateRange(1,10000)] [int] $DiskCount,
		[Parameter(Mandatory=$False)]
			[ValidateNotNullOrEmpty()] [PSObject[]] $CustomFlavorCosts
	)
	# Check if the object already exists
	if((Get-CloudFlavor -FlavorName $Name) -ne $null){
		throw "A Cloud Flavor with the name $Name already exists. Please remove it first or select another name for the Flavor."
	}
	# Create a collection of costs, add any customer ones first as they are common to all methods
	$colFlavorCosts = New-Object -TypeName System.Collections.ArrayList
	foreach($customFlavor in $CustomFlavorCosts){
		$colFlavorCosts.Add($customFlavor) > $nul
	}
	# Create the FlavorCosts for the VM object
	if($VM){
		[string] $FlavorType = "vm"
		$objCostCPU = New-FlavorCost -CostId "vm.cpu" -CostValue $CPUCost -CostUnit "COUNT"
		$colFlavorCosts.Add($objCostCPU) > $nul
		$objCostMemory = New-FlavorCost -CostId "vm.memory" -CostValue $MemoryGBCost -CostUnit "GB"
		$colFlavorCosts.Add($objCostMemory) > $nul
		if(!([string]::IsNullOrEmpty($CountCost))){
			$objCostVM = New-FlavorCost -CostId "vm" -CostValue $CountCost -CostUnit "COUNT"
			$colFlavorCosts.Add($objCostVM) > $nul
		}
	} else {
		if($ephemeraldisk){
			# Create the FlavorCosts for disk objects
			[string] $FlavorType = "ephemeral-disk"
			$objDiskCount = New-FlavorCost -CostId "ephemeral-disk" -CostValue $DiskCount -CostUnit "COUNT"
			$colFlavorCosts.Add($objDiskCount) > $nul
		}
		if($persistentdisk){
			[string] $FlavorType = "persistent-disk"
			$objDiskCount = New-FlavorCost -CostId "persistent-disk" -CostValue $DiskCount -CostUnit "COUNT"
			$colFlavorCosts.Add($objDiskCount) > $nul
		}
	}
	# Next create the Cloud Flavor Object
	$objFlavor = New-Object System.Management.Automation.PSObject
	$objFlavor | Add-Member Note* cost $colFlavorCosts
	$objFlavor | Add-Member Note* kind $FlavorType
	$objFlavor | Add-Member Note* name $Name
	# Make the call to the API to add the object
	$URI = $Global:DefaultPCServer.ServiceURI + "v1/flavors"
	$objCreateFlavorTask = Publish-PCAPIDataJSON -URI $URI -Data (ConvertTo-JSON $objFlavor)
	$objTaskComplete = Watch-TaskCompleted -Task $objCreateFlavorTask -Timeout 60
	if($objTaskComplete){
		if((Get-CloudFlavor -FlavorName $Name) -ne $null){
			$true
		} else{
			$false
		}
	}
}

function New-FlavorCost(){
	<#
	.SYNOPSIS
	 This cmdlet returns a new Cloud Flavor Cost object

	.DESCRIPTION
	The cmdlet constructs a PSObject for a new Cloud Flavor Costs which can be used with the New-CloudFlavor cmdlet.

	.PARAMETER CostId
	The cost key (eg. vm.cpu) for the cost

	.PARAMETER CostValue
	A single cost is a number (fractional numbers are allowed) and a unit.

	.PARAMETER CostUnit
	Units can be B, KB, MB, GB (for size) or COUNT (for totals).

	.EXAMPLE
	New-FlavorCost -CostId "ephemeral-disk" -CostValue 20 -CostUnit "COUNT"
	Creates a new Cloud Flavor Cost of type "ephemeral-disk" with a cost value of Count 20

	.EXAMPLE
	New-FlavorCost -CostId "vm.memory" -CostValue 60 -CostUnit "GB"
	Creates a new Cloud Flavor Cost of type "vm.memory" with a cost value of 60GB

	.EXAMPLE
	New-FlavorCost -CostId "customer.limit" -CostValue 20 -CostUnit "COUNT"
	Creates a new custom Cloud Flavor Cost of type "customer.limit" with a cost value of Count 20

	.NOTES
	  NAME: New-FlavorCost
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-17
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller new flavor cost
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Flavors
	#>
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, HelpMessage="The cost key (eg. vm.cpu) for the cost")]
			[ValidateNotNullorEmpty()] [string] $CostId,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, HelpMessage="A single cost is a number (fractional numbers are allowed) and a unit.")]
			[ValidateRange(0,2147483647)] [int] $CostValue,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Units can be B, KB, MB, GB (for size) or COUNT (for totals).")]
			[ValidateSet("B","KB","MB","GB","COUNT")] [string] $CostUnit
	)
	$objCost = New-Object System.Management.Automation.PSObject
	$objCost | Add-Member Note* unit $CostUnit
	$objCost | Add-Member Note* value $CostValue
	$objCost | Add-Member Note* key $CostId
	$objCost
}

function Remove-CloudFlavor(){
	<#
	.SYNOPSIS
	 This cmdlet removes a Cloud Flavor Objects if it exists

	.DESCRIPTION
	 This cmdlet removes a Cloud Flavor Objects if it exists.

	.PARAMETER FlavorName
	The name of the flavor to remove

	.EXAMPLE
	Remove-CloudFlavor -FlavorName "Kubernetes-ServiceVM"
	Removes the Cloud Flavor with the name Kubernetes-ServiceVM from the Photon Platform.

	.NOTES
	  NAME: Remove-CloudFlavor
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-17
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller remove flavor
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Flavors
	#>
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$True, HelpMessage="The name of the flavor to remove")]
			[ValidateNotNullorEmpty()] [string] $FlavorName
	)
	# Check if the object exists and only one object was returned
	$objFlavor = Get-CloudFlavor -FlavorName $FlavorName
	if(($objFlavor -ne $null) -and ($objFlavor.Count -eq $null)){
		[string] $URI = $Global:DefaultPCServer.ServiceURI + "v1/flavors/" + $objFlavor.id
		[string] $DataPayload = "{`"id`":`"$($objFlavor.id)`"}"
		$RemoveTask = Remove-PCAPIDataJSON -URI $URI -Data $DataPayload
		$objTaskComplete = Watch-TaskCompleted -Task $RemoveTask -Timeout 60
		if($objTaskComplete){
			if((Get-CloudFlavor -FlavorName $FlavorName) -eq $null){
				$true
			} else{
				$false
			}
		}
	} else {
		throw "No Cloud Flavor can be found with the name $Name. Please review and try again."
	}
}
#endregion

#region: System
Function Get-PCDeploymentConfig(){
	<#
	.SYNOPSIS
	 This cmdlet returns the Deployment Configuration for the Photon Platform.

	.DESCRIPTION
	 This cmdlet returns the Deployment Configuration for the Photon Platform.

	.EXAMPLE
	Get-PCDeploymentConfig
	Returns the Photon Platform Configuration for the environment.

	.NOTES
	  NAME: Get-PCDeploymentConfig
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-05
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller deployment config
	#>
	$URISysInfo = $Global:DefaultPCServer.ServiceURI + "v1/system/info"
	$URISysQuorum = $Global:DefaultPCServer.ServiceURI + "v1/system/properties" # Quorum
	$URISysUsage = $Global:DefaultPCServer.ServiceURI + "v1/system/usage" # Cloud Usage Statistics

	# Get the System Properties
	$SystemInfo = Get-PCAPIResponseJSON -URI $URISysInfo
	$Quorum =  Get-PCAPIResponseJSON -URI $URISysQuorum
	$SystemStats =  Get-PCAPIResponseJSON -URI $URISysUsage

	# Create a new PSObject with the Photon Platform Properties
	$objDeploymentObject = New-Object System.Management.Automation.PSObject
	$objDeploymentObject | Add-Member Note* State $SystemInfo.state
	$objDeploymentObject | Add-Member Note* Syslog $SystemInfo.syslogEndpoint
	$objDeploymentObject | Add-Member Note* StatsEnabled $SystemInfo.stats.enabled
	$objDeploymentObject | Add-Member Note* ImageDatastores $SystemInfo.imageDatastores
	$objDeploymentObject | Add-Member Note* UseImageDatastoreForVms $SystemInfo.useImageDatastoreForVms
	$objDeploymentObject | Add-Member Note* PlatformNodeCountQuorum $Quorum.Quorum
	$objDeploymentObject | Add-Member Note* LoadBalancerEnabled $SystemInfo.loadBalancerEnabled
	$objDeploymentObject | Add-Member Note* NetworkType $SystemInfo.networkType
	$objDeploymentObject | Add-Member Note* BaseVersion $SystemInfo.baseVersion
	$objDeploymentObject | Add-Member Note* FullVersion $SystemInfo.fullVersion
	$objDeploymentObject | Add-Member Note* gitCommitHash $SystemInfo.gitCommitHash
	$objDeploymentObject | Add-Member Note* CloudHosts $SystemStats.numberHosts
	$objDeploymentObject | Add-Member Note* CloudVMs $SystemStats.numberVMs
	$objDeploymentObject | Add-Member Note* CloudTenants $SystemStats.numberTenants
	$objDeploymentObject | Add-Member Note* CloudProjects $SystemStats.numberProjects
	$objDeploymentObject | Add-Member Note* CloudDatastores $SystemStats.numberDatastores
	$objDeploymentObject | Add-Member Note* CloudServices $SystemStats.numberServices

	# Collection of Lightwave services regsitered
	$colAuthServers = New-Object -TypeName System.Collections.ArrayList
	foreach($authObj in $SystemInfo.auth){
		$objAuthServer = New-Object System.Management.Automation.PSObject
		$objAuthServer | Add-Member Note* LightwaveAddress $AuthObj.endpoint
		$objAuthServer | Add-Member Note* Port $AuthObj.port
		$objAuthServer | Add-Member Note* Tenant $AuthObj.tenant
		$colAuthGroups = New-Object -TypeName System.Collections.ArrayList
		foreach($objSecurityGroup in $AuthObj.securityGroups){
			$objSecurityGroup = New-Object System.Management.Automation.PSObject
			$objSecurityGroup | Add-Member Note* SecurityPrincipal $objSecurityGroup
			$colAuthGroups.Add($objSecurityGroup) > $nul
		}
		$colAuthServers | Add-Member Note* Groups $colAuthGroups
	}
	$objDeploymentObject | Add-Member Note* LightwaveEndpoints $colAuthServers
	$objDeploymentObject | Add-Member Note* NetworkConfiguration $SystemInfo.networkConfiguration
	# Create a collection of objects for the Service Configurations
	$colServices = New-Object -TypeName System.Collections.ArrayList
	foreach($service in $SystemInfo.serviceConfigurations){
		$objServiceConfiguration = New-Object System.Management.Automation.PSObject
		$objServiceConfiguration | Add-Member Note* ServiceType $service.Type
		$objServiceConfiguration | Add-Member Note* CloudImage (Get-CloudImage -ImageId $service.imageId)
		$objServiceConfiguration | Add-Member Note* Kind $service.kind
		$colServices.Add($objServiceConfiguration) > $nul
	}
	$objDeploymentObject | Add-Member Note* ServiceConfiguration $colServices
	# Finally return the Deployment Object
	$objDeploymentObject
}

#UNTESED
function Set-PCDeploymentClusterConfig(){
	<#
	.SYNOPSIS
	 This cmdlet allows the Photon Controller Quorum setting for the deployment to be changed.

	.DESCRIPTION
	 This cmdlet allows the Photon Controller Quorum setting for the deployment to be changed. The default quotum is Node Majority.

	.PARAMETER QuorumSize
	 This is Quorum Setting for Photon Controller. When there are multiple Photon Controller hosts, this indicates how many hosts must accept a change before the user can get a response. Usually is it a majority(e.g. when there are 3 hosts, this should be 2). In some special cases (like shutting down) it maybe appropriate to set this to be the same as the number of nodes. Please do not modify the quorum unless you know exactly what you are doing. Incorrectly modifying this can damage your installation.

	.EXAMPLE
	Set-PCDeploymentClusterConfig -QuorumSize 2
	Sets the quorum sizer to 2 Photon Controllers for the Photon Platform Configuration.

	.NOTES
	  NAME: Set-PCDeploymentClusterConfig
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-29
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller deployment config
	#>
	Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True)]
			[ValidateRange(0,2147483647)] [int] $QuorumSize
	)
	# First check what the quorum is currently set to and if this value is different
	if($QuorumSize -ne ((Get-PCDeploymentConfig).PlatformNodeCountQuorum)){
		$URISysQuorum = $Global:DefaultPCServer.ServiceURI + "v1/system/properties/update" # Quorum
		[string] $DataPayload = "{`"size`":`"$QuorumSize`"}"
		$UpdateTask = Publish-PCAPIDataJSON -URI $URISysQuorum -Data $DataPayload
		$objTaskComplete = Watch-TaskCompleted -Task $UpdateTask -Timeout 60
		if($objTaskComplete){
			if(((Get-PCDeploymentConfig).PlatformNodeCountQuorum) -eq $QuorumSize){
				$true
			} else{
				$false
			}
		}
	} else {
		Write-Warning "The Quorum is already set at $QuorumSize no change has been made."
	}
}

function Enter-PCDeploymentMaintenanceMode(){
	<#
	.SYNOPSIS
	 This cmdlet Pauses the system state for the Photon Platform.

	.DESCRIPTION
	 This cmdlet Pauses the system state for the Photon Platform.

	.EXAMPLE
	Enter-PCDeploymentMaintenanceMode
	Pauses the system state for the Photon Platform

	.NOTES
	  NAME: Enter-PCDeploymentMaintenanceMode
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-29
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller deployment config
	#>
	# First check the status of the Photon Platform
	if(((Get-PCDeploymentConfig).State) -eq "READY"){
		$URISysPause = $Global:DefaultPCServer.ServiceURI + "v1/system/pause"
		$UpdateTask = Publish-PCAPIDataJSON -URI $URISysPause
		$objTaskComplete = Watch-TaskCompleted -Task $UpdateTask -Timeout 60
		if($objTaskComplete){
			if(((Get-PCDeploymentConfig).State) -eq "PAUSED"){
				$true
			} else{
				$false
			}
		}
	} else {
		Write-Warning "The Photon Platform is currently paused no change has been made."
	}
}

function Exit-PCDeploymentMaintenanceMode(){
	<#
	.SYNOPSIS
	 This cmdlet Resume the system state to READY for the Photon Platform.

	.DESCRIPTION
	 This cmdlet Resumes the system state to READY the Photon Platform.

	.EXAMPLE
	Enter-PCDeploymentMaintenanceMode
	Pauses the system state for the Photon Platform

	.NOTES
	  NAME: Enter-PCDeploymentMaintenanceMode
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-29
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller deployment config
	#>
	# First check the status of the Photon Platform
	if(((Get-PCDeploymentConfig).State) -eq "PAUSED"){
		$URI = $Global:DefaultPCServer.ServiceURI + "v1/system/resume"
		$UpdateTask = Publish-PCAPIDataJSON -URI $URI
		$objTaskComplete = Watch-TaskCompleted -Task $UpdateTask -Timeout 60
		if($objTaskComplete){
			if(((Get-PCDeploymentConfig).State) -eq "READY"){
				$true
			} else{
				$false
			}
		}
	} else {
		Write-Warning "The Photon Platform is currently READY no change has been made."
	}
}

function Set-PCDeploymentSecurity(){
	throw "Not yet implemented"
}
#endregion

#region: VMs
function Remove-CloudVM(){
	<#
	.SYNOPSIS
	 This cmdlet removes/deletes a Cloud VM if it exists

	.DESCRIPTION
	 This cmdlet removes/deletes a Cloud VM if it exists.

	.PARAMETER Id
	The Virtual Machine Id

	.EXAMPLE
	Remove-CloudVM -Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"
	Removes the Cloud VM with the Id of 4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600 from the Photon Platform.

	.NOTES
	  NAME: Remove-CloudVM
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-28
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller delete vm
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Performing-Host-Maintenance
	#>
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$True, HelpMessage="The name of the flavor to remove")]
			[ValidateNotNullorEmpty()] [string] $Id
	)
	# Check if the object exists
	$objVM = Get-CloudVM -Id $Id
	if(($objVM -ne $null) -and ($objVM.Count -eq $null)){
		[string] $URI = $Global:DefaultPCServer.ServiceURI + "v1/vms/" + $Id
		[string] $DataPayload = "{`"id`":`"$Id`"}"
		$RemoveTask = Remove-PCAPIDataJSON -URI $URI -Data $DataPayload
		$objTaskComplete = Watch-TaskCompleted -Task $RemoveTask -Timeout 60
		if($objTaskComplete){
			if((Get-CloudVM -Id $Id) -eq $null){
				$true
			} else{
				$false
			}
		}
	} else {
		throw "No VM with the Id $Id can be found. Please review and try again."
	}
}

function Get-CloudVM(){
	<#
	.SYNOPSIS
	 This cmdlet returns a collection of Cloud VM matching the provided criteria

	.DESCRIPTION
	 This cmdlet returns a collection of Cloud VM matching the provided criteria

	.PARAMETER Id
	The Virtual Machine Id

	.PARAMETER Host
	The IP address or DNS hostname of a Cloud Host

	.PARAMETER TenantName
	The Tenant Name of the VMs to return

	.PARAMETER ProjectName
	Optionally the Project Name of the VMs to return

	.PARAMETER VMName
	Optionally the Project Scoped Name of the VM to return

	.EXAMPLE
	Get-CloudVM
	Returns a collection of all Cloud VM on the Photon Platform.

	.EXAMPLE
	Get-CloudVM -Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"
	Returns the Cloud VM with the Id of 4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600 from the Photon Platform if it exists.

	.EXAMPLE
	Get-CloudVM -Host "photonesx1.photon.pigeonnuggets.com"
	Returns a collection of Cloud VM objects on the Photon Platform Cloud Host "photonesx1.photon.pigeonnuggets.com".

	.EXAMPLE
	Get-CloudVM -TenantName "Marketing"
	Returns a collection of Cloud VM objects which are owned by the Tenant "Marketing" on the Photon Platform.

	.EXAMPLE
	Get-CloudVM -TenantName "Marketing" -ProjectName "Campaign 2017"
	Returns a collection of Cloud VM objects which are owned by the Tenant "Marketing" and belong to the Project "Campaign 2017" on the Photon Platform.

	.NOTES
	  NAME: Get-CloudVM
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-07-28
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller get vm cloud
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Working-with-Virtual-Machines
	#>
	[CmdletBinding(DefaultParameterSetName="Default")]
	param(
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $Id,
		[Parameter(Mandatory=$True,ParameterSetName = "ByHost")]
			[ValidateNotNullorEmpty()] [string] $Host,
		[Parameter(Mandatory=$True,ParameterSetName = "ByTenant")]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$False,ParameterSetName = "ByTenant")]
			[ValidateNotNullorEmpty()] [string] $ProjectName,
		[Parameter(Mandatory=$False,ParameterSetName = "ByTenant")]
			[ValidateNotNullorEmpty()] [string] $VMName
	)
	# Check if a filter by Id has been provided
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$URI = $Global:DefaultPCServer.ServiceURI + "v1/vms/" + $Id
		$colAPIVM = (Get-PCAPIResponseJSON -URI $URI).items
	} elseif($PSCmdlet.ParameterSetName -eq "ByHost"){
		# Get the VMs associated with the provided Host
		$CloudHost = Get-CloudHosts -CloudHost $Host
		if($CloudHost -ne $null){
			$URI = $Global:DefaultPCServer.ServiceURI + "v1/infrastructure/hosts/" + $CloudHost.Id + "/vms"
			$colAPIVM = (Get-PCAPIResponseJSON -URI $URI).items
		} else {
			throw "A host with the specified name can not be found. Please check the host name and try again."
		}
	} elseif($PSCmdlet.ParameterSetName -eq "ByTenant"){
		if(!([string]::IsNullOrEmpty($ProjectName))){
			# If a Project was provided check if that a Project exists in that Tenant
			$colProjects = Get-CloudProjects -TenantName $TenantName -ProjectName $ProjectName
		} else {
			$colProjects = Get-CloudProjects -TenantName $TenantName
		}
		# Next check that at least 1 Project has been returned
		if($colProjects -ne $null){
			foreach($Project in $colProjects){
				$colAPIVM += (Get-PCAPIResponseJSON -URI $URI).items
			}
		}
	}
	# Create a collection
	$colAPIVM = (Get-PCAPIResponseJSON -URI $URI).items




	# Code goes here
	throw "Not yet implementated"
}

# NOT TESTED !!!!
function Add-CloudVMTag(){
	<#
	.SYNOPSIS
	 This cmdlet adds a provided Tag to a Virtual Machine

	.DESCRIPTION
	 This cmdlet adds a provided Tag to a Virtual Machine

	.PARAMETER Id
	The VM Id of the VM

	.PARAMETER TenantName
	The Tenant Name of the VMs to return

	.PARAMETER ProjectName
	Optionally the Project Name of the VMs to return

	.PARAMETER VMName
	The project-scoped name of the VM

	.PARAMETER Tag
	The Tag to add to the VM

	.EXAMPLE
	Add-CloudVMTag -Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600" -Tags @("Prod","Marketing")
	Adds the Tags "Prod" and "Marketing" to the VM with the Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"

	.EXAMPLE
	Add-CloudVMTag -TenantName "Marketing" -ProjectName "Campaign 2017" -Name "Prod01" -Tags @("Prod","Marketing")
	Adds the Tags "Prod" and "Marketing" to the VM in the Campaign 2017 project under the Marketing tenant with the name "Prod01"

	.NOTES
	  NAME: Add-CloudVMTag
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-03
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller set vm tags
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Working-with-Virtual-Machines
	#>
	param(
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $Id,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $ProjectName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $VMName,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $Tag
	)
	# Check if the VM exists with the provided values
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$objVM = Get-CloudVM -Id $Id
	} elseif($PSCmdlet.ParameterSetName -eq "ByVMName"){
		$objVM = Get-CloudVM -TenantName $TenantName -ProjectName $ProjectName -VMName $VMName
	}
	if($objVM -eq $null){
		throw "A VM matching the criteria can not be found. Please check the values provided and try again."
	}
	# Add the Tags to the VM
	[string] $URI = $Global:DefaultPCServer.ServiceURI + "v1/vms/" + $objVM.Id + "/tags"
	[string] $DataPayload = "{`"id`":`"$Tag`"}"
	$UpdateTask = Publish-PCAPIDataJSON -URI $URI -Data $DataPayload
	$objTaskComplete = Watch-TaskCompleted -Task $UpdateTask -Timeout 60
	if($objTaskComplete){
		$true
	} else {
		$false
	}
}

function Start-CloudVM(){
	<#
	.SYNOPSIS
	 This cmdlet performs a Start Operation on the provided Virtual Machine

	.DESCRIPTION
	 This cmdlet performs a Start Operation on the provided Virtual Machine

	.PARAMETER Id
	The VM Id of the VM

	.PARAMETER TenantName
	The Tenant Name of the VMs to return

	.PARAMETER ProjectName
	Optionally the Project Name of the VMs to return

	.PARAMETER VMName
	The project-scoped name of the VM

	.EXAMPLE
	Start-CloudVM -Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"
	Performs a Start Operation on the VM with the Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"

	.EXAMPLE
	Start-CloudVM -TenantName "Marketing" -ProjectName "Campaign 2017" -Name "Prod01"
	Performs a Start Operation on the VM in the Campaign 2017 project under the Marketing tenant with the name "Prod01"

	.NOTES
	  NAME: Start-CloudVM
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-03
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller vm start
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Working-with-Virtual-Machines
	#>
	param(
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $Id,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $ProjectName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $VMName
	)
	# Check if the VM exists with the provided values
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$objVM = Get-CloudVM -Id $Id
	} elseif($PSCmdlet.ParameterSetName -eq "ByVMName"){
		$objVM = Get-CloudVM -TenantName $TenantName -ProjectName $ProjectName -VMName $VMName
	}
	if($objVM -eq $null){
		throw "A VM matching the criteria can not be found. Please check the values provided and try again."
	}
	# Check that the VM is currently in a state that allows it to be Started
	if(!($objVM.State -in @("STOPPED","SUSPENDED"))){
		throw "The VM has a state of $($objVM.State). The Start Operation can not be performed in this state."
	} else {
		# Start the VM
		[string] $URI = $Global:DefaultPCServer.ServiceURI + "v1/vms/" + $objVM.Id + "/start"
		[string] $DataPayload = "{`"id`":`"$($objVM.Id)`"}"
		$StartTask = Publish-PCAPIDataJSON -URI $URI -Data $DataPayload
		$objTaskComplete = Watch-TaskCompleted -Task $StartTask -Timeout 60
		if($objTaskComplete){
			if((Get-CloudVM -Id $objVM.Id).State -eq "STATED"){
				$true
			} else {
				$false
			}
		} else {
			$false
		}
	}
}

function Stop-CloudVM(){
	<#
	.SYNOPSIS
	 This cmdlet performs a Stop Operation on the provided Virtual Machine

	.DESCRIPTION
	 This cmdlet performs a Stop Operation on the provided Virtual Machine

	.PARAMETER Id
	The VM Id of the VM

	.PARAMETER TenantName
	The Tenant Name of the VMs to return

	.PARAMETER ProjectName
	Optionally the Project Name of the VMs to return

	.PARAMETER VMName
	The project-scoped name of the VM

	.EXAMPLE
	Stop-CloudVM -Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"
	Performs a Stop Operation on the VM with the Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"

	.EXAMPLE
	Stop-CloudVM -TenantName "Marketing" -ProjectName "Campaign 2017" -Name "Prod01"
	Performs a Stop Operation on the VM in the Campaign 2017 project under the Marketing tenant with the name "Prod01"

	.NOTES
	  NAME: Stop-CloudVM
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-03
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller vm stop
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Working-with-Virtual-Machines
	#>
	param(
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $Id,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $ProjectName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $VMName
	)
	# Check if the VM exists with the provided values
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$objVM = Get-CloudVM -Id $Id
	} elseif($PSCmdlet.ParameterSetName -eq "ByVMName"){
		$objVM = Get-CloudVM -TenantName $TenantName -ProjectName $ProjectName -VMName $VMName
	}
	if($objVM -eq $null){
		throw "A VM matching the criteria can not be found. Please check the values provided and try again."
	}
	# Check that the VM is currently in a state that allows it to be Started
	if(!($objVM.State -in @("STARTED","SUSPENDED"))){
		throw "The VM has a state of $($objVM.State). The Stop Operation can not be performed in this state."
	} else {
		# Start the VM
		[string] $URI = $Global:DefaultPCServer.ServiceURI + "v1/vms/" + $objVM.Id + "/stop"
		[string] $DataPayload = "{`"id`":`"$($objVM.Id)`"}"
		$StopTask = Publish-PCAPIDataJSON -URI $URI -Data $DataPayload
		$objTaskComplete = Watch-TaskCompleted -Task $StopTask -Timeout 60
		if($objTaskComplete){
			if((Get-CloudVM -Id $objVM.Id).State -eq "STOPPED"){
				$true
			} else {
				$false
			}
		} else {
			$false
		}
	}
}

function Suspend-CloudVM(){
	<#
	.SYNOPSIS
	 This cmdlet performs a Suspend Operation on the provided Virtual Machine

	.DESCRIPTION
	 This cmdlet performs a Suspend Operation on the provided Virtual Machine

	.PARAMETER Id
	The VM Id of the VM

	.PARAMETER TenantName
	The Tenant Name of the VMs to return

	.PARAMETER ProjectName
	Optionally the Project Name of the VMs to return

	.PARAMETER VMName
	The project-scoped name of the VM

	.EXAMPLE
	Suspend-CloudVM -Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"
	Performs a Suspend Operation on the VM with the Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"

	.EXAMPLE
	Suspend-CloudVM -TenantName "Marketing" -ProjectName "Campaign 2017" -Name "Prod01"
	Performs a Suspend Operation on the VM in the Campaign 2017 project under the Marketing tenant with the name "Prod01"

	.NOTES
	  NAME: Suspend-CloudVM
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-03
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller vm suspend
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Working-with-Virtual-Machines
	#>
	param(
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $Id,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $ProjectName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $VMName
	)
	# Check if the VM exists with the provided values
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$objVM = Get-CloudVM -Id $Id
	} elseif($PSCmdlet.ParameterSetName -eq "ByVMName"){
		$objVM = Get-CloudVM -TenantName $TenantName -ProjectName $ProjectName -VMName $VMName
	}
	if($objVM -eq $null){
		throw "A VM matching the criteria can not be found. Please check the values provided and try again."
	}
	# Check that the VM is currently in a state that allows it to be Started
	if(!($objVM.State -in @("STARTED"))){
		throw "The VM has a state of $($objVM.State). The Suspend Operation can not be performed in this state."
	} else {
		# Start the VM
		[string] $URI = $Global:DefaultPCServer.ServiceURI + "v1/vms/" + $objVM.Id + "/suspend"
		[string] $DataPayload = "{`"id`":`"$($objVM.Id)`"}"
		$SuspendTask = Publish-PCAPIDataJSON -URI $URI -Data $DataPayload
		$objTaskComplete = Watch-TaskCompleted -Task $SuspendTask -Timeout 60
		if($objTaskComplete){
			if((Get-CloudVM -Id $objVM.Id).State -eq "SUSPENDED"){
				$true
			} else {
				$false
			}
		} else {
			$false
		}
	}
}

function Resume-CloudVM(){
	<#
	.SYNOPSIS
	 This cmdlet performs a Resume Operation on the provided Virtual Machine

	.DESCRIPTION
	 This cmdlet performs a Resume Operation on the provided Virtual Machine

	.PARAMETER Id
	The VM Id of the VM

	.PARAMETER TenantName
	The Tenant Name of the VMs to return

	.PARAMETER ProjectName
	Optionally the Project Name of the VMs to return

	.PARAMETER VMName
	The project-scoped name of the VM

	.EXAMPLE
	Resume-CloudVM -Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"
	Performs a Suspend Operation on the VM with the Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"

	.EXAMPLE
	Resume-CloudVM -TenantName "Marketing" -ProjectName "Campaign 2017" -Name "Prod01"
	Performs a Suspend Operation on the VM in the Campaign 2017 project under the Marketing tenant with the name "Prod01"

	.NOTES
	  NAME: Resume-CloudVM
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-03
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller vm resume
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Working-with-Virtual-Machines
	#>
	param(
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $Id,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $ProjectName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $VMName
	)
	# Check if the VM exists with the provided values
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$objVM = Get-CloudVM -Id $Id
	} elseif($PSCmdlet.ParameterSetName -eq "ByVMName"){
		$objVM = Get-CloudVM -TenantName $TenantName -ProjectName $ProjectName -VMName $VMName
	}
	if($objVM -eq $null){
		throw "A VM matching the criteria can not be found. Please check the values provided and try again."
	}
	# Check that the VM is currently in a state that allows it to be Started
	if(!($objVM.State -in @("SUSPENDED"))){
		throw "The VM has a state of $($objVM.State). The Suspend Operation can not be performed in this state."
	} else {
		# Start the VM
		[string] $URI = $Global:DefaultPCServer.ServiceURI + "v1/vms/" + $objVM.Id + "/resume"
		[string] $DataPayload = "{`"id`":`"$($objVM.Id)`"}"
		$ResumeTask = Publish-PCAPIDataJSON -URI $URI -Data $DataPayload
		$objTaskComplete = Watch-TaskCompleted -Task $ResumeTask -Timeout 60
		if($objTaskComplete){
			if((Get-CloudVM -Id $objVM.Id).State -eq "STARTED"){
				$true
			} else {
				$false
			}
		} else {
			$false
		}
	}
}

function Restart-CloudVM(){
	<#
	.SYNOPSIS
	 This cmdlet performs a Restart Operation on the provided Virtual Machine

	.DESCRIPTION
	 This cmdlet performs a Restart Operation on the provided Virtual Machine

	.PARAMETER Id
	The VM Id of the VM

	.PARAMETER TenantName
	The Tenant Name of the VM

	.PARAMETER ProjectName
	Optionally the Project Name of the VM

	.PARAMETER VMName
	The project-scoped name of the VM

	.EXAMPLE
	Restart-CloudVM -Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"
	Performs a Restart Operation on the VM with the Id "4f2fe2d3-7c2a-4f35-b70a-a1d6fec90600"

	.EXAMPLE
	Restart-CloudVM -TenantName "Marketing" -ProjectName "Campaign 2017" -Name "Prod01"
	Performs a Restart Operation on the VM in the Campaign 2017 project under the Marketing tenant with the name "Prod01"

	.NOTES
	  NAME: Restart-CloudVM
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-08-15
	  STATE: Alpha (Testing)
	  KEYWORDS: vmware photon controller vm restart
	  REFERENCE: https://github.com/vmware/photon-controller/wiki/Working-with-Virtual-Machines
	#>
	param(
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $Id,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $TenantName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $ProjectName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByVMName")]
			[ValidateNotNullorEmpty()] [string] $VMName
	)
	# Check if the VM exists with the provided values
	if($PSCmdlet.ParameterSetName -eq "ById"){
		$objVM = Get-CloudVM -Id $Id
	} elseif($PSCmdlet.ParameterSetName -eq "ByVMName"){
		$objVM = Get-CloudVM -TenantName $TenantName -ProjectName $ProjectName -VMName $VMName
	}
	if($objVM -eq $null){
		throw "A VM matching the criteria can not be found. Please check the values provided and try again."
	}
	# Check that the VM is currently in a state that allows it to be Started
	if(!($objVM.State -in @("STARTED"))){
		throw "The VM has a state of $($objVM.State). The Restart Operation can not be performed in this state."
	} else {
		# Start the VM
		[string] $URI = $Global:DefaultPCServer.ServiceURI + "v1/vms/" + $objVM.Id + "/restart"
		[string] $DataPayload = "{`"id`":`"$($objVM.Id)`"}"
		$ResumeTask = Publish-PCAPIDataJSON -URI $URI -Data $DataPayload
		$objTaskComplete = Watch-TaskCompleted -Task $ResumeTask -Timeout 60
		if($objTaskComplete){
			if((Get-CloudVM -Id $objVM.Id).State -eq "STARTED"){
				$true
			} else {
				$false
			}
		} else {
			$false
		}
	}
}
function Mount-CloudVMISO(){
	throw "Not yet implementated"
}

function Dismount-CloudVMISO(){
	throw "Not yet implementated"
}

function Mount-CloudDisk(){
	throw "Not yet implementated"
}

function Dismount-CloudDisk(){
	throw "Not yet implementated"
}

function New-CloudImage(){
	throw "Not yet implementated"
}
#endregion
