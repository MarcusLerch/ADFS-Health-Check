<#
=============================================================================
THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

This sample is not supported under any standard support program or
service. The code sample is provided AS IS without warranty of any kind.
lmxlabs further disclaims all implied warranties including, without
limitation, any implied warranties of merchantability or of fitness for a
particular purpose. The entire risk arising out of the use or performance of
the sample and documentation remains with you. In no event shall lmxlabs, 
its authors, or anyone else involved in the creation, production, or delivery 
of the script be liable for any damages whatsoever (including, without 
limitation, damages for loss of business profits, business interruption, loss
of business information, or other pecuniary loss) arising out of  the use of
or inability to use the sample or documentation, even if lmxlabs has been 
advised of the possibility of such damages.
=============================================================================
#>
#Requires -Version 3

#region Parameter
[cmdletBinding(SupportsShouldProcess=$true)]
param(
    [String]$ConfigFile="config.xml",
    [pscredential]$Credential,
    [String]$LogDir
)

#endregion

[String]$ScriptVersion = "1.2.0"

#region Functions
function Log2File{
param(
[string]$log,
[string]$text
)
"$(Get-Date -Format "yyyyMMdd-HH:mm:ss"):`t$text" | Out-File -FilePath $log -Append
Write-Verbose $text
}

function Get-SSLCert {
    param(
        [string]$ServerUrl,
        [int]$ServerSslPort
    )
    if(!($ServerSslPort)){$ServerSslPort = 443}
    $tcpClient = New-Object Net.Sockets.TcpClient($ServerUrl,$ServerSslPort)
    if(!$tcpClient) {
        Log2File -log $LogFile -text ("Error connecting to: {0} on port: {1}" -f $ServerUrl,$ServerSslPort)
    }
    else {
        Log2File -log $LogFile -text ("Success connecting to: {0} on port: {1}" -f $ServerUrl,$ServerSslPort)
        $tcpStream = $tcpClient.GetStream()
        Log2File -log $LogFile -text ("Getting SSL Certificate from {0}" -f $ServerUrl)
        $SslStream = New-Object System.Net.Security.SslStream($tcpStream,$false)
        $SslStream.AuthenticateAsClient($ServerUrl) # trigger certificate to be send
        $SslCert = New-Object system.security.cryptography.x509certificates.x509certificate2($SslStream.RemoteCertificate)
        $SslCert
    }
}

function Get-ADFSCertificateFromMetadata{
    param(
        [string]$ServerUrl,
        [int]$ServerSslPort,
        [string]$FederationDocPath = "/federationmetadata/2007-06/federationmetadata.xml"
    )
    if($ServerSslPort){$SslPort = ":$ServerSslPort"}
    $FederationDocUrl = ('https://{0}{1}/{2}' -f $ServerUrl, $sslPort, $FederationDocPath) 
    $FederationCerts = @{}
    Log2File -log $LogFile -text ("Getting Federation Document from {0}" -f $FederationDocUrl)
    try {
    $Global:FederationDocXml = [xml](Invoke-WebRequest -Uri $FederationDocUrl -UseBasicParsing).content
    }
    catch {
    Log2File -log $LogFile -text ("Error: Could not get federation xml document")
    }
    $keyDescriptors = $Global:FederationDocXml.GetElementsByTagName('KeyDescriptor')
    $FederationCerts = @{}
    foreach ($keyDescriptor in $keyDescriptors){
        try{
            $FederationCerts.Add($keyDescriptor.KeyInfo.X509Data.X509Certificate,@($keyDescriptor.use))
        }
        catch{
            if($FederationCerts.Item($keyDescriptor.KeyInfo.X509Data.X509Certificate) -notcontains $keyDescriptor.use){
                $FederationCerts.Item($keyDescriptor.KeyInfo.X509Data.X509Certificate) += $keyDescriptor.use
            }
        }
    }
    foreach ($CertBase64 in $FederationCerts.Keys){
        $CertArray = [System.convert]::FromBase64String($CertBase64)
        $TempCertificate = new-object System.Security.Cryptography.X509Certificates.X509Certificate2(,$CertArray)
        $TempCertificate | Add-Member -MemberType NoteProperty -Name 'KeyUsage' -Value $FederationCerts.Item($CertBase64)
        $TempCertificate
    }
}
#endregion

#region Initialize
$rundatestring = ("{0:yyyyMMdd}" -f (get-date))
$ScriptPath = $MyInvocation.MyCommand.Path | Split-Path
if($LogDir){
    if(-not (Test-Path $LogDir -PathType Container)){
        $LogDir = $ScriptPath
    }
}
else{
    $LogDir = $ScriptPath
}
$LogFilePath = "$LogDir\$rundatestring"

if (-not (Test-Path $LogFilePath -PathType Container)){ $null = mkdir $LogFilePath -Force }
$LogFile = "$LogFilePath\$rundatestring-RuntimeLog.log"
[String]$Spacer = "=" * 80

$HTMLRed = "bgcolor=#FF4000"
$HTMLGreen = "bgcolor=#13D813"
$HTMLYellow = "bgcolor=#F7FE2E"

Log2File -log $LogFile -text $Spacer
Log2File -log $LogFile -text "Starting"
#endregion

#region Read config
if(Test-Path $ConfigFile -PathType Leaf){
    $config = $ConfigFile
}
elseif(Test-Path "$ScriptPath\$ConfigFile" -PathType Leaf){
    $config = "$ScriptPath\$ConfigFile"
}
else{
    Write-Host ("Configuration file {0} not found and config not in script path.`nExiting script" -f $ConfigFile)
    break
}

Log2File -log $LogFile -text "Reading configuration from file $config"
[xml]$configuration = Get-Content $config

$recipients = @()
Log2File -log $LogFile -text "Reading recipients"
foreach ($recipient in $configuration.ScriptConfiguration.MailSettings.recipientlist){
    Log2File -log $LogFile -text "`t - $($recipient.recipient)"
    $recipients += $recipient.recipient
}

$MetaDataRecipientList = @()
Log2File -log $LogFile -text "Reading recipients for metadata mail"
foreach ($recipient in $configuration.ScriptConfiguration.MailSettings.MetaDataRecipientList){
    Log2File -log $LogFile -text "`t - $($recipient.recipient)"
    $MetaDataRecipientList += $recipient.recipient
}


[bool][int]$sendMail = $configuration.ScriptConfiguration.MailSettings.SendMail
Log2File -log $LogFile -text "SendMail:"
Log2File -log $LogFile -text "`t - $sendMail"

$smtpserver = $configuration.ScriptConfiguration.MailSettings.'SMTP-Server'
Log2File -log $LogFile -text "SMTP Server to use"
Log2File -log $LogFile -text "`t - $smtpserver"

$Sender = $configuration.ScriptConfiguration.MailSettings.Sender
Log2File -log $LogFile -text "Mail sender"
Log2File -log $LogFile -text "`t - $Sender"

$Subject = $configuration.ScriptConfiguration.MailSettings.Subject
Log2File -log $LogFile -text "Mail subject"
Log2File -log $LogFile -text "`t - $Subject"

[int]$EventlogCheckDays = $configuration.ScriptConfiguration.EventLogSettings.CheckDays 
Log2File -log $LogFile -text "Number of days for Eventlog reporting" 
Log2File -log $LogFile -text "`t - $EventlogCheckDays" 
[String]$EventlogCheckDays = $EventlogCheckDays * -1 

$CheckEventIDs = @()
Log2File -log $LogFile -text "Reading EventIDs to check"
foreach ($CheckEventID in $configuration.ScriptConfiguration.EventLogSettings.EventIDs.EventID){
    Log2File -log $LogFile -text "`t - $($CheckEventID)"
    $CheckEventIDs += $CheckEventID
}

$ADFSFarmURL = $configuration.ScriptConfiguration.WebSettings.FarmURL
Log2File -log $LogFile -text "ADFS Farm URL"
Log2File -log $LogFile -text "`t - $ADFSFarmURL"

$ADFSFarmSSLPort = $configuration.ScriptConfiguration.WebSettings.SSLPort
Log2File -log $LogFile -text "ADFS Farm SSLPort"
Log2File -log $LogFile -text "`t - $ADFSFarmSSLPort"

$CheckURLs = @{}
Log2File -log $LogFile -text "Reading URLs to check"
foreach ($ReadURL in $configuration.ScriptConfiguration.WebSettings.CheckURLs.URL){
    Log2File -log $LogFile -text "`t - $($ReadURL.URLType)"
    $CheckURLs.Add($ReadURL.URLType,$ReadURL.URLPath)
}

$CheckServers = @()
Log2File -log $LogFile -text "Reading servers to check"
foreach ($CheckServer in $configuration.ScriptConfiguration.Servers.ServerName){
    Log2File -log $LogFile -text "`t - $($CheckServer)"
    $CheckServers += $CheckServer
}

$CheckServices = @()
Log2File -log $LogFile -text "Reading services to check"
foreach ($ReadService in $configuration.ScriptConfiguration.Services.Service){
    Log2File -log $LogFile -text "`t - $($ReadService.ServiceName)"
    $htService = @{'ServiceName'=$ReadService.ServiceName;'StartMode'=$ReadService.StartMode;'State'=$ReadService.State}
    $CheckServices += New-Object PSObject -Property $htService
}
#endregion

#region Main

Log2File -log $LogFile -text "Starting checks of ADFS Farm"
$sslWebCert = Get-SSLCert -ServerUrl $ADFSFarmURL -ServerSslPort $ADFSFarmSSLPort
Log2File -log $LogFile -text ("Found SSL certificate with subject : {0}" -f $sslWebCert.Subject)
Log2File -log $LogFile -text ("      SSL certificate valid from   : {0}" -f $sslWebCert.NotBefore)
Log2File -log $LogFile -text ("      SSL certificate valid until  : {0}" -f $sslWebCert.NotAfter)

$ADFSCerts = Get-ADFSCertificateFromMetadata -ServerUrl $ADFSFarmURL -FederationDocPath $CheckURLs['MetadataXML'] -ServerSslPort $ADFSFarmSSLPort
$CertCounter = New-Object System.Object | Select-Object -Property Signing,Encryption,Other
$CertCounter.Signing = 0
$CertCounter.Encryption = 0
$CertCounter.Other = 0
foreach($ADFSCert in $ADFSCerts){
    switch ($ADFSCert.KeyUsage){
        {$_ -contains 'signing'}{
            $ADFSSigningCert = $ADFSCert
            $CertCounter.Signing++
            Log2File -log $LogFile -text ("Found ADFS signing certificate with subject : {0}" -f $ADFSCert.Subject)
            Log2File -log $LogFile -text ("      ADFS signing certificate valid from   : {0}" -f $ADFSCert.NotBefore)
            Log2File -log $LogFile -text ("      ADFS signing certificate valid until  : {0}" -f $ADFSCert.notafter)
        }
        {$_ -contains 'encryption'}{
            $ADFSEncryptionCert = $ADFSCert
            $CertCounter.Encryption++
            Log2File -log $LogFile -text ("Found ADFS encryption certificate with subject : {0}" -f $ADFSCert.Subject)
            Log2File -log $LogFile -text ("      ADFS encryption certificate valid from   : {0}" -f $ADFSCert.NotBefore)
            Log2File -log $LogFile -text ("      ADFS encryption certificate valid until  : {0}" -f $ADFSCert.NotAfter)
        }
        default {
            $CertCounter.Other++
            Log2File -log $LogFile -text ("Found additional ADFS certificate with subject {0}" -f $ADFSCert.Subject)
        }
    }
}

#region Check URLs and export result
$webCheckResults = @()
if($ADFSFarmSSLPort){$SSLport = ":$ADFSFarmSSLPort"}
foreach($CheckURL in $CheckURLs.GetEnumerator()){
    $webCheck = [ordered]@{}
    $webCheck.Type = $CheckURL.Name
    $webCheck.URL = ('https://{0}{1}/{2}' -f $ADFSFarmURL, $SSLport, $CheckURL.Value) 
    Log2File -log $LogFile -text ("Checking {0} Url {1}" -f $CheckURL.Name,$webCheck.URL)
    $HttpResponse = Invoke-WebRequest -Uri $webCheck.URL -UseBasicParsing
    $webCheck.StatusCode = $HttpResponse.StatusCode
    $webCheck.StatusDescription = $HttpResponse.StatusDescription
    New-Variable -Name ($CheckURL.Name) -Value ($HttpResponse.StatusDescription)
    $webCheckObject = New-Object psobject -Property $webCheck
    $webCheckResults += $webCheckObject
}
$webCheckResults | Export-Csv -Path "$LogFilePath\WebCheckResults.csv" -Delimiter ';' -NoTypeInformation
#endregion

#region Create ScriptBlock to run on ADFS server
Log2File -log $LogFile -text "Creating script block for ADFS server checks"

$EventIDQuery = "("
for($i=0; $i -lt $CheckEventIDs.count; $i++){
    $EventIDQuery += "EventID=" + $CheckEventIDs[$i]
    if($i -lt $CheckEventIDs.count -1 ){
        $EventIDQuery += " or "
    }
}
$EventIDQuery += ")"

$TimeToCheck = 86400000 * [int]$EventlogCheckDays
$filterXML = @"
<QueryList>
  <Query Id="0" Path="AD FS/Admin">
    <Select Path="AD FS/Admin">*[System[(Level=2) and $EventIDQuery and TimeCreated[timediff(@SystemTime) &lt;= $TimeToCheck]]]</Select>
  </Query>
</QueryList>
"@
Write-Verbose $filterXML

$SBText = @'
$ADFS_HealthInfo = [ordered]@{}
$ADFS_HealthInfo.Computername = $env:COMPUTERNAME
$ADFS_HealthInfo.OSDirFreeSpace = (Get-WmiObject -Query "SELECT FreeSpace FROM win32_logicaldisk WHERE DeviceID = 'C:'").FreeSpace /1GB
$ADFS_HealthInfo.UnexpectedShutdown = @(Get-Eventlog 'System' -After (get-date).AddDays($using:EventlogCheckDays) -EntryType Error -ErrorAction SilentlyContinue | Where-Object {$_.EventID -eq 6008})
$ADFS_HealthInfo.UnexpectedShutdownCount = $ADFS_HealthInfo.UnexpectedShutdown.Count
$ADFS_HealthInfo.EventCollection = @(Get-WinEvent -FilterXml $using:filterXML -ErrorAction SilentlyContinue) 
$ADFS_HealthInfo.EventCollectionCount = $ADFS_HealthInfo.EventCollection.Count 
$ServicesChecked = @()
foreach ($Service2Check in $using:CheckServices){
    $Service = Get-WmiObject -Query "SELECT Name,State,StartMode FROM win32_service WHERE Name='$($Service2Check.ServiceName)'" | Select-Object -Property Name,State,StartMode
    if (($Service.State -eq $Service2Check.State) -and ($Service.StartMode -eq $Service2Check.StartMode)){
        $ServiceResult = [ordered]@{'Computername'=$env:COMPUTERNAME;'ServiceName'=$Service2Check.ServiceName;'CheckResult'='OK';'StartMode'=$Service.StartMode;'State'=$Service.State}
    }
    else {
        $ServiceResult = [ordered]@{'Computername'=$env:COMPUTERNAME;'ServiceName'=$Service2Check.ServiceName;'CheckResult'='ERROR';'StartMode'=$Service.StartMode;'State'=$Service.State}
    }
    $ServicesChecked += New-Object PSObject -Property $ServiceResult
}
$ADFS_HealthInfo.CheckedServices = $ServicesChecked
New-Object PSObject -Property $ADFS_HealthInfo
'@

$SB = [ScriptBlock]::Create($SBText)
#endregion

#region Run checks on farmservers
Log2File -log $LogFile -text "Collecting information from the ADFS servers" 
if ($Credential){
    $results = @(Invoke-Command -ComputerName $CheckServers -ScriptBlock $SB -Credential $Credential) 
}
else{
    $results = @(Invoke-Command -ComputerName $CheckServers -ScriptBlock $SB) 
}
$CertificatesChecked = @()
foreach ($ADFSCert in $ADFSCerts){
    $CheckCert = New-Object PSObject | Select-Object -Property 'KeyUsage','Certificate','CheckResult'
    $CheckCert.KeyUsage = $ADFSCert.KeyUsage
    $CheckCert.Certificate = Get-AdfsCertificate | Where-Object {$_.Thumbprint -eq $ADFSCert.Thumbprint}
    if($CheckCert.Certificate){
        $CheckCert.CheckResult = 'Success'
    }
    else{
        $CheckCert.CheckResult = 'Error'
    }
    $CertificatesChecked += $CheckCert
}
#$ADFS_HealthInfo.CertificatesChecked = $CertificatesChecked

#endregion 

$FarmResults = @()
$FarmServices = @()
$CertErrors = 0
$ServiceErrors = 0
$EventCount = 0
$UXShutdowns = 0
foreach($result in $results){
    $FarmServer = [ordered]@{}
    $FarmServer.Name = $result.Computername
    $FarmServer.OSDiskFreeSpace = $result.OSDirFreeSpace
    $FarmServer.UnexpectedShutdown = $result.UnexpectedShutdownCount
    $UXShutdowns += $result.UnexpectedShutdownCount
    $FarmServer.Events = $result.EventCollectionCount
    $EventCount += $result.EventCollectionCount
    $FarmServer.ServiceError = $false
    foreach($service in $result.CheckedServices){
        $FarmService = [ordered]@{}
        $FarmService.Computername = $service.Computername
        $FarmService.ServiceName = $service.ServiceName
        $FarmService.StartMode = $service.StartMode
        $FarmService.State = $service.State
        $FarmService.CheckResult = $service.CheckResult
        if($service.CheckResult -ne "OK"){
            $FarmServer.ServiceError = $true
            $ServiceErrors++
        }
        $FarmServiceObject = New-Object psobject -Property $FarmService
        $FarmServices += $FarmServiceObject
    }
    $FarmServer.CertificateError = $false
    foreach($ServerCert in $CertificatesChecked){
        if($ServerCert.CheckResult -ne "Success"){
            $FarmServer.CertificateError = $true
            $CertErrors++
        }
    }
    $FarmServerObject = New-Object psobject -Property $FarmServer
    $FarmResults += $FarmServerObject
}
$FarmResults | Export-Csv -Path "$LogFilePath\$rundatestring-ADFSFarmHealth.csv" -NoTypeInformation -Delimiter ";" -Force
$FarmServices | Export-Csv -Path "$LogFilePath\$rundatestring-ServiceCheck.csv" -NoTypeInformation -Delimiter ";" -Force

#region generating mail
Log2File -log $LogFile -text "Generating report"
Log2File -log $LogFile -text "Reading mail body template from $Scriptpath\MailBody.html"
[string]$MailBody = Get-Content -Path "$Scriptpath\MailBody.html"

$MailBody = $MailBody.Replace("___ADFSFARM___",$ADFSFarmURL)
$MailBody = $MailBody.Replace("___SIGNON___",$SignonPage)
$MailBody = $MailBody.Replace("___WEBSERVICE___",$WebServiceXML)
$MailBody = $MailBody.Replace("___TRUST___",$TrustXML)
$MailBody = $MailBody.Replace("___METADATA___",$MetadataXML)
$MailBody = $MailBody.Replace("___SIGNING___",$ADFSSigningCert.NotAfter)
$MailBody = $MailBody.Replace("___ENCRYPTION___",$ADFSEncryptionCert.NotAfter)
$MailBody = $MailBody.Replace("___SSL___",$sslWebCert.NotAfter)
$MailBody = $MailBody.Replace("___CERTERRORS___",$CertErrors)
$MailBody = $MailBody.Replace("___SERVICEERRORS___",$ServiceErrors)
$MailBody = $MailBody.Replace("___EVENTCOUNT___",$EventCount)
$MailBody = $MailBody.Replace("___SHUTDOWNS___",$UXShutdowns)

switch ($SignonPage){
    {"OK"} {$MailBody = $MailBody.Replace("___SIGNONCOLOR___",$HTMLGreen); break}
    default {$MailBody = $MailBody.Replace("___SIGNONCOLOR___",$HTMLRed)}
}
switch ($WebServiceXML){
    {"OK"} {$MailBody = $MailBody.Replace("___WEBCOLOR___",$HTMLGreen); break}
    default {$MailBody = $MailBody.Replace("___WEBCOLOR___",$HTMLRed)}
}
switch ($TrustXML){
    {"OK"} {$MailBody = $MailBody.Replace("___TRUSTCOLOR___",$HTMLGreen); break}
    default {$MailBody = $MailBody.Replace("___TRUSTCOLOR___",$HTMLRed)}
}
switch ($MetadataXML){
    {"OK"} {$MailBody = $MailBody.Replace("___METACOLOR___",$HTMLGreen); break}
    default {$MailBody = $MailBody.Replace("___METACOLOR___",$HTMLRed)}
}
switch ($ADFSSigningCert.NotAfter){
    {$_ -gt (Get-Date).AddMonths(-1)} {$MailBody = $MailBody.Replace("___SIGNCOLOR___",$HTMLGreen); break}
    {$_ -gt (Get-Date).AddDays(-14)} {$MailBody = $MailBody.Replace("___SIGNCOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___SIGNCOLOR___",$HTMLRed)}
}
switch ($ADFSEncryptionCert.NotAfter){
    {$_ -gt (Get-Date).AddMonths(-1)} {$MailBody = $MailBody.Replace("___ENCRYPTCOLOR___",$HTMLGreen); break}
    {$_ -gt (Get-Date).AddDays(-14)} {$MailBody = $MailBody.Replace("___ENCRYPTCOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___ENCRYPTCOLOR___",$HTMLRed)}
}
switch ($sslWebCert.NotAfter){
    {$_ -gt (Get-Date).AddMonths(-2)} {$MailBody = $MailBody.Replace("___SSLCOLOR___",$HTMLGreen); break}
    {$_ -gt (Get-Date).AddMonths(-1)} {$MailBody = $MailBody.Replace("___SSLCOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___SSLCOLOR___",$HTMLRed)}
}
switch ($CertErrors){
    {$_ -gt 0} {$MailBody = $MailBody.Replace("___CERTCOLOR___",$HTMLRed); break}
    default {$MailBody = $MailBody.Replace("___CERTCOLOR___",$HTMLGreen)}
}
switch ($ServiceErrors){
    {$_ -gt 1} {$MailBody = $MailBody.Replace("___SRVCOLOR___",$HTMLRed); break}
    {$_ -gt 0} {$MailBody = $MailBody.Replace("___SRVCOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___SRVCOLOR___",$HTMLGreen)}
}
switch ($EventCount){
    {$_ -gt 5} {$MailBody = $MailBody.Replace("___EVENTCOLOR___",$HTMLRed); break}
    {$_ -gt 0} {$MailBody = $MailBody.Replace("___EVENTCOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___EVENTCOLOR___",$HTMLGreen)}
}
switch ($UXShutdowns){
    {$_ -gt 1} {$MailBody = $MailBody.Replace("___SHUTDOWNCOLOR___",$HTMLRed); break}
    {$_ -gt 0} {$MailBody = $MailBody.Replace("___SHUTDOWNCOLOR___",$HTMLYellow); break}
    default {$MailBody = $MailBody.Replace("___SHUTDOWNCOLOR___",$HTMLGreen)}
}
if(($CertCounter.Signing -gt 1) -or ($CertCounter.Encryption -gt 1)){
    [string]$MetadataMailBody = Get-Content -Path "$Scriptpath\MetadataMailBody.html"
    $MailBody = $MailBody.Replace("___ROLLOVER___","<br>!!! Achtung, die ADFS Farm befindet sich im Zertifikats Rollover Prozess !!!<br>!!! Bitte informieren sie die beteiligten Stellen &uuml;ber die neuen Zertifkate !!!")
    $Global:FederationDocXml | Out-File -FilePath "$LogFilePath\$rundatestring-FederationMetadata.xml" -Force
    $MetadataMailBody = $MetadataMailBody.Replace("___ADFSFARM___",$ADFSFarmURL)
    $MetadataMailBody = $MetadataMailBody.Replace("___SCRIPTNAME___",$MyInvocation.MyCommand.Path)
    $MetadataMailBody = $MetadataMailBody.Replace("___SCRIPTVERSION___",$ScriptVersion)
    $MetadataMailBody = $MetadataMailBody.Replace("___SERVERNAME___",$env:COMPUTERNAME)
    Log2File -log $LogFile -text "Sending metadata mail"
    Send-MailMessage -BodyAsHtml -Body $MetadataMailBody `
                -Attachments "$LogFilePath\$rundatestring-FederationMetadata.xml" `
                -To $MetaDataRecipientList `
                -From $Sender `
                -SmtpServer $smtpserver `
                -Subject $Subject 
}
else{
    $MailBody = $MailBody.Replace("___ROLLOVER___","")
}

$MailBody = $MailBody.Replace("___SCRIPTNAME___",$MyInvocation.MyCommand.Path)
$MailBody = $MailBody.Replace("___SCRIPTVERSION___",$ScriptVersion)
$MailBody = $MailBody.Replace("___SERVERNAME___",$env:COMPUTERNAME)

$Attachements = Get-ChildItem -Path $LogFilePath | ForEach-Object {$_.FullName}

if($sendMail){
Log2File -log $LogFile -text "Sending mail"
Send-MailMessage -BodyAsHtml -Body $MailBody `
            -Attachments $Attachements `
            -To $recipients `
            -From $Sender `
            -SmtpServer $smtpserver `
            -Subject $Subject 
}
$MailBody | Out-File -FilePath "$LogFilePath\SentMail.html" 
$MetadataMailBody | Out-File -FilePath "$LogFilePath\SentMetadataMail.html" 

#endregion
Log2File -log $LogFile -text "Ended"
Log2File -log $LogFile -text $Spacer
#endregion
