$DomainName = "bjarki-eep.local"
# Netstillingar PASSA NAFN Á NETIIIIIII
function finna_netkort {
    param(
    [Parameter(Mandatory=$true, HelpMessage="Slá inn Ip tölu")]
    [string]$ipaddress
    )
    $ip = Get-NetIPaddress -IPAddress $ipaddress
    return $ip.InterfaceAlias
}

Rename-NetAdapter -Name (finna_netkort -ipaddress 169.254.*) -NewName "LAN"
New-NetIPAddress -InterfaceAlias "LAN" -IPAddress 172.16.3.254 -PrefixLength 22
Set-DnsClientServerAddress -InterfaceAlias "LAN" -ServerAddresses 127.0.0.1

# Setja inn AD-DS role
Install-WindowsFeature -Name ad-domain-services -IncludeManagementTools

# Promote server í DC
Install-ADDSForest -DomainName $DomainName -InstallDns -SafeModeAdministratorPassword (ConvertTo-SecureString -AsPlainText "pass.123" -Force) 

# REBOOT---------------------------------------------------------------------REBOOT-----------------------------------------------------REBOOT------------------REBOOT

# Setja upp DHCP
Install-WindowsFeature -Name DHCP -IncludeManagementTools

# Setja upp scope
Add-DhcpServerv4Scope -Name scope1 -StartRange 172.16.0.1 -EndRange 172.16.3.91 -SubnetMask 255.255.252.0
Set-DhcpServerv4OptionValue -DnsServer 172.16.3.254 -Router 172.16.3.254
Add-DhcpServerInDC $($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN)

#----------------------------------------------------------------------------------------------------------------------------------------------------------------------

$passwd = ConvertTo-SecureString -AsPlainText "2015P@ssword" -force
$win8notandi = New-Object System.Management.Automation.PSCredential -ArgumentList $("win3a-w81-04\administrator"), $passwd
$serverNotandi = New-Object System.Management.Automation.PSCredential -ArgumentList $($env:USERDOMAIN + "\administrator"), $passwd

# Setja win 8 vél á domain
Add-Computer -ComputerName "win3a-w81-04" -LocalCredential $win8notandi -DomainName $env:USERDNSDOMAIN -Credential $serverNotandi -Restart -Force

# Bú til OU fyrir tölvur
New-ADOrganizationalUnit -Name Tölvur -ProtectedFromAccidentalDeletion $false

# Færa win 8 vél í nýja tölvur OU
Move-ADObject -Identity $("CN=WIN3A-W81-04,CN=Computers,DC=" + $env:USERDOMAIN + ", dc=" + $env:USERDNSDOMAIN.Split('.')[1]) -TargetPath $("ou=Tölvur, dc=" + $env:USERDOMAIN + ", dc=" + $env:USERDNSDOMAIN.Split('.')[1])

#---------------Notendur--------------
New-ADOrganizationalUnit Notendur -ProtectedFromAccidentalDeletion $false
New-ADGroup -Name Allir -Path $("ou=notendur, dc=" + $env:USERDOMAIN + ", dc=" + $env:USERDNSDOMAIN.Split('.')[1]) -GroupScope Global 

$notendur = Import-Csv .\notendur.csv
#VEF
Install-WindowsFeature web-server -IncludeManagementTools
Add-DnsServerPrimaryZone -Name "eep.is" -ReplicationScope Domain

function breyta_stofum {
   param(
    [string]$nafn
    )
    $nafn = $nafn.ToLower()
    $nafn = $nafn.Replace("á","a")
    $nafn = $nafn.Replace("ó","o")
    $nafn = $nafn.Replace("í","i")
    $nafn = $nafn.Replace("ö","o")
    $nafn = $nafn.Replace("ð","d")
    $nafn = $nafn.Replace("þ","th")
    $nafn = $nafn.Replace("ý","y")
    $nafn = $nafn.Replace("ú","u")
    $nafn = $nafn.Replace("é","e")
    $nafn = $nafn.Replace("æ","ae")
    $nafn
}

foreach($n in $notendur) {
    $deild = $n.deild
    if((Get-ADOrganizationalUnit -Filter { name -eq $deild}).Name -ne $deild){
        New-ADOrganizationalUnit -Name $deild -Path $("ou=notendur, dc=" + $env:USERDNSDOMAIN.split(".")[0] +  ", dc=" + $env:USERDNSDOMAIN.Split(".")[1]) -ProtectedFromAccidentalDeletion $false
        New-ADGroup -Name $deild -Path $("ou="+$deild+", ou=notendur, dc=" + $env:USERDNSDOMAIN.split(".")[0] +  ", dc=" + $env:USERDNSDOMAIN.Split(".")[1]) -GroupScope Global
        Add-ADGroupMember -Identity Allir -Members $deild
        # Búa til möppur
        New-Item $("C:\DATA\"+$deild) -ItemType directory
        $rettindi = Get-Acl -Path $("C:\DATA\"+$deild)
        $nyrettindi = New-Object System.Security.Accesscontrol.FileSystemAccessrule ($($env:userdomain + "\" + $deild),"Modify","Allow")
        $rettindi.AddAccessRule($nyrettindi)
        Set-Acl -Path $("C:\DATA\"+$deild) $rettindi
        New-SmbShare -Name $deild -Path $("C:\DATA\"+$deild) -FullAccess Everyone
        # Prentarar
        Add-PrinterDriver -Name "HP LaserJet 2300L PCL6 Class Driver"
        Add-Printer -Name $($deild + "_prentari") -DriverName "HP LaserJet 2300L PCL6 Class Driver" -PortName "LPT1:" -Location "Þarna" -Shared -ShareName $($deild + "_prentari") -Published
    }
    #New-ADUser -Name $n.nafn -DisplayName $n.nafn -GivenName $n.fornafn -Surname $n.eftirnafn -SamAccountName $n.notendanafn -UserPrincipalName $($n.notendanafn + "@"+$env:USERDNSDOMAIN) -AccountPassword (convertTo-SecureString -AsPlainText "pass.123" -force) -Path $("ou="+$deild+", ou=notendur, dc="+ $env:USERDOMAIN + ", dc=" + $env:USERDNSDOMAIN.Split('.')[1]) -Enabled $true
    $Arguments = @{
        Name = $n.nafn
        DisplayName = $n.nafn
        GivenName = $n.fornafn 
        Surname = $n.eftirnafn 
        SamAccountName = $n.notendanafn 
        UserPrincipalName = $($n.notendanafn + "@"+$env:USERDNSDOMAIN) 
        AccountPassword = (convertTo-SecureString -AsPlainText "pass.123" -force) 
        Path = $("ou="+$deild+", ou=notendur, dc="+ $env:USERDOMAIN + ", dc=" + $env:USERDNSDOMAIN.Split('.')[1]) 
        Enabled = $true
        Title = $n.starfsheiti
        City = $n.sveitarfelag
        HomePhone = $n.heimasimi
        OfficePhone = $n.vinnusimi
        MobilePhone = $n.farsimi
    }
    New-ADUser @Arguments 
    Add-ADGroupMember -Identity $deild -Members $n.notendanafn
    #-------- VEFSÍÐA ---------
    $slod = breyta_stofum -nafn $n.notendanafn
    Add-DnsServerResourceRecordA -ZoneName "eep.is" -Name $slod -IPv4Address "172.16.3.254"
    New-Item $("C:\inetpub\wwwroot\"+$slod) -ItemType Directory
    New-Item $("C:\inetpub\wwwroot\"+$slod+"\index.html") -ItemType File -Value $("Vefsíðan" + $slod)
    New-Website -Name $slod -HostHeader $slod -PhysicalPath $("C:\inetpub\wwwroot\"+$slod+"\")
}
#---------IP scirpta---------
