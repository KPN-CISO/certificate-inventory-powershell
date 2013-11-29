#Requires -version 2.0

##############################################
# This file is part of certificate-inventory.
#
# certificate-inventory is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# certificate-inventory is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# certificate-inventory. If not, see <http://www.gnu.org/licenses/>.
##############################################

##############################################
# Author: Oscar Koeroo <oscar.koeroo@kpn.com>
# Office: KPN CISO / Red Team - Ethical Hacker
# Project: Certs-on-Fire
# Date: October 1, 2013
# Version: 0.1, powershell spinoff
# License: GPLv3
##############################################


$Ip = "62.132.193.64"
$Port = 443
$Connection = New-Object System.Net.Sockets.TcpClient($Ip,$Port)
$Connection.SendTimeout = 5000
$Connection.ReceiveTimeout = 5000
$Stream = $Connection.GetStream()

try {
    $sslStream = New-Object System.Net.Security.SslStream($Stream,$False,([Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}))
    $sslStream.AuthenticateAsClient($null)

    #$Certificate = [Security.Cryptography.X509Certificates.X509Certificate2]$sslStream.RemoteCertificate

    $cert = $sslStream.get_remotecertificate()
    $cert2 = New-Object system.security.cryptography.x509certificates.x509certificate2($cert)

    $validto = [datetime]::Parse($cert.getexpirationdatestring())
    $validfrom = [datetime]::Parse($cert.geteffectivedatestring())

    if ($cert.get_issuer().CompareTo($cert.get_subject())) {
        $selfsigned = "no";
    } else {
        $selfsigned = "yes";
    }

    Write-Host '"' -nonewline; Write-Host $Ip -nonewline; Write-Host '",' -nonewline;
    Write-Host '"' -nonewline; Write-Host $Port -nonewline; Write-Host '",' -nonewline;
    Write-Host '"' -nonewline; Write-Host $cert.get_subject() -nonewline; Write-Host '",' -nonewline;
    Write-Host '"' -nonewline; Write-Host $cert.get_issuer() -nonewline; Write-Host '",' -nonewline;
    Write-Host '"' -nonewline; Write-Host $cert2.PublicKey.Key.KeySize -nonewline; Write-Host '",' -nonewline;
    Write-Host '"' -nonewline; Write-Host $cert.getserialnumberstring() -nonewline; Write-Host '",' -nonewline;
    Write-Host '"' -nonewline; Write-Host $validfrom -nonewline; Write-Host '",' -nonewline;
    Write-Host '"' -nonewline; Write-Host $validto -nonewline; Write-Host '",' -nonewline;
    Write-Host '"' -nonewline; Write-Host $selfsigned -nonewline; Write-Host '",' -nonewline;
    Write-Host '"' -nonewline; Write-Host $cert2.SignatureAlgorithm.FriendlyName -nonewline; Write-Host '"';

} finally {
    $Connection.Close()
}

