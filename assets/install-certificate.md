# Install proxyfor's Certificate Authority
<!-- <head>
    <title>proxyfor</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head> -->

<!-- <style>
summary {
    display: flex;
    align-items: center;
}
summary * {
    margin: 0;
    padding: 0;
}

summary::-webkit-details-marker {
    display: none;
}

summary:before {
    content: '►';
    display: inline-block;
    margin-right: 5px;
}
</style> -->

<details>
<summary>

## Windows
</summary>

[proxyfor-ca-cert.cer](http://proxyfor.local/proxyfor-ca-cert.cer)

### Manual Installation

1.  Double-click the CER file to start the import wizard.
2.  Select a certificate store location. This determines who will trust the certificate – only the current Windows user or everyone on the machine. Click Next.
3.  Click Next again.
4.  Leave Password blank and click Next.
5.  **Select Place all certificates in the following store**, then click Browse, and select Trusted Root Certification Authorities.  
    Click OK and Next.
6.  Click Finish.
7.  Click Yes to confirm the warning dialog.

### Automated Installation

1.  Run `certutil.exe -addstore root proxyfor-ca-cert.cer` ([details](https://technet.microsoft.com/en-us/library/cc732443.aspx)).

</details>

<details>
<summary>

## Linux
</summary>

[proxyfor-ca-cert.pem](http://proxyfor.local/proxyfor-ca-cert.pem)

### Ubuntu/Debian

1.  `mv proxyfor-ca-cert.pem /usr/local/share/ca-certificates/proxyfor.crt`
2.  `sudo update-ca-certificates`

### Fedora

1.  `mv proxyfor-ca-cert.pem /etc/pki/ca-trust/source/anchors/`
2.  `sudo update-ca-trust`

</details>

<details>
<summary>

## macOS
</summary>

[proxyfor-ca-cert.pem](http://proxyfor.local/proxyfor-ca-cert.pem)

### Manual Installation

1.  Double-click the PEM file to open the Keychain Access application.
2.  Locate the new certificate "proxyfor" in the list and double-click it.
3.  Change Secure Socket Layer (SSL) to Always Trust.
4.  Close the dialog window and enter your password if prompted.

### Automated Installation

1.  `sudo security add-trusted-cert -d -p ssl -p basic -k /Library/Keychains/System.keychain proxyfor-ca-cert.pem`

</details>

<details>
<summary>

## iOS
</summary>

[proxyfor-ca-cert.pem](http://proxyfor.local/proxyfor-ca-cert.pem)

### iOS 13+

1.  Use Safari to download the certificate. Other browsers may not open the proper installation prompt.
2.  Install the new Profile (Settings -> General -> VPN & Device Management).
3.  **Important: Go to Settings -> General -> About -> Certificate Trust Settings.** Toggle proxyfor to ON.

</details>

<details>
<summary>

## Android
</summary>

[proxyfor-ca-cert.cer](http://proxyfor.local/proxyfor-ca-cert.cer)

### Android 10+

1.  Open the downloaded CER file.
2.  Enter proxyfor (or anything else) as the certificate name.
3.  For credential use, select VPN and apps.
4.  Click OK.

Some Android distributions require you to install the certificate via Settings -> Security -> Advanced -> Encryption and credentials -> Install a certificate -> CA certificate (or similar) instead.

**Warning:** Apps that target Android API Level 24 (introduced in 2016) and above only accept certificates from the system trust store ([#2054](https://github.com/proxyfor/proxyfor/issues/2054)). User-added CAs are not accepted unless the application manually opts in. Except for browsers, you need to patch most apps manually ([Android network security config](https://developer.android.com/training/articles/security-config)).

Alternatively, if you have rooted the device and have Magisk installed, you can install [this Magisk module](/cert/magisk) via the Magisk Manager app.

</details>

<details>
<summary>

## Firefox
</summary>

[proxyfor-ca-cert.pem](http://proxyfor.local/proxyfor-ca-cert.pem)

### Firefox

1.  Open Options -> Privacy & Security and click View Certificates... at the bottom of the page.
2.  Click Import... and select the downloaded certificate.
3.  Enable Trust this CA to identify websites and click OK.