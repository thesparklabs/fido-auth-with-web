# Viscosity FIDO Authentication with Web Registration Example
This code is designed to act as a basic proof-of-concept for developers seeking an example of how to integrate a FIDO authenticator registered in a web browser using the WebAuthn APIs with Viscosity's FIDO/U2F authentication support.

WARNING: Do not use this server in production environments. This code is a proof-on-concept only aimed at server developers. It does not fully error check or validate data, it does not validate usernames, and it does not isolate sessions.

If you are a systems administrator seeking to enable FIDO/U2F authentication, please check out our [Two-Factor Authentication Setup Guides](https://www.sparklabs.com/support/kb/category/two-factor-authentication-setup-guides/) and [VPN Server Setup Guides](https://www.sparklabs.com/support/kb/category/vpn-server-setup-guides/) instead.

## Requirements

This code and installation steps assumes the following requirements have been met:

* You have a machine with the latest LTS version of Ubuntu LTS installed (22.04 at the time of writing)
* You have a DNS domain configured to point at your server's IP address, for example myserver.example.com
* You do not have an existing web server running on the machine (port 443 should be available)
* You have the latest beta version of Viscosity installed on your local computer. Instructions for installing beta versions [can be found here](https://www.sparklabs.com/support/kb/article/using-viscosity-beta-versions/).
* You have a FIDO token or smartcard available. This code has been tested using YubiKey tokens.

## Preparation

Before getting started you will need to set up an OpenVPN server instance on your Ubuntu server, and configure it to support FIDO/U2F authentication. First, following the [Setting up an OpenVPN server with Ubuntu and Viscosity](https://www.sparklabs.com/support/kb/article/setting-up-an-openvpn-server-with-ubuntu-and-viscosity/) guide to set up OpenVPN on your server.

Once an OpenVPN server is running, configure it to support FIDO/U2F authentication by following the [YubiKey U2F Two-Factor Authentication with OpenVPN and Viscosity](https://www.sparklabs.com/support/kb/article/yubikey-u2f-two-factor-authentication-with-openvpn-and-viscosity/) guide.

Once you have confirmed you can successfully connect and authenticate with the OpenVPN server from Viscosity, please proceed to the next section.

## Download and Install

First, install the authentication server's dependencies using the following command:
```
sudo python3 -m pip install fido2 flask requests
```

Download a copy of the code by running the following command in the terminal:
```
wget -O fidoweb.tar.gz https://api.github.com/repos/thesparklabs/fido-auth-with-web/tarball/main
tar -xvzf fidoweb.tar.gz
```

Replace the existing authentication plugin script by running the following commands:
```
cd thesparklabs-fido-auth-with-web-*
sudo cp -f plugin/auth-pam-u2f.py /usr/share/openvpn/pam-u2f/auth-pam-u2f.py
sudo chmod 755 /usr/share/openvpn/pam-u2f/auth-pam-u2f.py
```

Now edit the server.py file:
```
nano server/server.py
```

Find the following line, and replace `myserver.example.com` with the correct DNS address on your server. Save your changes.
```
serverDomain = "myserver.example.com"
```

Now start the authentication server with the following command. You will need to keep your terminal session active.
```
sudo python3 server/server.py
```

## Register your FIDO Authenticator

Using your web browser, go to `https://myserver.example.com` (replace `myserver.example.com` with the correct DNS address). You'll likely need to click through some SSL certificate warnings.

Click on the Register link, and then click the "Click here to start" button. Follow the prompts from your web browser to register your FIDO authenticator.

## Configure Viscosity

To be able to share your registration between the web browser and Viscosity you will need to make a small change to your FIDO/U2F VPN connection. In Viscosity, edit your connection, and in the advanced commands area on a new line add the command `#viscosity U2FURIScheme none` . Click Save. For more information on how to add advanced commands please see [Advanced Configuration Commands](https://www.sparklabs.com/support/kb/article/advanced-configuration-commands/).

Please note that at the time of writing only Viscosity beta versions suport the "none" option in the command above. We expect support will be available in the normal release versions by version 1.10.8 (macOS) and version 1.10.6 (Windows).

## Connect Your VPN Connection

You can now connect your VPN connection. Enter the same username/password credentials as you did when following the "YubiKey U2F Two-Factor Authentication with OpenVPN and Viscosity" guide. You should then be prompted for to connect and activate your FIDO authenticator.

If you are instantly disconnected, please check that your FIDO device has been registered via the web interface. Please also note that restarting the authentication server resets all registered devices (so you will need to re-register your device). If you receive an "FacetID validation failed for AppID" error, or your FIDO device is not found, please ensure that the "U2FURIScheme" command was added to your VPN connection.

For troubleshooting other issues, please observe the output from the server in your terminal session for any error messages or warnings.

## Support

Please note that this example code is provided as a courtesy for OpenVPN server developers wishing to add FIDO authentication support to their product. We cannot provide technical support or development assistance.

For more information about Viscosity please visit the [Viscosity website](https://www.sparklabs.com/viscosity/). For more information about SparkLabs please visit the [SparkLabs website](https://www.sparklabs.com).