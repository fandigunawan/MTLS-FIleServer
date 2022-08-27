# Idnaf Mutual Authentication File Server
Idnaf Mutual Authentication File Server serves as file server with client side authentication. There are several design requirements:
1. Mutual authentication HTTPS 
2. Access file or directory based on certificate's organization
3. Users within an organization could access organization's directories and files

## How to
1. Create CA
2. Create users certificate within organization that is signed by CA
3. Create organization directory

## Example
```
     CA
      +
      |
      +
 Org=TestOrg
      |
 +----+----+
User1    User2
```
You will need to create a directory in executable directory named "TestOrg". The "TestOrg" is accessible by user "User1" and "User2"

## Parameters
```
-cafile   : CA file in PEM format (Mandatory)
-certfile : Cert file in PEM format (Mandatory)
-keyfile  : Private key file in PEM format (Mandatory)
-listen   : Listen port default :8443 (Optional)
```