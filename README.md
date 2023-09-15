# RDinstall

Powershell script to install/update Rustdesk for deployments for MS Windows

## Features

* Install/Update Rustdesk client as Service on MS Windows
* Create randomized permanent password
* Optional create/update credentials in [Nextcloud Passwords App](https://apps.nextcloud.com/apps/passwords)
* Script will display Rustdesk ID and password at the end

## Parameters

* `rdServer`
  * Type: Optional
  * Description: Use for self hosted [Rustdesk Server](https://github.com/rustdesk/rustdesk-server)
  * Default: `rs-ny.rustdesk.com`
* `rdKey`
  * Type: Required if `rdServer` is set to none default value
  * Description: Contents of `id_ed25519.pub` from self hosted Rustdesk Server
  * Default: `$null`
* `pwLength`
  * Type: Optional
  * Description: Integer to define length for random password created during installation
  * Default: `8`
* `enableAudio`
  * Type: Optional
  * Description: Boolean to enable or disable audio for Rustdesk connections
  * Default: `$True`
* `toNextcloudPassword`
  * Type: Optional
  * Description: Boolean to enable create/update passwords in [Nextcloud Passwords App](https://apps.nextcloud.com/apps/passwords)
  * Default: `$False`
* `ncBaseUrl`
  * Type: Required if `toNextcloudPassword` is set to `$True`
  * Description: Base URL/URI to Nextcloud Password app (e.g. https://some.nextcloud.tld/apps/passwords)
  * Default: none
* `ncUsername`
  * Type: Required if `toNextcloudPassword` is set to `$True`
  * Description: Nextcloud username
  * Default: none
* `ncToken`
  * Type: Required if `toNextcloudPassword` is set to `$True`
  * Description: Token created in personal settings -> security (/settings/user/security)
  * Default: none
* `ncFolder`
  * Type: Required if `toNextcloudPassword` is set to `$True`
  * Description: Folder UUID where Rustdesk credentials will be searched, created or updated at. You can get the folder UUID from the URL of your browser (e.g. https://some.nextcloud.tld/apps/passwords/#/folders/ed7a91e1-a264-4806-8e0a-cdf8896cb5d8)
  * Default: none

## Examples

### Install Rustdesk

#### Example 1:

Install Rustdesk client pointing to self hosted Rustdesk Server, without any Nextcloud Passwords App integration, password length set to 12 characters and disabled audio

```
powershell -ExecutionPolicy ByPass .\rustdeskinstall.ps1 -rdServer my.self-hosted-rustdesk-server.tld -rdKey PublicKeyFromRustdeskServer -pwLength 12 -enableAudio 0
```

#### Example 2:

Install Rustdesk client pointing to self hosted Rustdesk Server and send credentials to Nextcloud Passwords App

```
powershell -ExecutionPolicy ByPass .\rustdeskinstall.ps1 -rdServer my.self-hosted-rustdesk-server.tld -rdKey PublicKeyFromRustdeskServer -toNextcloudPassword 1 -ncBaseUrl https://some.nextcloud.tld/apps/passwords -ncUsername user.name -ncToken 12345-kkkkk-d8d8b-b5b5b-ddddd -ncFolder ed7a91e1-a264-4806-8e0a-cdf8896cb5d8

```

## Notes

PRs welcome