# hacktiv8 

hacktiv8(formerly A5_Bypass_OSS) is an open-source research project focused on analyzing and experimenting with the iOS activation process. It provides a one-click cross-platform solution for bypassing activation on legacy iOS devices without the need of pwning DFU.

## Disclaimer

This project is intended strictly for research and educational purposes.  
It is not designed for, and must not be used in, production environments or for unlawful activities.  
The authors and contributors take no responsibility for any misuse or damage caused to devices, data, or systems.

## Requirements

Python 3.11 is used by the project build workflow.

For the `itunesstored` exploit (iOS 9 - 10), both the host and target devices must be connected to Wi-Fi at all times during operation.  
Jailbroken devices works fully offline over USB, but requires a jailbroken target.

## Run from Source

On macOS or Linux:

```sh
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

On Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

Connect the device by USB. Review the app's change summary before continuing. The app needs network access for supported-build checks and the `itunesstored` backend.

## Compatibility

- iOS 9.0 - 10.3.4, not jailbroken
- iOS 8.0 - 8.4.1, not jailbroken (Wi-Fi-only devices)
- iOS 4.0 - 8.4.1, jailbroken

## Backend Configuration

The backend URL can be configured via Settings dialog. When left empty, the defaults from [`exploits/itunesstored/itunesstored.py`](exploits/itunesstored/itunesstored.py#L13) are used.

Due to legacy iOS devices lacking trust for modern certificate authorities, the backend must either use HTTP, or serve an SSL certificate that chains to a root CA trusted by legacy iOS. Modern certificate authorities such as Let's Encrypt are not trusted on legacy iOS versions and will cause HTTPS connections to fail on target devices.

## Scope and Device Changes

Support is limited to the model/build profiles present in the backend. A matching iOS version alone does not mean that every device is supported.

This project changes activation-related state on legacy devices. It does not recover an Apple Account or remove an Activation Lock association from Apple's servers. Use Apple Account recovery or Apple Support for an Activation Lock screen.

The `itunesstored` method replaces only `Downloads/downloads.28.sqlitedb`; other files in `Downloads` are left in place. The SFTP method modifies activation-related files, keeps the original MobileGestalt plist beside the cache as `.hacktiv8.orig` or keeps `/usr/libexec/lockdownd.orig`, and reboots the device. It verifies the backup and patched file and refuses to overwrite an existing backup. On some cellular iOS 8 devices, it disables `CommCenter`, which can interrupt cellular service.

The default backend uses HTTP, which does not authenticate or encrypt its responses. Prefer a trusted HTTPS backend when the target device supports its certificate chain. If HTTP is required for a legacy device, use a trusted network and backend.

## Credits
- [pkkf5673](https://github.com/bablaerrr)
- [bl_sbx](https://github.com/hanakim3945/bl_sbx)
- [pymobiledevice3](https://github.com/doronz88/pymobiledevice3)

## License

Refer to the repository license file for licensing details.
