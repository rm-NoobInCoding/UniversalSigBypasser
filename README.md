# Unreal Engine Signature Bypasser

A simple dll designed to hook and bypass the signature check function in Unreal Engine-based games, enabling modding and custom pak/utoc/ucas files in Paks folder. This bypasser is inspired by and based upon the [Lua script](https://gist.github.com/Buckminsterfullerene02/90077ce81c0fd908144498869f4ea288) originally created by LongerWarrior.

## Installation

1. Download the latest release from the Release section.
2. Extract the zip on the [Releases](https://github.com/rm-NoobInCoding/UniversalSigBypasser/releases) page into your game's Win64 directory (usually found in the `GAMENAME/Binaries/Win64` path).

> [!TIP]
> I used dsound.dll to load the bypasser dll. You can use any other asi loader you want instead of dsound, just remove the dsound.dll and grab a x64 asi loader from [here](https://github.com/ThirteenAG/Ultimate-ASI-Loader) then paste it in the same folder as bypasser.

You're all set! Launch your game normally, and the signature checks will be automatically bypassed.

## Tested Games
* Eriksholm: The Stolen Dream (NoobInCoding)
* Wuchang: Fallen Feathers (NoobInCoding)
* Dying Island 2 (NoobInCoding)
* Coral Island (hikarosato)
* Kao the Kangaroo (hikarosato)
* Luto (Bahasnyldz)
* Drive Beyond Horizons (Indra881)

If you tested this hook on any games and it worked, just leave a comment [in this issue](https://github.com/rm-NoobInCoding/UniversalSigBypasser/issues/2) and I will add its name in here.

## License

This work is licensed under a [Creative Commons Attribution-NonCommercial 4.0 International License](https://creativecommons.org/licenses/by-nc/4.0/).

## Credits

Special thanks to LongerWarrior for the original Lua-based implementation.

### Happy modding!
