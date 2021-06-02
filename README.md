# UWPDumper-lib
Fork of https://github.com/Wunkolo/UWPDumper that replaces the Injector CLI with a class interface for using UWPInjector/Dumper in other tools.


Created mainly for [DOOMdumper](https://github.com/SEWsam/DOOMDumper), the c++ rewrite of [UWP-DOOMdumper](https://github.com/SEWsam/UWP-DOOMdumper)

The purpose of creating this was to help easily automate the process of sideloading _DOOM Eternal_, for modding. Simply calling the `UWPInjector` executable from within DOOMdumper leaves room for error, such as the inability to safely determine if the game was properly dumped, which can cause incomplete installations/needing to reinstall.


## Changes
* UWPInjector main functionallity has been moved to UWPInjector class and split across appropriate member functions.
* Expands IPC to send progress and errors (Expanded MessageEntry struct and new IPC::ErrorStatus enum for errors)
* Input path now supports spaces, now that args are passed as class parameters and not cmdline args.
* The dumper thread now terminates on failure.


## Usage
Compile UWPDumper dynamic link lib, and UWPInjector static link lib.  (This was originally compiled within Visual Studio 2019)  
Link with the output `.lib`, and include the `.dll` with your executable.  

```c++
#include "UWPInjector/include/UWPInjector.hpp"
```

### Initialize Injector
```c++
UWPDumper::UWPInjector injector(0, "C:\\DUMP\\");
```

### Start Dump and Print Output
```c++
injector.DumperInject();  // This is what starts the dumper thread.

std::wstring message;
UWPDumper::DumperError error;
float progress;

while (injector.ValidThread()) {
    while (injector.PopMessage(message, error, progress) {
        std::wcout << message;
        
        if (progress != 0) {
            std::cout << "progress" << progress << "\n";
        }
        
        if (error != UWPDumper::DumperError::none) {
           std::cout << "An error!\n";
        }
        
    }
}
```
