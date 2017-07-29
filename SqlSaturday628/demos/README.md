DatabaseReporter Example Modules (AdventureWorks Product)
---------------------------------------------------------
These files are meant to be opened and looked at in order. The first one starts with a very simple command, and each iteration of the module extends the functionality in some way.

To use the commands defined in the modules, follow these steps:
1. Ensure all files are in the same folder. The DatabaseReporter.ps1 file MUST be present in the same folder as each of the .psm1 files
2. Choose a module to examine and import. Open the module to read the code and comments, and then use Import-Module to use it:

   ```
   Import-Module .\01_SimpleModule.psm1
   Get-AwProduct
   ```
3. When you're finished with a module and ready to move on, remove the one you just looked at:

   ```
   Remove-Module 01_SimpleModule
   ```