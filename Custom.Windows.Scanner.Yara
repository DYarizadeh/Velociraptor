name: CPIRT.Windows.Scanner.Yara
description: |
    Instructions: Upload compiled yara signature file (signature file must be named yara.yas) 
    and yara64.exe in a single zip file called yara.zip
    
    This artifact will drop the yara.zip file onto the client in a temporary directory, 
    iterate through every running process or file in C: and can with the provided compiled signature base,
    and then finally delete the temporary file. 
    
    
    
    
    
author: Chris Jones + Dennis Yarizadeh



tools:
  - name: yaraexecutable
    url: https://github.com/VirusTotal/yara/releases/download/v4.3.2/yara-4.3.2-2150-win64.zip
    
parameters:
 - name: ScanType
   description: "Are we scanning Processes?"
   type: bool
   default: Y

    
sources:
  - query: |

        LET processes = SELECT * FROM pslist()
        
        LET TmpDir <= tempdir()

        LET YaraExePath <= SELECT FullPath FROM Artifact.Generic.Utils.FetchBinary(ToolName="yaraexecutable", IsExecutable=FALSE, TemporaryOnly=TRUE)

        
        LET FetchYara <= SELECT * FROM unzip(filename=YaraExePath.FullPath, output_directory=TmpDir)

        -- Set EXE
        LET YaraExe <= TmpDir + '\\yara64.exe'

        -- Set Yara file
        Let YaraFile <= TmpDir + '\\yara.yas'

        
        SELECT * FROM 
        
        if (condition=ScanType, 
        then={
        SELECT * FROM 
        foreach(
            row=processes,
        query={
            SELECT Name, Pid, Ppid, Stdout FROM execve(argv=[YaraExe, "-C", YaraFile, Pid])
        })},
        
        else = { 
        SELECT * FROM execve(argv=[YaraExe, "-C", YaraFile, "-r", "C:"])
             }
        )

        
        
