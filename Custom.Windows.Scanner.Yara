name: CPIRT.Windows.Scanner.Yara.Parsed
description: |
    Instructions: Upload compiled yara signature file (signature file must be named yara.yas) 
    and yara64.exe in a single zip file called yara.zip
    
    This artifact will drop the yara.zip file onto the client in a temporary directory, 
    iterate through every running process and scan the process with a given yara signature, 
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
   
 - name: ThreadLimit
   description: "How many threads to utilise?"
   type: string
   default: "2"
    
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
        
        -- Scan with Yara File
        LET Execute <= SELECT * FROM if (condition=ScanType, then={SELECT * FROM  foreach(row=processes,
        query={
            SELECT Name, Pid, Ppid, Stdout FROM execve(argv=[YaraExe, "-C", YaraFile, Pid, "-p", ThreadLimit])
        })},
        
        else = { 
        SELECT Stdout FROM execve(argv=[YaraExe, "-C", YaraFile, "-r",  "C:\\", "-g", "-p", ThreadLimit])})
        
        --Read Data
        LET Query = SELECT Stdout FROM Execute
        
        LET ParseLines = SELECT * FROM parse_lines(filename=Query.Stdout, accessor="data")
        
        LET YaraGrok = "%{WORD:category} \\[\\] %{GREEDYDATA:file_path}"
        
        LET ParsedData = SELECT grok(grok=YaraGrok, data=Line) AS Parsed FROM ParseLines
        
        SELECT Parsed.category AS Category, Parsed.file_path AS `File Path` FROM ParsedData
