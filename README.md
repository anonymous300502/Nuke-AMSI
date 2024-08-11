# Nuke-AMSI
 NukeAMSI is a powerful tool designed to neutralize the Antimalware Scan Interface (AMSI) in Windows environments. Developed for educational purposes, this script enables users to disable AMSI protections within the current PowerShell session, allowing for the execution of scripts that would typically be flagged or blocked by Windows Defender and other antivirus solutions.

### Key Features

- *Direct Memory Manipulation*: NukeAMSI utilizes direct memory manipulation techniques to disable AMSI, leveraging the ntdll library and other critical Windows APIs. This ensures that AMSI is effectively bypassed without raising alerts or triggering additional security measures.
  
- *Stealth Operations*: The tool operates in-memory, meaning it leaves no trace on disk. This makes it particularly useful in scenarios where maintaining operational security is paramount.
  
- *Highly Effective Bypass*: Unlike traditional AMSI bypass techniques that may involve patching specific functions, NukeAMSI attacks AMSI at a deeper level. By leveraging ntdll, it targets the heart of AMSI's detection mechanisms, ensuring a higher success rate even against updated antivirus engines.

### Technical Breakdown

NukeAMSI uses several advanced techniques to achieve its goals:

- *Process Injection*: By injecting code into the memory space of the PowerShell process, NukeAMSI can alter the behavior of critical security functions.
  
- *Utilization of NTDLL*: The script makes use of ntdll, a core Windows library, to access low-level system functions. This allows NukeAMSI to manipulate the system's memory directly, making its operations more effective and harder to detect.
  
- *Advanced Error Handling*: NukeAMSI includes robust error handling to ensure smooth operation even in complex environments. It carefully checks for and handles potential failures, reducing the likelihood of detection or script failure.

### Why NukeAMSI Outperforms Traditional Methods

While traditional AMSI bypass techniques often rely on patching or manipulating specific AMSI-related functions, these methods are increasingly ineffective as antivirus software evolves. NukeAMSI takes a more sophisticated approach, targeting AMSI at the root level via direct memory access. This not only makes the bypass more reliable but also significantly reduces the chances of detection.

### Usage and Disclaimer

*Note: This tool is intended for **educational purposes only*. It should be used responsibly and in compliance with all relevant laws and regulations. Unaut
horized use of this tool on systems you do not own or have explicit permission to test can result in severe legal consequences.

First lets try running mimikatz in our powershell shell 
![mimikatz amsi trigger](https://github.com/user-attachments/assets/0003e944-34a8-477f-b900-fc6b67a3041f)
SO as we can see amsi Triggered, now lets run our tool 
You will be prompted to confirm your intent before the script proceeds to neutralize AMSI within the session.
![Running nukeamsi](https://github.com/user-attachments/assets/ce380592-5b7f-4521-ac55-3b503eb1c62d)

Now we can run mimikatz without worrying about windows defender bothering us
![nukeamsi2](https://github.com/user-attachments/assets/8bff87d5-797b-4a53-89ad-4a7978ec6833)

### Conclusion

NukeAMSI represents the cutting edge of AMSI bypass techniques, offering a powerful, reliable, and stealthy solution for professionals who need to execute scripts in environments where AMSI is active. Whether you're conducting penetration testing, research, or learning more about Windows security internals, NukeAMSI provides the tools you need to operate effectively and securely.



