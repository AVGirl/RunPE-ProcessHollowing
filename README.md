# RunPE-ProcessHollowing

Process Hollowing is a technique mainly used by Malware Creators to hide malicious code behind Legitimate Process.

This technique mainly consists of following steps:-
1) Start the remote process in Suspended State.
2) Replace the headers and sections loaded into memory with our executable's.
3) Change the Image Base and Start the thread with new Entry Point.
