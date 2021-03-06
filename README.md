# OSCP_Scripts
The following repo includes scripts I created to assist with automating some tasks for the OSCP v2.0 exam.
All of my scripts were made in bash.
I will not be maintaining this repo.

## my_notes/cheat-sheet.md
This is not a script, but all of my notes I took for the OSCP test. This file is huge. However it includes a lot of good examples for commands.
Note: there are probably lots of spelling mistakes in this file, sorry ahead of time. 
use this .md file in the following way:

- Search for a binary or a command, use the examples I share if you like.

## BadCharChecker
Dependencies: none

BadCharChecker is used for BOF attacks when using Imunity Debugger on Windows exploits.
Its purpose is to find bad characters from an ESP dump. To use do the following.
When you ready to check for bad characters in your stack buffer overflow attack, 
use this tool in the following way:

- Adjust your POC code to send a string of all bad chars (recommend sending after a string of A's (\x41) so its easier to find in the ESP dump.)
- Run the vulnerable binary. Attach to Immunity Debugger.
- Run your POC code to send A's + Bad Characters string.
- Inside Immunity Debugger: Dump ESP 
- Copy Immunity Debugger ESP Hex dump output. Only copy characters that Need to be checked. 
  Note: Take a look in example_files/bc01, if you want to see what copy of Immunity Debugger ESP dump looks like
- Paste into a file on Kali (Example: bc01).
    > BadCharChecker bc01
- BadCharChecker will display some information.
    - User identified bad chars: These are the chars you passed in via $2
    - Chars missing from AllChars & User identified bad chars: Bad chars found not identified by user input. 
      This will display "None! :)" if there are none. This means you identified all BadChars list is good.
    - Chars missing form AllChars: Exact chars missing from all chars, these are considered the actual bad chars. 
- Update your POC code to remove bad chars.
- Repeat until BadCharChecker finds all Bad chars.

## LEC (Little Endian Converter)
Dependencies: none

LEC is used for BOF attacks when using ImmunityDebugger on Windows exploits.
Its purpose is to be used when you want to convert a registry address to Little endian format.
I mainly used this after I ran `!mona find -s "\xff\xe4" -m "dependencyfoundname.exe"`. I would
then copy any addresses that appear in Immunity Debugger to my clipboard, and run them against LEC.
LEC will convert the registry location to Little Endian and output in C and python syntax.
Use this tool in the following way:

- Copy a registry location address from Immunity Debugger to your clipboard
    > LEC 81356039
- Copy output to your code as needed.

## HTTP
Dependencies: python

HTTP is just a wrapper over the python simpleHTTPServer. I created this because, I didn't like having to type out "python -m SimpleHTTPServer 1234" over and over again.
Also I wanted something that would list all files recursively as URL paths, so I can copy them quickly.
Use this tool in the following way:
- cd to the directory you want to share. WARNING: It is recommended to share a directory with not many sub directories.
- perform a "ip -br addr show" to find the IP address of the interface you want to share on.
- choose a port (Example: 1234)
    > HTTP 192.168.5.22 1234
- HTTP will list all files in a url path form and run the python simple server.

This tool works great in combination with tmux search. Try the following after running HTTP and have output:
- Enter tmux copy mode 
    - Default: "CTRL+B" then press "["
- Search up
    - Default: "SHIFT+n" then type the word your looking for and press "ENTER". 
- Copy the URL path you found.

## webgrabber
Dependencies: cutycapt, jq(for ffuf json files), firefox (by default this is the browser configured to open files)

webgrabber is a wrapper around cutycapt. You MUST have cutycapt installed and in your path for webgrabber to work. 
The purpose of webgrabber is to quickly iterate though a directory buster output file, go to each url's web interface,
take a picture of what it looks like, append it to a HTML file, and open in firefox. The web page will include
The link, image location, the image. This works with HTTP and HTTPS, however I have had more sucess with HTTP. 

Supported dir busters / file format:
- gobuster (use gobuster's "-o" parameter to create a file of results)
- feroxbuster (use feroxbuster's "-o" parameter to create a file of results)
- ffuf (use ffuf's "-o" parameter, and specify format with "-of". Note: jq is required for json formatted files)

Use this tool in the following way:
- Perform a web directory enumeration with gobuster, feroxbuster, or ffuf, make sure to create an output file with one of the above supported methods
- run webgrabber, here are some examples.
    > webgrabber -s http://10.10.10.10 -f <gobusterfile> -e gb"

    > webgrabber -s https://10.10.10.10 -f <gobusterfile> -e gb"

    > webgrabber -s http://10.10.10.10:8080 -f <feroxbusterfile> -e fb"

    > webgrabber -s https://10.10.10.10:4443 -f <ffuf csv file> -e ff"

## lsc (ls cat)
Dependencies: none

lsc or "ls cat" will perform a ls, but include file names as a title. 
The purpose of this binary was I didn't like how `ls *` opened all files but it was hard to delineate between 
where one file started and one file ended. By default lsc will output all files recursivly in the directory its run from.
If you want to filter on your search with globbing, put your search in quotes
Use this tool in the following way:
- Go to the directory you want to view all file contents in stdout.
    > lsc
- or if you want to filter use
    > lsc "*.config"

## pulllinks
Dependencies: none

pulllinks is a quick way to to filter out the HTML for a page to show all links and comments found on a page. 
The purpose of this script was to copy the HTML source form a specific page, paste into a file (Example: index.html)
then run pulllinks against it. This will show all the links for hrefs, src, onclick, and path references. 
I made this because I ran into a box once that had a link that was hidden. 
By default it does some filtering to just show the links (best effort), you can run "nofilter" as $1 and the extracted links
in their entirety will be displayed.
Use this tool in the following way:
- Go to a web interface you want to search for links.
- view the page source.
- Copy all to clipboard
- Paste into a file (Example: index.html)
    > pulllinks index.html
    - or to remove filtering
    > pulllinks index.html nofilter

## ldapgatherer
Dependences: ldapsearch

ldapgather will pull a bunch of ldap information from a system using ldapsearch. 
The purpose of this script was mainly to gather user account "comments" to see if passwords were in there.
However I expanded it to do much more. Forgive how verbose the code is, I just didn't have time to clean it up.
Use this tool in the following way.
- To log into a ldap server with no credentials and run ldapgatherer
    > ldapgatherer -u '' -p '' -s 10.10.10.161 -d htb.local"
    or
    > ldapgatherer -s 10.10.10.161 -d htb.local"
- If you want to use creds:
    > ldapgatherer -u 'domain\username' -p 'MyCoolPassword' -s 10.10.10.161 -d htb.local"

## tnas (Tmux Nmap Automation Script)
Dependences: tmux, nmap

tnas (pronaounced "T","NAS") utilizes tmux window panes to send your most common nmap scripts to seperate panes on the same window.
tmux offers a way to send commands to seperate windows, however the syntax is long. I made this script to send the 
most common nmap scans I use to seperate tmux panes. That way I can monitor all of the nmap scans running at once.
By default tnas has the nmap scans I used built into the end of the script, you will need to adjust accordingly if you want to use different scans.
Use the tool in the following way.
- Open at least 4 panes.
- Perform a "CTRL+B" "Q" to identify each pane's numeric value. 
- Run tnas against a host ip, and specify which panes to send each command
    > tnas 10.10.10.10 1,2,4,5
- You will need to type in the sudo password in each pane
By default tnas uses these nmap scans:
    `- sudo nmap -p- -sV -vv -oN _nmap_tcp_quick 10.10.10.10
    `- sudo nmap -sC -sV -p- -vv -oN _nmap_tcp_full 10.10.10.10
    `- sudo nmap -sU --top-ports 1000 -oN _nmap_udp_1000 10.10.10.10
    `- sudo nmap -O --osscan-guess -oN _nmap_os 10.10.10.10
