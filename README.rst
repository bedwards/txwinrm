txwinrm: Async Python WinRM Client
==================================

At Zenoss we are working on a project to improve the reliability, performance
and features of native Windows monitoring. The core of this project is this
Python library for asynchronously managing Windows using the WinRM and WinRS
services. This library will then be used by Zenoss to do automatic discovery
and monitoring the way Zenoss users are used to with some new possibilities.

Right now we're trying to get as much real world experience using the library
as possible to prove out the reliability and performance improvements we're
hoping to achieve. If you have access to Windows servers, you can help! This
tool no longer stands alone.  You must install kerberos.so from the Windows
ZenPack, https://github.com/zenoss/ZenPacks.zenoss.Microsoft.Windows/tree/develop/ZenPacks/zenoss/Microsoft/Windows/lib.
The source for this version of pykerberos can be found here:
https://github.com/zenoss/ZenPacks.zenoss.Microsoft.Windows/tree/develop/src/pykerberos

See the zenoss-windows forum for updates to the project, and leave your
feedback there. 

http://community.zenoss.org/community/forums/zenoss-windows


Installation
------------

Ubuntu Server 12.04.1 LTS (Python 2.7.3)

::

    sudo apt-get update

    sudo apt-get -y install gcc python-dev libkrb5-dev krb5-user python-setuptools
    # if prompted for your kerberos realm, leave it blank and choose OK

    sudo easy_install txwinrm

    # if you want to use a Windows domain
    sudo genkrb5conf <windows domain> <domain controller IP address>

    # now you can run the txwinrm commands (winrm, winrs, typeperf, and wecutil)
 
 
Centos 6.3 x86_64 (Python 2.6.6)

::
 
    # as root
    yum -y install gcc python-devel krb5-devel krb5-workstation python-setuptools
    easy_install txwinrm
     
    # if you want to use a Windows domain
    genkrb5conf <windows domain> <domain controller IP address>
     
    # now you can run the txwinrm commands (winrm, winrs, typeperf, and wecutil) as a normal user


Zenoss Core or Resource Manager 4.2.x installed on CentOS 6 (Zenoss Python 2.7)

::

    # as root
    yum -y install gcc krb5-devel krb5-workstation

    # as the zenoss user
    easy_install txwinrm

    # as root (if you want to use a Windows domain)
    genkrb5conf <windows domain> <domain controller IP address>

    # now you can run the txwinrm commands (winrm, winrs, typeperf, and wecutil) as the zenoss user


Current Feature Support
-----------------------

-  HTTP
-  HTTPS
-  Basic authentication
-  WQL queries
-  WinRS
-  typeperf
-  Subscribe to the Windows Event Log
-  Kerberos authentication (domain accounts)
-  Single session clients
-  WMI Associators queries


Configuring the Target Windows Machines
---------------------------------------

You can enable the WinRM service on Windows Server 2003, 2008, 2012, and 2016. Run
Command Prompt as Administrator and execute the following commands for basic authentication.

::

    winrm quickconfig
    winrm s winrm/config/service '@{AllowUnencrypted="true";MaxConcurrentOperationsPerUser="4294967295"}'
    winrm s winrm/config/service/auth '@{Basic="true"}'
    winrm s winrm/config/winrs '@{MaxShellsPerUser="2147483647"}'

If using domain authentication, run the following commands.

::

    winrm quickconfig
    winrm s winrm/config/service '@{MaxConcurrentOperationsPerUser="4294967295"}'
    winrm s winrm/config/service/auth '@{Kerberos="true"}'
    winrm s winrm/config/winrs '@{MaxShellsPerUser="2147483647"}'


WQL Queries
-----------

You can pass a single host a query via the command line...

::

    $ winrm -r host -u user -p password -f "select * from Win32_NetworkAdapter"


Another option is to create an ini-style config file and hit multiple targets
with multiple queries. Example config is at `examples/config.ini <https://raw.github.com/zenoss/txwinrm/master/examples/config.ini>`_

::

    $ winrm -c path/to/config.ini


This will send WinRM enumerate requests to the hosts listed in config.ini. It
will send a request for each WQL query listed in that file. The output will
look like

::

    <hostname> ==> <WQL query>
        <property-name> = <value>
        ...
        ---- (indicates start of next item)
        <property-name> = <value>
        ...
    ...


Here is an example...

::

    cupertino ==> Select name,caption,pathName,serviceType,startMode,startName,state From Win32_Service
      Caption = Application Experience
      Name = AeLookupSvc
      PathName = C:\Windows\system32\svchost.exe -k netsvcs
      ServiceType = Share Process
      StartMode = Manual
      StartName = localSystem
      State = Stopped
      ----
      Caption = Application Layer Gateway Service
      Name = ALG
    ...


A summary of the number of failures if any and number of XML elements processed
appears at the end. The summary and any errors are written to stderr, so
redirect stdin to /dev/null if you want terse output.

::

    $ winrm -c path/to/config.ini >/dev/null

    Summary:
      Connected to 3 of 3 hosts
      Processed 13975 elements
      Failed to process 0 responses
      Peak virtual memory useage: 529060 kB

      Remote CPU utilization:
        campbell
          0.00% of CPU time used by WmiPrvSE process with pid 1544
          4.00% of CPU time used by WmiPrvSE#1 process with pid 1684
          4.00% of CPU time used by WmiPrvSE#2 process with pid 3048
        cupertino
          0.00% of CPU time used by WmiPrvSE process with pid 1608
          3.12% of CPU time used by WmiPrvSE#1 process with pid 1764
          9.38% of CPU time used by WmiPrvSE#2 process with pid 2608
        gilroy
          1.08% of CPU time used by WmiPrvSE process with pid 1428
          5.38% of CPU time used by WmiPrvSE#1 process with pid 1760
          4.30% of CPU time used by WmiPrvSE#2 process with pid 1268


The '-a' option specifies the authentication method. Currently supported values
are 'basic' and 'kerberos'. 'basic' is the default.

The '-d' option increases logging, printing out the XML for all requests and
responses, along with the HTTP status code.

The '-e' option specifies which service principal to use on the Windows host.  Valid
values are 'http', 'https', and 'wsman'.

::

    usage: winrm.py [-h] [--debug] [--config CONFIG] [--remote REMOTE]
                    [--authentication {basic,kerberos}] [--username USERNAME]
                    [--dcip DCIP] [--keytab KEYTAB] [--password PASSWORD]
                    [--ipaddress IPADDRESS] [--service SERVICE]
                    [--includedir INCLUDEDIR] [--filter FILTER]

    optional arguments:
      -h, --help            show this help message and exit
      --debug, -d
      --config CONFIG, -c CONFIG
      --remote REMOTE, -r REMOTE
                            hostname
      --authentication {basic,kerberos}, -a {basic,kerberos}
      --username USERNAME, -u USERNAME
      --dcip DCIP, -i DCIP  address of kdc
      --keytab KEYTAB, -k KEYTAB
      --password PASSWORD, -p PASSWORD
      --ipaddress IPADDRESS, -s IPADDRESS
      --service SERVICE, -e SERVICE
                            http/https/wsman
      --includedir INCLUDEDIR
                            valid includedir
      --filter FILTER, -f FILTER


WinRS
-----

The winrs program has four modes of operation:

-  interactive (default): Execute many commands in an interactive command
   prompt on the remote host.  PowerShell will not work in this mode.
-  single: Execute a single command and return its output
-  long: Execute a single long-running command like
   'typeperf -si 1' and check the output periodically
-  batch: Opens a command prompt on the remote system and
   executes a list of commands (actually right now it executes one
   command twice as a proof-of-concept)
-  powershell: Run a powershell script.  This is NOT interactive.
   Only enter the script here, not the powershell command.


An example of interactive mode

::

    $ winrs interactive -u Administrator -r oakland
    Microsoft Windows [Version 6.2.9200]
    (c) 2012 Microsoft Corporation. All rights reserved.
    C:\Users\Default>dir
    Volume in drive C has no label.
    Volume Serial Number is 5E71-6BA3
    Directory of C:\Users\Default
    02/22/2013  03:42 AM    <DIR>          Contacts
    02/22/2013  03:42 AM    <DIR>          Desktop
    02/22/2013  03:42 AM    <DIR>          Documents
    02/22/2013  03:42 AM    <DIR>          Downloads
    02/22/2013  03:42 AM    <DIR>          Favorites
    02/22/2013  03:42 AM    <DIR>          Links
    02/22/2013  03:42 AM    <DIR>          Music
    02/22/2013  03:42 AM    <DIR>          Pictures
    02/22/2013  03:42 AM    <DIR>          Saved Games
    02/22/2013  03:42 AM    <DIR>          Searches
    02/22/2013  03:42 AM    <DIR>          Videos
    0 File(s)              0 bytes
    11 Dir(s)   7,905,038,336 bytes free

    C:\Users\Default>exit


An example of single mode

::

    $ winrs single -u Administrator -x 'typeperf "\Memory\Pages/sec" "\PhysicalDisk(_Total)\Avg. Disk Queue Length" "\Processor(_Total)\% Processor Time" -sc 1' -r oakland
    {'exit_code': 0,
     'stderr': [],
     'stdout': ['"(PDH-CSV 4.0)","\\\\AMAZONA-SDFU7B1\\Memory\\Pages/sec","\\\\AMAZONA-SDFU7B1\\PhysicalDisk(_Total)\\Avg. Disk Queue Length","\\\\AMAZONA-SDFU7B1\\Processor(_Total)\\% Processor Time"',
                '"04/19/2013 21:43:48.823","0.000000","0.000000","0.005660"',
                'Exiting, please wait...',
                'The command completed successfully.']}


An example of long mode

::

    $ winrs long -u Administrator -x 'typeperf "\Memory\Pages/sec" "\PhysicalDisk(_Total)\Avg. Disk Queue Length" "\Processor(_Total)\% Processor Time" -si 1' -r oakland
      "(PDH-CSV 4.0)","\\AMAZONA-SDFU7B1\Memory\Pages/sec","\\AMAZONA-SDFU7B1\PhysicalDisk(_Total)\Avg. Disk Queue Length","\\AMAZONA-SDFU7B1\Processor(_Total)\% Processor Time"
      "04/19/2013 21:43:10.603","0.000000","0.000000","18.462005"
      "04/19/2013 21:43:11.617","0.000000","0.000000","0.000464"
      "04/19/2013 21:43:12.631","0.000000","0.000000","1.538423"
      "04/19/2013 21:43:13.645","0.000000","0.000000","0.000197"


An example of batch

::

    $ winrs batch -u Administrator -x 'typeperf "\Memory\Pages/sec" "\PhysicalDisk(_Total)\Avg. Disk Queue Length" "\Processor(_Total)\% Processor Time" -sc 1' -r oakland
    Creating shell on oakland.

    Sending to oakland:
      typeperf "\Memory\Pages/sec" "\PhysicalDisk(_Total)\Avg. Disk Queue Length" "\Processor(_Total)\% Processor Time" -sc 1

    Received from oakland:
      "(PDH-CSV 4.0)","\\AMAZONA-SDFU7B1\Memory\Pages/sec","\\AMAZONA-SDFU7B1\PhysicalDisk(_Total)\Avg. Disk Queue Length","\\AMAZONA-SDFU7B1\Processor(_Total)\% Processor Time"
      "04/19/2013 21:43:39.198","0.000000","0.000000","0.000483"
      Exiting, please wait...
      The command completed successfully.

    Sending to oakland:
      typeperf "\Memory\Pages/sec" "\PhysicalDisk(_Total)\Avg. Disk Queue Length" "\Processor(_Total)\% Processor Time" -sc 1

    Received from oakland:
      "(PDH-CSV 4.0)","\\AMAZONA-SDFU7B1\Memory\Pages/sec","\\AMAZONA-SDFU7B1\PhysicalDisk(_Total)\Avg. Disk Queue Length","\\AMAZONA-SDFU7B1\Processor(_Total)\% Processor Time"
      "04/19/2013 21:43:41.054","0.000000","0.000000","0.000700"
      Exiting, please wait...
      The command completed successfully.

    Deleted shell on oakland.

    Exit code of shell on oakland: 0


An example of powershell

::

  $ winrs powershell -u Administrator -r 10.10.10.10 -x "get-counter -counter '\Memory\Pages/sec'"
    Timestamp                 CounterSamples
    ---------                 --------------
    12/19/2017 11:54:27 AM    \\myserver\memory\pages/sec :
    0

Be sure not to include newlines in your powershell script as it is sent to a
Windows command line (cmd.exe).  The command line character length is capped
at 8192.  The powershell command is 55 characters, which leaves 8137 for your
script.  This mode is effectively the same as:

::
  $ winrs single -u Administrator -r 10.10.10.10 -x "powershell -NoLogo -NonInteractive -NoProfile -Command \"get-counter -counter '\Memory\Pages/sec'\" "


Usage

::

    usage: winrs.py [-h] [--debug] [--config CONFIG] [--remote REMOTE]
                    [--authentication {basic,kerberos}] [--username USERNAME]
                    [--dcip DCIP] [--keytab KEYTAB] [--password PASSWORD]
                    [--ipaddress IPADDRESS] [--service SERVICE]
                    [--includedir INCLUDEDIR] [--command COMMAND]
                    [{interactive,single,batch,long,multiple,powershell}]

    positional arguments:
      {interactive,single,batch,long,multiple,powershell}

    optional arguments:
      -h, --help            show this help message and exit
      --debug, -d
      --config CONFIG, -c CONFIG
      --remote REMOTE, -r REMOTE
                            hostname
      --authentication {basic,kerberos}, -a {basic,kerberos}
      --username USERNAME, -u USERNAME
      --dcip DCIP, -i DCIP  address of kdc
      --keytab KEYTAB, -k KEYTAB
      --password PASSWORD, -p PASSWORD
      --ipaddress IPADDRESS, -s IPADDRESS
      --service SERVICE, -e SERVICE
                            http/https/wsman
      --includedir INCLUDEDIR
                            valid includedir
      --command COMMAND, -x COMMAND

Typeperf
--------

txwinrm's typeperf command allows you to run a remote typeperf command, check
the output periodically, parse it, and print it to stdout. It support the -si
option and multiple counters. Here is an example:

::

    $ typeperf -r gilroy -u Administrator '\Processor(_Total)\% Processor Time' '\memory\Available Bytes' '\paging file(_Total)\% Usage'
    \memory\Available Bytes
      00:54:27: 193130496.0
    \paging file(_Total)\% Usage
      00:54:27: 0.012207
    \Processor(_Total)\% Processor Time
      00:54:27: 0.004487
    \memory\Available Bytes
      00:54:28: 193216512.0
      00:54:29: 193982464.0
    \paging file(_Total)\% Usage
      00:54:28: 0.012207
      00:54:29: 0.012207
    \Processor(_Total)\% Processor Time
      00:54:28: 1.542879
      00:54:29: 0.004487
    \memory\Available Bytes
      00:54:30: 193933312.0
      00:54:31: 193941504.0
    \paging file(_Total)\% Usage
      00:54:30: 0.012207


Subscribing to the Windows Event Log
------------------------------------

The following command shows an example of subscribing to the Windows event log:

::

    $ wecutil -r saratoga -u Administrator
    Pull #1
    Event(system=System(provider='Microsoft-Windows-EventForwarder', event_id=111, event_id_qualifiers=None, level=None, task=None, keywords=None, time_created=datetime.datetime(2013, 5, 8, 20, 29, 31, 132000), event_record_id=None, channel=None, computer='saratoga.solutions.loc', user_id=None), data=None, rendering_info=None)
    Pull #2


You can run wecutil against a matrix of hosts and event queries by using a config file.

::

    $ wecutil -c examples/config.ini
    milpitas System/'*' pull #1 of 2
    milpitas Application/'*' pull #1 of 2
    gilroy System/'*' pull #1 of 2
    ...
    milpitas System/'*' Event(system=System(provider='Microsoft-Windows-...
    ...
    milpitas Application/'*' pull #2 of 2
    ...
    
    Summary:
      Connected to 4 of 4 hosts
      Processed 12 events
      Peak virtual memory useage: 361060 kB

      Remote CPU utilization:
        saratoga
          0.15% of CPU time used by WmiPrvSE process with pid 1640
          0.96% of CPU time used by WmiPrvSE#1 process with pid 2000
          0.00% of CPU time used by WmiApSrv process with pid 604
          0.07% of CPU time used by WmiPrvSE#2 process with pid 1604
        gilroy
          0.00% of CPU time used by WmiPrvSE process with pid 1384
          0.00% of CPU time used by WmiPrvSE#1 process with pid 1684
          0.00% of CPU time used by WmiApSrv process with pid 1924
          0.15% of CPU time used by WmiPrvSE#2 process with pid 1348
        milpitas
          0.36% of CPU time used by wmiprvse process with pid 1924
          1.01% of CPU time used by wmiprvse process with pid 816
        berkeley
          0.00% of CPU time used by WmiPrvSE process with pid 1624
          0.00% of CPU time used by WmiPrvSE#1 process with pid 1744
          0.00% of CPU time used by WmiApSrv process with pid 1620
          0.07% of CPU time used by WmiPrvSE#2 process with pid 1280


Feedback
--------

To provide feedback on txwinrm start a discussion on the zenoss-windows forum
on community.zenoss.org:
http://community.zenoss.org/community/forums/zenoss-windows

Zenoss uses JIRA to track bugs. Create an account and file a bug, or browse
reported bugs: http://jira.zenoss.com/jira/secure/Dashboard.jspa


Unit Test Coverage
------------------

As of Apr 16, 2013...

::

    $ txwinrm/test/cover
    ........................
    ----------------------------------------------------------------------
    Ran 24 tests in 7.910s

    OK
    Name                Stmts   Miss  Cover
    ---------------------------------------
    txwinrm/__init__        0      0   100%
    txwinrm/constants      18      0   100%
    txwinrm/enumerate     259     46    82%
    txwinrm/shell         114     34    70%
    txwinrm/util           89     24    73%
    ---------------------------------------
    TOTAL                 480    104    78%


Develop
-------

Run txwinrm/test/precommit before merging to master. This requires that you...

::

    easy_install flake8
    easy_install coverage
    git clone https://github.com/dgladkov/cyclic_complexity


Changes
-------

1.2.2
* Add support for multiple kdcs to be defined

1.1.27
* Add support for running commands/enumerations in a single session
