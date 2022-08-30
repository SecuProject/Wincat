/*
splunkforwarder.exe

Fortisiem		??
ArcSight SIEM	??
*/


const uint32_t processNameHash[] = {
        0xf11ffc1c,     // activeconsole.exe -
        0x9560419c,     // apimonitor-x64.exe -
        0xd5aa738c,     // apimonitor-x86.exe -
        0x424e67a9,     // appsense.exe -
        0xad00d944,     // afwserv.exe - Avast - Firewall
        0x97cc3cdb,     // aswidsagent.exe - Avast
        0x2b3d8cfd,     // aswtoolssvc.exe - Avast
        0xbfc4d080,     // avast.exe - Avast
        0xb02ef94,      // avastsvc.exe - Avast
        0xb26ee0f8,     // authtap.exe -
        0x235d5d64,     // avecto.exe -
        0xd5a2487c,     // atasagent.exe - Trend Micro - Advanced Managed Detection
        0x1c052ea1,     // canary.exe -
        0x193d6e81,     // carbon black.exe -
        0xebdcf887,     // carbonblack.exe -
        0x6b714a8f,     // carbon.exe -
        0x89f4f95,      // cb.exe -
        0x9abc0ddc,     // cisco amp.exe - Cisco
        0xca6ded32,     // ciscoamp.exe -
        0xcb545a0e,     // countercept.exe -
        0x2e973649,     // countertack.exe -
        0xa1162dde,     // cramtray.exe -
        0xb1895aed,     // crowdstrike.exe -
        0x2f76343d,     // crssvc.exe -
        0x1d14bf83,     // csagent.exe -
        0xe24d8d75,     // csfalcon.exe -
        0x5b5aba90,     // csshell.exe -
        0xd76a5525,     // cybereason.exe -
        0x83da35ef,     // cyclorama.exe -
        0xde0f388c,     // cylance.exe -
        0xa3d04e91,     // cyoptics.exe -
        0xc4d507c4,     // cyserver.exe -
        0x3512154d,     // cytray.exe -
        0x2d7b70fd,     // cyupdate.exe -
        0x9c1c06,       // cyvera.exe -
        0x9806b3db,     // darktrace.exe -
        0xe735b68,      // defender.exe -
        0xde8322b2,     // defendpoint.exe -
        0x342faa00,     // dsagent.exe -
        0x31187f1f,     // edrsvc.exe - ComodoSecurity - OpenEDR
        0x4a14b1a0,     // eectrl.exe -
        0xa3f4e4fa,     // elastic-agent.exe - Elastic agent
        0xd5997c24,     // elastic.exe - Elastic agent
        0x6ccbf0e1,     // emcoreservice.exe -
        0xc6b6b5ec,     // emsystem.exe -
        0x423dd258,     // endgame.exe -
        0x1a796eb4,     // filebeat.exe - Elastic agent
        0xc8f4f738,     // fireeye.exe - FireEye
        0xb78b756b,     // forcepoint.exe -
        0x3e29da8,      // forescout.exe -
        0xd9fb8ceb,     // f-secure.exe - F-secure
        0x8740ab24,     // deepinstinct.exe - FortiEDR
        0xad58b218,     // groundling.exe -
        0xdb453918,     // grrservice.exe -
        0x5d2a03b1,     // grrservic.exe -
        0x2830b60c,     // inspector.exe -
        0x5a57870a,     // ivanti.exe -
        0xa30fe00a,     // kaspersky.exe -
        0xc11ec683,     // lacuna.exe -
        0x57e1d45b,     // logrhythm.exe -
        0xddb746c0,     // logserver.exe -
        0x4491760,      // macmnsvc.exe - McAfee Agent Common Services
        0x5dc24c60,     // masvc.exe - McAfee Agent Service
        0x3c164bed,     // malware.exe -
        0x9ad56511,     // mandiant.exe -
        0x5dc24c60,     // masvc.exe -
        0x8b7e5216,     // mcafee.exe - Mcafee
        0x510aca1c,     // mfemactl.exe - McAfee Agent AAC Host
        0xeb911770,     // morphisec.exe -
        0x1a2124c0,     // msascuil.exe -
        0xf868b2f1,     // msmpeng.exe -
        0xc78c39c5,     // nissrv.exe -
        0x25afd43,      // ntrtscan.exe - Trend Micro - Security Agent/Real-time scan
        0x1d817646,     // omniagent.exe -
        0xf49b8ca2,     // omni.exe -
        0x92c03c6e,     // osqueryd.exe - OsQuery
        0x9d45f32,      // osquery.exe - OsQuery
        0x31eaa0c1,     // ossec-agent.exe - AlienVault Agent/WAZUS/ossec
        0xc8e82285,     // ossec.exe - AlienVault Agent/WAZUS/ossec
        0x489e7a2f,     // palo alto networks.exe -
        0xf3996f9e,     // pgeposervice.exe -
        0x76083e33,     // pgsystemtray.exe -
        0x9991328d,     // privilegeguard.exe -
        0xc0bc736f,     // procwall.exe -
        0x39380231,     // protectorservice.exe -
        0xd3997def,     // qradar.exe - IBM - QRadar
        0x2cfa5ea1,     // redcloak.exe -
        0xfbfe4deb,     // secureconnector.exe - Forescout agent
        0xb8ac3964,     // secureworks.exe -
        0xfb22a468,     // securityhealthservice.exe - Windows Defender
        0x5b285963,     // semlaunchsvc.exe -
        0x7046ecf8,     // semlaunchsv.exe -
        0xaffa3669,     // sentinel.exe -
        0xf2325ab7,     // sepliveupdate.exe -
        0x43f877f1,     // sisidsservice.exe -
        0x3746bbbd,     // sisipsservice.exe -
        0xd298a623,     // sisipsutil.exe -
        0xfedbb33e,     // smc.exe -
        0x58afdb8c,     // smcgui.exe -
        0x9e07b79f,     // snac64.exe -
        0xfa381bf5,     // sophos.exe - Sophos
        0xa52e4381,     // splunkd.exe - Splunk Universal Forwarde
        0x3f9040d9,     // splunk.exe - Splunk Universal Forwarde
        0x74e9b0c6,     // splunkforwarder.exe - Splunk Universal Forwarde
        0x79dea124,     // srtsp.exe -
        0x4d4d8110,     // symantec.exe - Symantec
        0x707a6d38,     // symcorpu.exe -
        0x8afcbff3,     // symcorpui.exe -
        0x699d81e7,     // symefasi.exe -
        0xa3a3b5da,     // sysinternal.exe -
        0x9d3369c3,     // sysmon64.exe - System Monitor - Windows Sysinternals
        0x61255b79,     // sysmon.exe - System Monitor - Windows Sysinternals
        0x62fdfbad,     // tanium.exe -
        0x9c89f652,     // tcpdump.exe -
        0x66b38f18,     // tda.exe -
        0x11c4588c,     // tdawork.exe -
        0xd75db698,     // threat.exe -
        0x129c7e9,      // tmbmsrv.exe - Trend Micro
        0x1a35902a,     // tmccsf.exe - Trend Micro - Security Agent - Memory scan
        0x6ccef6bb,     // tmlisten.exe - Trend Micro - Security Agent
        0xad508441,     // tmpfw.exe - Trend Micro - Security Agent - firewall
        0x237d1294,     // tmssclient.exe - Trend Micro
        0x4ea0ff6a,     // tmwscsvc.exe - Trend Micro
        0x14193e2f,     // tpython.exe -
        0xf63e7b90,     // trend.exe - Trend Micro
        0x7e1d4ffa,     // vectra.exe -
        0x4b14a9d0,     // watchdogagent.exe -
        0x95716b98,     // wazuh-agent.exe - Wazuh agent
        0x95716b98,     // wazuh-agent.exe - Wazuh agent
        0x4da68834,     // wincollect.exe - Elastic agent
        0xf04af51a,     // windowssensor.exe - Windows ATP
        0x4495116,      // winlogbeat.exe - Elastic agent
        0x77ae10f7,     // wireshark.exe -
        0xfa3adc1f,     // xagt.exe -
        0xb23218dc,     // xagtnotif.exe -
};