patchExclusionList = ['ARM', 'arm', 'Embedded', '팜', '팝', 'Itanium', 'POS']
officeList = ['Office', 'Word', 'Excel', 'Outlook', 'PowerPoint', 'Visio', 'SharePoint']

"""
#v# : Version
#ki# : KBID
#gi# : GUID
#s# : Severity
"""
totalRegexDic = {
    'windows-cumulative' : [
        {
            'regex' : 'x86 기반 시스템용 Windows 10 Version \w{4}에 대한 누적 업데이트',
            'excel' : '	Q#ki# 10_#v#	#gi#	#ki#	0	W10		#df1#	#df2#, Windows 10 #v# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#v#-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#v#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : '에 대한'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 10 Version \w{4}에 대한 누적 업데이트',
            'excel' : '	Q#ki# 10_#v#_x64	#gi#	#ki#	9	W10		#df1#	#df2#, Windows 10_x64 #v# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#v#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#v#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : '에 대한'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11 Version \w{4}에 대한 누적 업데이트',
            'excel' : '	Q#ki# 11_#v#_x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11 #v# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-#v#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#v#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : '에 대한'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11에 대한 누적 업데이트',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 10 Version \w{4} for x86-based Systems',
            'excel' : '	Q#ki# 10_#v#	#gi#	#ki#	0	W10		#df1#	#df2#, Windows 10 #v# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows10.0-#v#-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#v#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : ' for x86'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 10 Version \w{4} for x64-based Systems',
            'excel' : '	Q#ki# 10_#v#_x64	#gi#	#ki#	9	W10		#df1#	#df2#, Windows 10_x64 #v# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows10.0-#v#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#v#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : ' for x64'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 11 Version \w{4} for x64-based Systems',
            'excel' : '	Q#ki# 11_#v#x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11_x64 #v# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows11.0-#v#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#v#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : ' for x64'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 11 for x64-based Systems',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11_x64 Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2016에 대한 누적 업데이트',
            'excel' : '	Q#ki# 216	#gi#	#ki#	9	W216		#df1#	#df2#, Windows 2016_x64 누적 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows10.0-1607-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2019에 대한 누적 업데이트',
            'excel' : '	Q#ki# 219	#gi#	#ki#	9	W219		#df1#	#df2#, Windows 2019_x64 누적 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows10.0-1809-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        }
    ],
    'windows-security' : [
        {
            'regex' : 'x86 기반 시스템용 Windows Server 2008에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28		#df1#	#df2#, Windows 2008 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows Server 2008에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28		#df1#	#df2#, Windows 2008 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 7에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	#df2#, Windows 7 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 7에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	#df2#, Windows 7 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 8.1에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 81	#gi#	#ki#	0	W81		#df1#	#df2#, Windows 8.1 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 8.1에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	#df2#, Windows 8.1_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28		#df1#	#df2#, Windows 2008_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28		#df1#	#df2#, Windows 2008_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 7에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7		#df1#	#df2#, Windows 7_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 7에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7		#df1#	#df2#, Windows 7_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 8.1에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	#df2#, Windows 8.1_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 8.1에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	#df2#, Windows 8.1_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008 R2에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2		#df1#	#df2#, Windows 2008R2_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008 R2에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2		#df1#	#df2#, Windows 2008R2_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212		#df1#	#df2#, Windows 2012 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8-RT-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212		#df1#	#df2#, Windows 2012 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8-RT-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012 R2에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2		#df1#	#df2#, Windows 2012R2 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012 R2에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2		#df1#	#df2#, Windows 2012R2 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 10 Version 22H2 보안 업데이트',
            'excel' : '	Q#ki# 10_22H2	#gi#	#ki#	0	W10		#df1#	#df2#, Windows 10 22H2 보안 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows10.0-22H2-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 2
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 10 Version 22H2 보안 업데이트',
            'excel' : '	Q#ki# 10_22H2_x64	#gi#	#ki#	9	W10		#df1#	#df2#, Windows 10_x64 22H2 보안 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows10.0-22H2-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 2
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11 22H2 보안 업데이트',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11 보안 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 2
        }
    ]
}

totalRowDic = {
    'windows-cumulative' : {},
    'windows-security' : {}
}